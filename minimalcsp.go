// Package minimalcsp generates the minimal working Content Security Policy for
// a webpage.
//
// A Collector gathers what a page needs into a Page, and Build turns that Page
// into a Policy. Policies never contain 'unsafe-inline'. Inline scripts and
// styles are allowed by hash, and inline code that can't be hashed is reported
// as a Blocker.
package minimalcsp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/idna"
)

// Reasons a page can't meet a strict policy.
const (
	ReasonEventHandler   = "inline event handler"
	ReasonStyleAttribute = "style attribute"
	ReasonJavaScriptURL  = "javascript: URL"
	ReasonEval           = "eval"
)

// Finding is something a page needs its policy to allow. It holds either a
// resource's URL or the text of an inline script or style.
type Finding struct {
	Directive string   // The directive that governs it, such as "img-src".
	URL       *url.URL // The resource's absolute URL, or nil for inline code.
	Code      string   // The inline code, exactly as the browser sees it.

	// Hashes holds an external script's hash source expressions without their
	// quotes, such as "sha256-...".
	Hashes []string

	// Loaded reports that another script added this script, so it wasn't in
	// the page as served. 'strict-dynamic' trusts it through that script.
	Loaded bool
}

// Blocker is inline code that a strict policy will block and that can't be
// allowed by hash, so the page has to change.
type Blocker struct {
	Reason  string // One of the Reason constants.
	Element string // The element's tag name, if there is one.
	Attr    string // The attribute's name, if known.
	Value   string // The code.
}

func (b Blocker) String() string {
	value := b.Value
	if r := []rune(value); len(r) > 60 {
		value = string(r[:60]) + "..."
	}
	switch {
	case b.Element == "":
		return fmt.Sprintf("%s: %q", b.Reason, value)
	case b.Attr == "":
		return fmt.Sprintf("%s: <%s> %q", b.Reason, b.Element, value)
	}
	return fmt.Sprintf("%s: <%s %s=%q>", b.Reason, b.Element, b.Attr, value)
}

// Page is what a Collector learned about a webpage.
type Page struct {
	URL      *url.URL
	Findings []Finding
	Blockers []Blocker
	Warnings []string
	Links    []*url.URL // Absolute http and https links, for crawling.

	// Incomplete reports that the page may need resources the collector
	// couldn't see.
	Incomplete bool
}

// Merge combines pages from one origin, so that a policy built from the result
// works on all of them. It returns nil if there are no pages. 'self' in the
// resulting policy means the origin of the first page.
func Merge(pages ...*Page) *Page {
	if len(pages) == 0 {
		return nil
	}
	merged := &Page{URL: pages[0].URL}
	for _, page := range pages {
		merged.Findings = append(merged.Findings, page.Findings...)
		merged.Blockers = append(merged.Blockers, page.Blockers...)
		merged.Links = append(merged.Links, page.Links...)
		merged.Incomplete = merged.Incomplete || page.Incomplete
		for _, warning := range page.Warnings {
			if !slices.Contains(merged.Warnings, warning) {
				merged.Warnings = append(merged.Warnings, warning)
			}
		}
	}
	return merged
}

// Collector gathers what a page needs. Implementations differ in what they can
// see, but they all feed the same call to Build.
type Collector interface {
	Collect(ctx context.Context, pageURL string) (*Page, error)
}

// ScriptTrust is how a policy decides which scripts may run.
type ScriptTrust int

const (
	// ByHash trusts scripts by hash, for sites that can't vary a response per
	// request. External scripts need integrity attributes, which Apply adds,
	// and cross-origin ones need CORS. Scripts trusted this way can't use
	// import, statically or dynamically, so pages that do need ByNonce.
	ByHash ScriptTrust = iota

	// ByNonce trusts scripts carrying a nonce that changes on every response.
	// It has none of ByHash's limits, but it needs a server. See NonceMiddleware.
	ByNonce

	// ByURL lists external scripts by URL, so the page needs no changes. It's
	// weaker, since anything an attacker can get onto a listed URL will run.
	ByURL
)

// NoncePlaceholder stands in for the nonce in a ByNonce policy.
const NoncePlaceholder = "{nonce}"

// Options controls how Build reduces resources to sources.
type Options struct {
	// Scripts is how the policy trusts scripts. The default is ByHash.
	Scripts ScriptTrust

	// ExactPaths lists resources by URL rather than by origin. This is tighter
	// but needs regenerating whenever a resource moves.
	ExactPaths bool
}

// Integrity is an attribute a ByHash policy needs on a script element.
type Integrity struct {
	URL         *url.URL // The script.
	Value       string   // The value for the integrity attribute.
	CrossOrigin bool     // Whether it also needs crossorigin="anonymous".
}

func (i Integrity) String() string {
	if i.CrossOrigin {
		return fmt.Sprintf("%s needs integrity=%q crossorigin=\"anonymous\"", i.URL, i.Value)
	}
	return fmt.Sprintf("%s needs integrity=%q", i.URL, i.Value)
}

// Directive is one entry in a policy.
type Directive struct {
	Name    string
	Sources []string
}

// Policy is a Content Security Policy, with anything the caller needs to know
// before deploying it.
type Policy struct {
	Directives []Directive
	Blockers   []Blocker   // Inline code this policy blocks.
	Warnings   []string    // Weaknesses in the policy or gaps in what was seen.
	Integrity  []Integrity // Attributes the page needs. Apply adds them.
}

// String returns the policy as a Content-Security-Policy header value. A
// ByNonce policy has NoncePlaceholder in place of the nonce.
func (p *Policy) String() string {
	parts := make([]string, len(p.Directives))
	for i, d := range p.Directives {
		parts[i] = strings.Join(append([]string{d.Name}, d.Sources...), " ")
	}
	return strings.Join(parts, "; ")
}

// WithNonce returns the policy as a header value for a response using nonce.
func (p *Policy) WithNonce(nonce string) string {
	return strings.ReplaceAll(p.String(), NoncePlaceholder, nonce)
}

// Apply returns document, a page served from pageURL, with the integrity
// attributes the policy needs. Everything else stays byte for byte, so hashes
// of inline code still match.
func (p *Policy) Apply(document []byte, pageURL *url.URL) []byte {
	return EditScriptTags(document, pageURL, func(src *url.URL) []html.Attribute {
		for _, i := range p.Integrity {
			if src == nil || i.URL.String() != src.String() {
				continue
			}
			attrs := []html.Attribute{{Key: "integrity", Val: i.Value}}
			if i.CrossOrigin {
				attrs = append(attrs, html.Attribute{Key: "crossorigin", Val: "anonymous"})
			}
			return attrs
		}
		return nil
	})
}

// EditScriptTags returns document with attributes added to its script elements.
// It calls attrs with each element's absolute src, or nil for inline scripts.
// Attributes an element already has are left alone, and everything else stays
// byte for byte.
//
// Never use this to add nonces to a page as it's served. A nonce on every
// script includes any script an attacker managed to inject, which defeats the
// policy. Nonces belong in the templates, where only real scripts have them.
func EditScriptTags(document []byte, pageURL *url.URL, attrs func(src *url.URL) []html.Attribute) []byte {
	var out bytes.Buffer
	base := pageURL
	z := html.NewTokenizer(bytes.NewReader(document))
	for {
		kind := z.Next()
		// Reading a token can change what Raw returned, so keep a copy.
		raw := bytes.Clone(z.Raw())
		if kind == html.ErrorToken {
			out.Write(raw)
			return out.Bytes()
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			out.Write(raw)
			continue
		}
		tag := z.Token()
		if tag.Data == "base" {
			if href, ok := tokenAttr(tag, "href"); ok {
				if u, err := base.Parse(cleanURL(href)); err == nil {
					base = u
				}
			}
		}
		if tag.Data != "script" {
			out.Write(raw)
			continue
		}
		var src *url.URL
		if value, ok := tokenAttr(tag, "src"); ok {
			src, _ = base.Parse(cleanURL(value))
		}
		end := len(raw) - 1
		if kind == html.SelfClosingTagToken {
			end--
		}
		out.Write(raw[:end])
		for _, a := range attrs(src) {
			if _, exists := tokenAttr(tag, a.Key); !exists {
				fmt.Fprintf(&out, " %s=%q", a.Key, a.Val)
			}
		}
		out.Write(raw[end:])
	}
}

func tokenAttr(tag html.Token, key string) (string, bool) {
	for _, a := range tag.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// Build returns the tightest policy that allows everything in page. It denies
// by default, and its output doesn't depend on the order of the findings.
func Build(page *Page, opts Options) *Policy {
	policy := &Policy{}
	if page.Incomplete {
		policy.Warnings = append(policy.Warnings,
			"static analysis can't see what this page's scripts and stylesheets load, such as fonts and API requests")
	}
	policy.Warnings = append(policy.Warnings, page.Warnings...)
	for _, b := range page.Blockers {
		if !slices.Contains(policy.Blockers, b) {
			policy.Blockers = append(policy.Blockers, b)
		}
	}

	sources := map[string][]string{}
	if opts.Scripts != ByURL {
		if list := policy.trustScripts(page, opts.Scripts); len(list) > 0 {
			sources["script-src"] = list
		}
	}
	for _, f := range page.Findings {
		if f.Directive == "script-src" && opts.Scripts != ByURL {
			continue
		}
		source := sourceFor(f, page.URL, opts)
		if slices.Contains(sources[f.Directive], source) {
			continue
		}
		sources[f.Directive] = append(sources[f.Directive], source)
		if f.Directive == "script-src" && f.URL != nil {
			policy.Warnings = append(policy.Warnings, scriptWarning(source))
		}
	}

	// These come first and are always present. default-src doesn't cover
	// base-uri or form-action, so leaving them out would allow anything.
	for _, name := range []string{"default-src", "base-uri", "form-action", "object-src"} {
		list := sources[name]
		delete(sources, name)
		if len(list) == 0 {
			list = []string{"'none'"}
		}
		slices.Sort(list)
		policy.Directives = append(policy.Directives, Directive{name, list})
	}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		slices.Sort(sources[name])
		policy.Directives = append(policy.Directives, Directive{name, sources[name]})
	}
	return policy
}

// trustScripts returns the script-src sources for a page under ByHash or
// ByNonce. Only scripts in the page as served need trusting directly, and
// 'strict-dynamic' is there only if the page has scripts that rely on it.
func (p *Policy) trustScripts(page *Page, trust ScriptTrust) []string {
	var sources []string
	add := func(source string) {
		if !slices.Contains(sources, source) {
			sources = append(sources, source)
		}
	}
	var hasScripts, hasLoaded bool
	for _, f := range page.Findings {
		if f.Directive != "script-src" {
			continue
		}
		hasScripts = true
		switch {
		case f.Loaded:
			hasLoaded = true
		case trust == ByNonce:
		case f.URL == nil:
			add(sourceFor(f, page.URL, Options{}))
		case len(f.Hashes) == 0:
			p.Warnings = append(p.Warnings, fmt.Sprintf("couldn't hash %s, so the policy will block it", f.URL))
		default:
			for _, hash := range f.Hashes {
				add("'" + hash + "'")
			}
			if !slices.ContainsFunc(p.Integrity, func(i Integrity) bool { return i.URL.String() == f.URL.String() }) {
				p.Integrity = append(p.Integrity, Integrity{
					URL:         f.URL,
					Value:       strings.Join(f.Hashes, " "),
					CrossOrigin: origin(f.URL) != origin(page.URL),
				})
			}
		}
	}
	if trust == ByNonce && hasScripts {
		add("'nonce-" + NoncePlaceholder + "'")
	}
	if hasLoaded {
		add("'strict-dynamic'")
	}
	return sources
}

// sourceFor returns the CSP source expression that allows f.
func sourceFor(f Finding, page *url.URL, opts Options) string {
	if f.URL == nil {
		sum := sha256.Sum256([]byte(f.Code))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	switch f.URL.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return f.URL.Scheme + ":"
	}
	// Scripts are always exact, since an origin would allow every script on it.
	if opts.ExactPaths || f.Directive == "script-src" {
		return exactSource(f.URL)
	}
	if origin(f.URL) == origin(page) {
		return "'self'"
	}
	return origin(f.URL)
}

// origin returns u's scheme, host and non-default port in the form CSP expects.
func origin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if ascii, err := idna.ToASCII(host); err == nil {
		host = ascii
	}
	port := u.Port()
	switch {
	case port == "":
	case port == "80" && (u.Scheme == "http" || u.Scheme == "ws"):
	case port == "443" && (u.Scheme == "https" || u.Scheme == "wss"):
	default:
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

// pathEscaper encodes the characters that end a CSP source expression.
var pathEscaper = strings.NewReplacer(";", "%3B", ",", "%2C")

// exactSource returns u without its query or fragment, which CSP doesn't allow.
func exactSource(u *url.URL) string {
	return origin(u) + pathEscaper.Replace(u.EscapedPath())
}

func scriptWarning(source string) string {
	if strings.HasSuffix(source, ":") {
		return fmt.Sprintf("script-src allows the %s scheme, which lets an attacker supply script content", source)
	}
	return fmt.Sprintf("script-src allows %s by URL, which is weaker than a hash or nonce", source)
}
