// Package minimalcsp generates the minimal working Content Security Policy for
// a webpage.
//
// A Collector gathers what a page needs into a Page, and Build turns that Page
// into a Policy. Policies never contain 'unsafe-inline'. Inline scripts and
// styles are allowed by hash, and inline code that can't be hashed is reported
// as a Blocker.
package minimalcsp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

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

// Options controls how Build reduces resources to sources.
type Options struct {
	// ExactPaths lists resources by URL rather than by origin. This is tighter
	// but needs regenerating whenever a resource moves.
	ExactPaths bool
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
	Blockers   []Blocker // Inline code this policy blocks.
	Warnings   []string  // Weaknesses in the policy or gaps in what was seen.
}

// String returns the policy as a Content-Security-Policy header value.
func (p *Policy) String() string {
	parts := make([]string, len(p.Directives))
	for i, d := range p.Directives {
		parts[i] = d.Name + " " + strings.Join(d.Sources, " ")
	}
	return strings.Join(parts, "; ")
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
	for _, f := range page.Findings {
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
