package minimalcsp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

// StaticCollector fetches a page and reads its HTML without running it, so it
// can't see anything the page loads later. Parse marks the page Incomplete when
// that matters.
type StaticCollector struct {
	Client *http.Client // Defaults to http.DefaultClient.
}

// Collect fetches pageURL and parses it. If the request redirects, the page's
// URL is the final one, since that's what 'self' will mean in the browser.
func (c StaticCollector) Collect(ctx context.Context, pageURL string) (*Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: %s", pageURL, resp.Status)
	}
	// Browsers hash decoded text, so hashes are wrong without this on pages
	// that aren't UTF-8.
	body, err := charset.NewReader(resp.Body, resp.Header.Get("Content-Type"))
	if errors.Is(err, io.EOF) {
		// An empty page is valid, but the reader has nothing to detect.
		body = strings.NewReader("")
	} else if err != nil {
		return nil, err
	}
	return Parse(body, resp.Request.URL)
}

// Parse reads a UTF-8 HTML document served from pageURL, which must be absolute.
func Parse(r io.Reader, pageURL *url.URL) (*Page, error) {
	if pageURL == nil || !pageURL.IsAbs() {
		return nil, errors.New("minimalcsp: page URL must be absolute")
	}
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}
	p := &parser{page: &Page{URL: pageURL}, base: pageURL}
	p.findBase(doc)
	p.walk(doc)
	return p.page, nil
}

// parser holds the state of one Parse call.
type parser struct {
	page *Page
	base *url.URL // What relative URLs resolve against.
}

// findBase applies the first <base href>, which browsers use for the whole document.
func (p *parser) findBase(n *html.Node) bool {
	if n.Type == html.ElementNode && n.Data == "base" {
		if href, ok := attr(n, "href"); ok {
			if u := p.resolve(href); u != nil && u.Scheme != "data" {
				p.page.Findings = append(p.page.Findings, Finding{Directive: "base-uri", URL: u})
				p.base = u
				return true
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if p.findBase(c) {
			return true
		}
	}
	return false
}

func (p *parser) walk(n *html.Node) {
	if n.Type == html.ElementNode {
		// Template contents are inert until a script clones them.
		if n.Data == "template" {
			return
		}
		p.checkAttrs(n)
		p.element(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		p.walk(c)
	}
}

// resources maps elements to the attribute holding their URL and the directive
// that governs it.
var resources = map[string]struct{ attr, directive string }{
	"audio":  {"src", "media-src"},
	"embed":  {"src", "object-src"},
	"iframe": {"src", "frame-src"},
	"img":    {"src", "img-src"},
	"object": {"data", "object-src"},
	"source": {"src", "media-src"},
	"video":  {"src", "media-src"},
}

func (p *parser) element(n *html.Node) {
	if r, ok := resources[n.Data]; ok {
		p.addURL(n, r.attr, r.directive)
		return
	}
	switch n.Data {
	case "link":
		p.link(n)
	case "script":
		p.script(n)
	case "style":
		styleType, _ := attr(n, "type")
		if styleType == "" || strings.EqualFold(styleType, "text/css") {
			p.addInline(n, "style-src")
		}
	case "form":
		// A form with no action submits to the page's own URL, not the base URL.
		if action, _ := attr(n, "action"); action == "" {
			p.page.Findings = append(p.page.Findings, Finding{Directive: "form-action", URL: p.page.URL})
		} else {
			p.addURL(n, "action", "form-action")
		}
	case "button", "input":
		p.addURL(n, "formaction", "form-action")
	case "a", "area":
		p.addLink(n)
	case "meta":
		if equiv, _ := attr(n, "http-equiv"); strings.EqualFold(equiv, "content-security-policy") {
			p.page.Warnings = append(p.page.Warnings,
				"this page sets a policy in a <meta> tag, which can hide what it would otherwise load")
		}
	}
}

// addLink records where n leads, if it's a page that could be crawled.
func (p *parser) addLink(n *html.Node) {
	href, ok := attr(n, "href")
	if !ok {
		return
	}
	if u := p.resolve(href); u != nil && (u.Scheme == "http" || u.Scheme == "https") {
		p.page.Links = append(p.page.Links, u)
	}
}

func (p *parser) link(n *html.Node) {
	rel, _ := attr(n, "rel")
	for _, token := range strings.Fields(strings.ToLower(rel)) {
		switch token {
		case "stylesheet":
			p.addURL(n, "href", "style-src")
			p.page.Incomplete = true
		case "icon":
			p.addURL(n, "href", "img-src")
		}
	}
}

func (p *parser) script(n *html.Node) {
	if _, ok := attr(n, "src"); ok {
		found := len(p.page.Findings)
		p.addURL(n, "src", "script-src")
		if len(p.page.Findings) > found {
			integrity, _ := attr(n, "integrity")
			p.page.Findings[found].Hashes = integrityHashes(integrity)
		}
		p.page.Incomplete = true
		return
	}
	scriptType, _ := attr(n, "type")
	if runsAsScript(scriptType) {
		p.addInline(n, "script-src")
	}
}

// integrityHashes returns the hash expressions in an integrity attribute,
// without the options that can follow each one.
func integrityHashes(integrity string) []string {
	var hashes []string
	for _, hash := range strings.Fields(integrity) {
		hash, _, _ = strings.Cut(hash, "?")
		if strings.HasPrefix(hash, "sha256-") || strings.HasPrefix(hash, "sha384-") || strings.HasPrefix(hash, "sha512-") {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

// addURL records the resource in n's attribute, if it has one that loads anything.
func (p *parser) addURL(n *html.Node, key, directive string) {
	value, ok := attr(n, key)
	if !ok {
		return
	}
	if u := p.resolve(value); u != nil {
		p.page.Findings = append(p.page.Findings, Finding{Directive: directive, URL: u})
	}
}

// addInline records n's text, unless it's empty and so never reaches CSP.
func (p *parser) addInline(n *html.Node, directive string) {
	var code strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			code.WriteString(c.Data)
		}
	}
	if code.Len() > 0 {
		p.page.Findings = append(p.page.Findings, Finding{Directive: directive, Code: code.String()})
	}
}

// resolve returns the absolute URL for an attribute value. It returns nil for
// values that load nothing, and warns about values it can't parse.
func (p *parser) resolve(value string) *url.URL {
	value = cleanURL(value)
	if value == "" || isJavaScriptURL(value) {
		return nil
	}
	u, err := p.base.Parse(value)
	if err != nil {
		p.page.Warnings = append(p.page.Warnings, fmt.Sprintf("skipped invalid URL %q", value))
		return nil
	}
	if u.Scheme == "about" {
		return nil
	}
	return u
}

// checkAttrs reports the inline code in n's attributes.
func (p *parser) checkAttrs(n *html.Node) {
	for _, a := range n.Attr {
		var reason string
		switch {
		case a.Val == "":
			continue
		case a.Key == "style":
			reason = ReasonStyleAttribute
		case strings.HasPrefix(a.Key, "on"):
			reason = ReasonEventHandler
		case urlAttrs[a.Key] && isJavaScriptURL(cleanURL(a.Val)):
			reason = ReasonJavaScriptURL
		default:
			continue
		}
		p.page.Blockers = append(p.page.Blockers, Blocker{reason, n.Data, a.Key, a.Val})
	}
}

// urlAttrs holds the attributes that can navigate to or load a URL.
var urlAttrs = map[string]bool{"action": true, "formaction": true, "href": true, "src": true}

// cleanURL removes what browsers ignore in a URL: tabs and newlines anywhere,
// and whitespace and control characters at either end.
func cleanURL(value string) string {
	value = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(value)
	return strings.TrimFunc(value, func(r rune) bool { return r <= ' ' })
}

func isJavaScriptURL(value string) bool {
	const scheme = "javascript:"
	return len(value) >= len(scheme) && strings.EqualFold(value[:len(scheme)], scheme)
}

// attr returns the value of n's attribute with the given key, and whether n has it.
func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// runsAsScript reports whether a script element with the given type attribute
// executes. Other types are data blocks, such as JSON-LD, which CSP doesn't
// restrict. Every JavaScript MIME type contains "script".
func runsAsScript(scriptType string) bool {
	t := strings.ToLower(strings.TrimSpace(scriptType))
	return t == "" || t == "module" || t == "importmap" || strings.Contains(t, "script")
}
