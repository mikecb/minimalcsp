package minimalcsp_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mikecb/minimalcsp"
)

const (
	testURL  = "https://x.test/dir/page.html"
	baseline = "default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
)

func hash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func parseAt(t *testing.T, rawURL, input string) *minimalcsp.Page {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := minimalcsp.Parse(strings.NewReader(input), u)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

// policyFor builds a policy for input, and fails if the policy isn't valid CSP.
func policyFor(t *testing.T, input string, opts minimalcsp.Options) *minimalcsp.Policy {
	t.Helper()
	policy := minimalcsp.Build(parseAt(t, testURL, input), opts)
	if err := checkCSP(policy.String()); err != nil {
		t.Errorf("invalid policy %q: %v", policy, err)
	}
	return policy
}

// These follow the source expression grammar in the CSP Level 3 specification,
// and exist separately from the code that generates sources.
var (
	directiveName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	keywordSource = regexp.MustCompile(`^'(self|none)'$`)
	hashSource    = regexp.MustCompile(`^'sha256-[A-Za-z0-9+/]{43}='$`)
	schemeSource  = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:$`)
	hostSource    = regexp.MustCompile(`^(https?|wss?)://[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]+)?(/[A-Za-z0-9\-._~!$&'()*+=:@%/]*)?$`)
)

// checkCSP returns an error unless policy is a valid, strict serialized policy.
func checkCSP(policy string) error {
	seen := map[string]bool{}
	for _, directive := range strings.Split(policy, "; ") {
		fields := strings.Split(directive, " ")
		name, sources := fields[0], fields[1:]
		if !directiveName.MatchString(name) {
			return fmt.Errorf("bad directive name %q", name)
		}
		if seen[name] {
			return fmt.Errorf("repeated directive %q", name)
		}
		seen[name] = true
		if len(sources) == 0 {
			return fmt.Errorf("%s has no sources", name)
		}
		for _, s := range sources {
			if s == "'none'" && len(sources) > 1 {
				return fmt.Errorf("%s combines 'none' with other sources", name)
			}
			if !keywordSource.MatchString(s) && !hashSource.MatchString(s) &&
				!schemeSource.MatchString(s) && !hostSource.MatchString(s) {
				return fmt.Errorf("%s has bad source %q", name, s)
			}
		}
	}
	if !seen["default-src"] {
		return fmt.Errorf("no default-src")
	}
	return nil
}

func TestCheckCSPRejectsBadPolicies(t *testing.T) {
	bad := []string{
		"",
		"img-src 'self'",
		"default-src",
		"default-src 'none'; default-src 'self'",
		"default-src 'none' 'self'",
		"default-src 'unsafe-inline'",
		"default-src 'none'; script-src 'unsafe-eval'",
		"default-src 'none'; img-src /a.png",
		"default-src 'none'; img-src a.png",
		"default-src 'none'; img-src data:,",
		"default-src 'none'; img-src https://x.test/a?b=c",
		"default-src 'none'; img-src https://x.test/a,b",
		"default-src 'none'; img-src https://X.test",
		"default-src 'none'; img-src https://ü.test",
		"default-src 'none'; script-src 'sha256-short='",
		"default-src 'none'; img-src 'self'; ",
	}
	for _, policy := range bad {
		if err := checkCSP(policy); err == nil {
			t.Errorf("checkCSP accepted %q", policy)
		}
	}
	if err := checkCSP(baseline + "; img-src 'self' data: https://x.test/a%2Cb"); err != nil {
		t.Errorf("checkCSP rejected a valid policy: %v", err)
	}
}

func TestBuild(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // The directive to expect, or "" for the baseline alone.
	}{
		{"no resources", `<p>hello</p>`, ""},
		{"empty document", ``, ""},

		// Reducing URLs to sources.
		{"same origin", `<img src="a.png">`, "img-src 'self'"},
		{"root-relative", `<img src="/a.png">`, "img-src 'self'"},
		{"parent-relative", `<img src="../a.png">`, "img-src 'self'"},
		{"absolute same origin", `<img src="https://x.test/a.png">`, "img-src 'self'"},
		{"other origin", `<img src="https://cdn.test/a/b.png?c=d">`, "img-src https://cdn.test"},
		{"other scheme is another origin", `<img src="http://x.test/a.png">`, "img-src http://x.test"},
		{"other port is another origin", `<img src="https://x.test:8443/a.png">`, "img-src https://x.test:8443"},
		{"default port is dropped", `<img src="https://x.test:443/a.png">`, "img-src 'self'"},
		{"http default port is dropped", `<img src="http://y.test:80/a.png">`, "img-src http://y.test"},
		{"protocol-relative", `<img src="//cdn.test/a.png">`, "img-src https://cdn.test"},
		{"uppercase host", `<img src="https://CDN.test/a.png">`, "img-src https://cdn.test"},
		{"international host", `<img src="https://münchen.test/a.png">`, "img-src https://xn--mnchen-3ya.test"},
		{"credentials are dropped", `<img src="https://u:p@cdn.test/a.png">`, "img-src https://cdn.test"},
		{"whitespace around URL", "<img src=\"\n  https://cdn.test/a.png  \">", "img-src https://cdn.test"},
		{"data URI", `<img src="data:image/png;base64,iVBOR/w==">`, "img-src data:"},
		{"data URI with comma only", `<link rel="icon" href="data:,">`, "img-src data:"},
		{"blob URL", `<img src="blob:https://x.test/1234">`, "img-src blob:"},
		{"duplicates", `<img src="a.png"><img src="b.png"><img src="https://x.test/c.png">`, "img-src 'self'"},
		{"sources are sorted", `<img src="https://b.test/1"><img src="data:,"><img src="https://a.test/1"><img src="1">`,
			"img-src 'self' data: https://a.test https://b.test"},
		{"empty src", `<img src="">`, ""},
		{"img without src", `<img alt="a">`, ""},

		// Elements.
		{"embed", `<embed src="https://cdn.test/a">`, "object-src https://cdn.test"},
		{"object", `<object data="https://cdn.test/a"></object>`, "object-src https://cdn.test"},
		{"iframe", `<iframe src="https://cdn.test/"></iframe>`, "frame-src https://cdn.test"},
		{"blank iframe", `<iframe src="about:blank"></iframe>`, ""},
		{"audio", `<audio src="a.mp3"></audio>`, "media-src 'self'"},
		{"video", `<video src="a.mp4"></video>`, "media-src 'self'"},
		{"source", `<video><source src="https://cdn.test/a.webm"></video>`, "media-src https://cdn.test"},
		{"nested", `<div><section><p><img src="a.png"></p></section></div>`, "img-src 'self'"},
		{"template contents are inert", `<template><img src="a.png"><script>a()</script></template>`, ""},
		{"text matching a tag name", `<p>script</p><p>style</p><p>form</p>`, ""},
		{"comment matching a tag name", `<!--<img src="a.png">-->`, ""},

		// Stylesheets and icons.
		{"stylesheet", `<link rel="stylesheet" href="a.css">`, "style-src 'self'"},
		{"href before rel", `<link href="a.css" rel="stylesheet">`, "style-src 'self'"},
		{"external stylesheet", `<link rel="stylesheet" href="https://cdn.test/a.css">`, "style-src https://cdn.test"},
		{"rel with other case", `<link rel="Stylesheet" href="a.css">`, "style-src 'self'"},
		{"rel with several values", `<link rel="alternate stylesheet" href="a.css">`, "style-src 'self'"},
		{"icon", `<link rel="icon" href="a.ico">`, "img-src 'self'"},
		{"shortcut icon", `<link rel="SHORTCUT Icon" href="a.ico">`, "img-src 'self'"},
		{"unrelated link", `<link rel="canonical" href="https://cdn.test/">`, ""},
		{"rel containing a value as a substring", `<link rel="apple-touch-icon" href="a.png">`, ""},
		{"link without href", `<link rel="stylesheet">`, ""},

		// External scripts are never reduced to an origin.
		{"script", `<script src="https://cdn.test/a/b.js"></script>`, "script-src https://cdn.test/a/b.js"},
		{"same-origin script", `<script src="a.js"></script>`, "script-src https://x.test/dir/a.js"},
		{"script query is removed", `<script src="/a.js?v=1#b"></script>`, "script-src https://x.test/a.js"},
		{"script path delimiters are escaped", `<script src="/a;b,c.js"></script>`, "script-src https://x.test/a%3Bb%2Cc.js"},
		{"async script", `<script async src="a.js"></script>`, "script-src https://x.test/dir/a.js"},
		{"script with text", `<script src="a.js">ignored()</script>`, "script-src https://x.test/dir/a.js"},

		// Inline code.
		{"inline script", `<script>a()</script>`, "script-src " + hash("a()")},
		{"inline script with type", `<script type="text/javascript">a()</script>`, "script-src " + hash("a()")},
		{"inline script with uppercase type", `<script type="TEXT/JAVASCRIPT">a()</script>`, "script-src " + hash("a()")},
		{"inline script with padded type", `<script type=" module ">a()</script>`, "script-src " + hash("a()")},
		{"inline module", `<script type="module">a()</script>`, "script-src " + hash("a()")},
		{"inline import map", `<script type="importmap">{}</script>`, "script-src " + hash("{}")},
		{"inline script keeps whitespace", "<script>\n  a()\n</script>", "script-src " + hash("\n  a()\n")},
		{"inline script normalizes line endings", "<script>a()\r\nb()</script>", "script-src " + hash("a()\nb()")},
		{"inline script keeps entities", `<script>"&amp;"</script>`, "script-src " + hash(`"&amp;"`)},
		{"identical inline scripts", `<script>a()</script><script>a()</script>`, "script-src " + hash("a()")},
		{"inline style", `<style>a{}</style>`, "style-src " + hash("a{}")},
		{"inline style with attribute", `<style media="print">a{}</style>`, "style-src " + hash("a{}")},
		{"inline style with css type", `<style type="TEXT/CSS">a{}</style>`, "style-src " + hash("a{}")},
		{"svg script", `<svg><script>a()</script></svg>`, "script-src " + hash("a()")},
		{"json data block", `<script type="application/ld+json">{}</script>`, ""},
		{"template data block", `<script type="text/template"><p></p></script>`, ""},
		{"style with non-css type", `<style type="text/x-less">a{}</style>`, ""},
		{"empty script", `<script></script>`, ""},
		{"empty style", `<style></style>`, ""},

		// Forms.
		{"form without action", `<form></form>`, "form-action 'self'"},
		{"form with empty action", `<form action=""></form>`, "form-action 'self'"},
		{"form action", `<form action="https://cdn.test/post"></form>`, "form-action https://cdn.test"},
		{"form action resolves", `<form action="/post"></form>`, "form-action 'self'"},
		{"form actions are sorted", `<form action="https://b.test/"></form><form action="https://a.test/"></form>`,
			"form-action https://a.test https://b.test"},
		{"button formaction", `<button formaction="https://cdn.test/post"></button>`, "form-action https://cdn.test"},
		{"input formaction", `<input formaction="https://cdn.test/post">`, "form-action https://cdn.test"},

		// Base URLs.
		{"same-origin base", `<base href="/other/">`, "base-uri 'self'"},
		{"external base", `<base href="https://cdn.test/a/">`, "base-uri https://cdn.test"},
		{"resources resolve against base", `<base href="https://cdn.test/a/"><img src="b.png">`, "img-src https://cdn.test"},
		{"base applies to earlier resources", `<img src="b.png"><base href="https://cdn.test/a/">`, "img-src https://cdn.test"},
		{"first base wins", `<base href="https://a.test/"><base href="https://b.test/">`, "base-uri https://a.test"},
		{"base without href is skipped", `<base target="_top"><base href="https://a.test/">`, "base-uri https://a.test"},
		{"form without action ignores base", `<base href="https://cdn.test/"><form></form>`, "form-action 'self'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := policyFor(t, tt.input, minimalcsp.Options{})
			if tt.want == "" {
				if got := policy.String(); got != baseline {
					t.Errorf("policy\n got %q\nwant %q", got, baseline)
				}
				return
			}
			got := strings.Split(policy.String(), "; ")
			if !slices.Contains(got, tt.want) {
				t.Errorf("policy %q has no directive %q", policy, tt.want)
			}
		})
	}
}

func TestBuildNeverAllowsInlineByKeyword(t *testing.T) {
	policy := policyFor(t, `<script>a()</script><style>b{}</style><a onclick="c()" style="d">e</a>`, minimalcsp.Options{})
	if strings.Contains(policy.String(), "unsafe") {
		t.Errorf("policy %q contains an unsafe keyword", policy)
	}
}

// This vector is the example in the CSP specification, so it pins the hash
// format independently of how this file computes hashes.
func TestBuildMatchesPublishedHash(t *testing.T) {
	policy := policyFor(t, `<script>alert('Hello, world.');</script>`, minimalcsp.Options{})
	want := "script-src 'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng='"
	if !strings.Contains(policy.String(), want) {
		t.Errorf("policy %q is missing %q", policy, want)
	}
}

func TestBuildFormat(t *testing.T) {
	policy := policyFor(t, `<style>a{}</style><img src="1.png"><script src="/2.js"></script><form></form>`, minimalcsp.Options{})
	want := "default-src 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; " +
		"img-src 'self'; script-src https://x.test/2.js; style-src " + hash("a{}")
	if got := policy.String(); got != want {
		t.Errorf("policy\n got %q\nwant %q", got, want)
	}
}

func TestBuildIgnoresDocumentOrder(t *testing.T) {
	one := policyFor(t, `<img src="https://a.test/"><script>a()</script><img src="https://b.test/"><audio src="c"></audio>`, minimalcsp.Options{})
	two := policyFor(t, `<audio src="c"></audio><img src="https://b.test/"><script>a()</script><img src="https://a.test/">`, minimalcsp.Options{})
	if one.String() != two.String() {
		t.Errorf("order changed the policy:\n%q\n%q", one, two)
	}
}

func TestBuildExactPaths(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"same origin", `<img src="a.png">`, "img-src https://x.test/dir/a.png"},
		{"other origin", `<img src="https://cdn.test/a.png?b=c">`, "img-src https://cdn.test/a.png"},
		{"stylesheet", `<link rel="stylesheet" href="/a.css">`, "style-src https://x.test/a.css"},
		{"scheme", `<img src="data:,">`, "img-src data:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := policyFor(t, tt.input, minimalcsp.Options{ExactPaths: true})
			if !strings.Contains(policy.String(), tt.want) {
				t.Errorf("policy %q is missing %q", policy, tt.want)
			}
		})
	}
}

func TestBuildFixture(t *testing.T) {
	input, err := os.ReadFile("testdata/mikecb-org.html")
	if err != nil {
		t.Fatal(err)
	}
	policy := minimalcsp.Build(parseAt(t, "https://mikecb.org/", string(input)), minimalcsp.Options{})
	script := hash("\nwindow.ga=window.ga||function(){(ga.q=ga.q||[]).push(arguments)};ga.l=+new Date;\n" +
		"ga('create', 'UA-42723924-1', 'auto');\nga('send', 'pageview');\n")
	style := hash("\n.layout-transparent .mdl-layout__header,\n.layout-transparent .mdl-layout__drawer-button {\n" +
		"color: white;\n}\n")
	want := baseline + "; img-src 'self'" +
		"; script-src " + script + " https://mikecb.org/js/material.min.js https://www.google-analytics.com/analytics.js" +
		"; style-src 'self' " + style + " https://fonts.googleapis.com"
	if got := policy.String(); got != want {
		t.Errorf("policy\n got %q\nwant %q", got, want)
	}
	if err := checkCSP(policy.String()); err != nil {
		t.Errorf("invalid policy: %v", err)
	}
}

func TestBlockers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []minimalcsp.Blocker
	}{
		{"none", `<a href="/b" class="c">d</a>`, nil},
		{"event handler", `<a onclick="b()">c</a>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonEventHandler, "a", "onclick", "b()"}}},
		{"event handler on body", `<body onload="a()">`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonEventHandler, "body", "onload", "a()"}}},
		{"style attribute", `<p style="color:red">a</p>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonStyleAttribute, "p", "style", "color:red"}}},
		{"javascript href", `<a href="javascript:a()">b</a>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonJavaScriptURL, "a", "href", "javascript:a()"}}},
		{"javascript with other case", `<a href="JavaScript:a()">b</a>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonJavaScriptURL, "a", "href", "JavaScript:a()"}}},
		{"javascript with ignored characters", "<a href=\" java\tscript:a()\">b</a>",
			[]minimalcsp.Blocker{{minimalcsp.ReasonJavaScriptURL, "a", "href", " java\tscript:a()"}}},
		{"javascript form action", `<form action="javascript:a()"></form>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonJavaScriptURL, "form", "action", "javascript:a()"}}},
		{"javascript formaction", `<button formaction="javascript:a()"></button>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonJavaScriptURL, "button", "formaction", "javascript:a()"}}},
		{"javascript iframe", `<iframe src="javascript:a()"></iframe>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonJavaScriptURL, "iframe", "src", "javascript:a()"}}},
		{"javascript text in other attributes", `<a title="javascript:a()">b</a>`, nil},
		{"empty attributes", `<a onclick="" style="">b</a>`, nil},
		{"identical blockers", `<p style="a">b</p><p style="a">c</p>`,
			[]minimalcsp.Blocker{{minimalcsp.ReasonStyleAttribute, "p", "style", "a"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyFor(t, tt.input, minimalcsp.Options{}).Blockers
			if !slices.Equal(got, tt.want) {
				t.Errorf("blockers\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestJavaScriptURLsAreNotSources(t *testing.T) {
	policy := policyFor(t, `<iframe src="javascript:a()"></iframe><form action="javascript:b()"></form>`, minimalcsp.Options{})
	if got := policy.String(); got != baseline {
		t.Errorf("policy\n got %q\nwant %q", got, baseline)
	}
}

func TestBlockerString(t *testing.T) {
	b := minimalcsp.Blocker{minimalcsp.ReasonEventHandler, "a", "onclick", strings.Repeat("é", 70)}
	want := `inline event handler: <a onclick="` + strings.Repeat("é", 60) + `...">`
	if got := b.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWarnings(t *testing.T) {
	gap := "static analysis can't see"
	tests := []struct {
		name  string
		input string
		want  []string // A substring of each expected warning, in order.
	}{
		{"none", `<img src="a.png"><script>a()</script><style>b{}</style>`, nil},
		{"stylesheet", `<link rel="stylesheet" href="a.css">`, []string{gap}},
		{"script", `<script src="https://cdn.test/a.js"></script>`,
			[]string{gap, "https://cdn.test/a.js by URL"}},
		{"data script", `<script src="data:text/javascript,a()"></script>`,
			[]string{gap, "the data: scheme"}},
		{"data image", `<img src="data:,">`, nil},
		{"repeated script", `<script src="/a.js"></script><script src="/a.js"></script>`,
			[]string{gap, "https://x.test/a.js by URL"}},
		{"invalid URL", `<img src="http://[bad">`, []string{`skipped invalid URL "http://[bad"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyFor(t, tt.input, minimalcsp.Options{}).Warnings
			if len(got) != len(tt.want) {
				t.Fatalf("warnings\n got %q\nwant %q", got, tt.want)
			}
			for i := range got {
				if !strings.Contains(got[i], tt.want[i]) {
					t.Errorf("warning %q is missing %q", got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseRequiresAbsoluteURL(t *testing.T) {
	for _, u := range []*url.URL{nil, {Path: "/a"}} {
		if _, err := minimalcsp.Parse(strings.NewReader(""), u); err == nil {
			t.Errorf("Parse(%v) succeeded, want an error", u)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestParseReturnsReadErrors(t *testing.T) {
	u, err := url.Parse(testURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := minimalcsp.Parse(failingReader{}, u); err == nil {
		t.Error("Parse succeeded, want an error")
	}
}

func TestStaticCollectorIsACollector(t *testing.T) {
	var _ minimalcsp.Collector = minimalcsp.StaticCollector{}
}

func serve(t *testing.T, contentType, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCollect(t *testing.T) {
	srv := serve(t, "text/html", `<img src="a.png">`)
	page, err := minimalcsp.StaticCollector{}.Collect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := minimalcsp.Build(page, minimalcsp.Options{}).String(); got != baseline+"; img-src 'self'" {
		t.Errorf("unexpected policy %q", got)
	}
}

func TestCollectEmptyPage(t *testing.T) {
	srv := serve(t, "text/html", ``)
	page, err := minimalcsp.StaticCollector{}.Collect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := minimalcsp.Build(page, minimalcsp.Options{}).String(); got != baseline {
		t.Errorf("unexpected policy %q", got)
	}
}

func TestCollectUsesClient(t *testing.T) {
	used := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	srv := serve(t, "text/html", ``)
	if _, err := (minimalcsp.StaticCollector{Client: client}).Collect(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("Collect ignored its Client")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCollectUsesFinalURLAfterRedirect(t *testing.T) {
	var final *httptest.Server
	final = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `<img src="%s/a.png">`, final.URL)
	}))
	defer final.Close()
	start := httptest.NewServer(http.RedirectHandler(final.URL+"/page", http.StatusFound))
	defer start.Close()

	page, err := minimalcsp.StaticCollector{}.Collect(context.Background(), start.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := page.URL.String(), final.URL+"/page"; got != want {
		t.Errorf("page URL is %q, want %q", got, want)
	}
	if got := minimalcsp.Build(page, minimalcsp.Options{}).String(); !strings.HasSuffix(got, "img-src 'self'") {
		t.Errorf("policy %q doesn't treat the final URL as 'self'", got)
	}
}

func TestCollectDecodesCharset(t *testing.T) {
	srv := serve(t, "text/html; charset=iso-8859-1", "<script>a(\"\xe9\")</script>")
	page, err := minimalcsp.StaticCollector{}.Collect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := minimalcsp.Build(page, minimalcsp.Options{}).String()
	if want := hash(`a("é")`); !strings.Contains(policy, want) {
		t.Errorf("policy %q is missing %s", policy, want)
	}
}

func TestCollectFails(t *testing.T) {
	missing := httptest.NewServer(http.NotFoundHandler())
	defer missing.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ok := serve(t, "text/html", ``)

	tests := []struct {
		name string
		ctx  context.Context
		url  string
	}{
		{"HTTP error", context.Background(), missing.URL},
		{"unreachable", context.Background(), closed.URL},
		{"cancelled", cancelled, ok.URL},
		{"invalid URL", context.Background(), "http://[bad"},
		{"unsupported scheme", context.Background(), "ftp://x.test/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := (minimalcsp.StaticCollector{}).Collect(tt.ctx, tt.url); err == nil {
				t.Error("Collect succeeded, want an error")
			}
		})
	}
}

func TestBlockerStringWithoutDetails(t *testing.T) {
	tests := []struct {
		blocker minimalcsp.Blocker
		want    string
	}{
		{minimalcsp.Blocker{Reason: minimalcsp.ReasonEval, Value: "1+1"}, `eval: "1+1"`},
		{minimalcsp.Blocker{Reason: minimalcsp.ReasonEventHandler, Element: "p", Value: "go()"}, `inline event handler: <p> "go()"`},
	}
	for _, tt := range tests {
		if got := tt.blocker.String(); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func TestLinks(t *testing.T) {
	page := parseAt(t, testURL, `
		<a href="other.html">relative</a>
		<a href="/root#section">with fragment</a>
		<area href="https://y.test/map">
		<a href="mailto:a@x.test">not a page</a>
		<a href="javascript:go()">not a page</a>
		<a>no href</a>
		<link rel="stylesheet" href="a.css">`)
	var got []string
	for _, link := range page.Links {
		got = append(got, link.String())
	}
	want := []string{"https://x.test/dir/other.html", "https://x.test/root#section", "https://y.test/map"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestIncomplete(t *testing.T) {
	const warning = "static analysis can't see"
	tests := []struct {
		name, input string
		want        bool
	}{
		{"plain page", `<p>hello`, false},
		{"image and inline code", `<img src="i.png"><script>x()</script><style>p{}</style>`, false},
		{"external script", `<script src="a.js"></script>`, true},
		{"stylesheet", `<link rel="stylesheet" href="a.css">`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := parseAt(t, testURL, tt.input)
			if page.Incomplete != tt.want {
				t.Errorf("Incomplete = %v, want %v", page.Incomplete, tt.want)
			}
			warned := slices.ContainsFunc(minimalcsp.Build(page, minimalcsp.Options{}).Warnings, func(w string) bool {
				return strings.Contains(w, warning)
			})
			if warned != tt.want {
				t.Errorf("warned = %v, want %v", warned, tt.want)
			}
		})
	}
}

func TestMetaPolicyWarning(t *testing.T) {
	for input, want := range map[string]bool{
		`<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`: true,
		`<meta http-equiv="content-security-policy" content="default-src 'none'">`: true,
		`<meta http-equiv="refresh" content="0">`:                                  false,
		`<meta name="viewport" content="width=device-width">`:                      false,
	} {
		page := parseAt(t, testURL, input)
		if got := len(page.Warnings) == 1; got != want {
			t.Errorf("%s: warnings = %q", input, page.Warnings)
		}
	}
}

func TestMerge(t *testing.T) {
	one := parseAt(t, "https://x.test/one", `<img src="/a.png"><p onclick="a()"><a href="/two">two</a>`)
	two := parseAt(t, "https://x.test/two", `<img src="https://cdn.test/b.png"><p onclick="b()"><a href="/one">one</a>`)
	one.Warnings = []string{"shared", "first"}
	two.Warnings = []string{"shared", "second"}

	merged := minimalcsp.Merge(one, two)
	if merged.URL != one.URL {
		t.Errorf("URL = %v, want the first page's", merged.URL)
	}
	if got, want := len(merged.Links), 2; got != want {
		t.Errorf("got %d links, want %d", got, want)
	}
	if got, want := merged.Warnings, []string{"shared", "first", "second"}; !slices.Equal(got, want) {
		t.Errorf("warnings = %v, want %v", got, want)
	}
	if merged.Incomplete {
		t.Error("neither page is incomplete")
	}

	policy := minimalcsp.Build(merged, minimalcsp.Options{})
	if got, want := policy.String(), baseline+"; img-src 'self' https://cdn.test"; got != want {
		t.Errorf("policy = %q, want %q", got, want)
	}
	if got := len(policy.Blockers); got != 2 {
		t.Errorf("got %d blockers, want 2", got)
	}
}

func TestMergeIsIncompleteIfAnyPageIs(t *testing.T) {
	complete := parseAt(t, testURL, `<p>`)
	incomplete := parseAt(t, testURL, `<script src="a.js"></script>`)
	for _, pages := range [][]*minimalcsp.Page{{complete, incomplete}, {incomplete, complete}} {
		if !minimalcsp.Merge(pages...).Incomplete {
			t.Error("expected Incomplete")
		}
	}
}

func TestMergeNothing(t *testing.T) {
	if got := minimalcsp.Merge(); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}
