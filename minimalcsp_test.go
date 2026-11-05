package minimalcsp_test

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mikecb/minimalcsp"
)

func checkSources(t *testing.T, input string, want [][]string) {
	t.Helper()
	got := minimalcsp.GetSources(input)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSources(%q)\n got %q\nwant %q", input, got, want)
	}
}

func TestGetSources(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  [][]string
	}{
		{"no resources", `<p>hello</p>`, nil},
		{"empty document", ``, nil},
		{"stylesheet", `<link rel="stylesheet" href="a.css">`,
			[][]string{{"style-src", "a.css"}}},
		{"href before rel", `<link href="a.css" rel="stylesheet">`,
			[][]string{{"style-src", "a.css"}}},
		{"icon", `<link rel="icon" href="a.ico">`,
			[][]string{{"img-src", "a.ico"}}},
		{"shortcut icon", `<link rel="shortcut icon" href="a.ico">`,
			[][]string{{"img-src", "a.ico"}}},
		{"unrelated link", `<link rel="canonical" href="https://x.test/">`, nil},
		{"link without href", `<link rel="stylesheet">`, nil},
		{"external script", `<script src="a.js"></script>`,
			[][]string{{"script-src", "a.js"}}},
		{"async external script", `<script async src="a.js"></script>`,
			[][]string{{"script-src", "a.js"}}},
		{"inline style", `<style>a{}</style>`,
			[][]string{{"style-src", "unsafe-inline"}}},
		{"img", `<img src="a.png">`, [][]string{{"img-src", "a.png"}}},
		{"img without src", `<img alt="a">`, nil},
		{"embed", `<embed src="a.swf">`, [][]string{{"object-src", "a.swf"}}},
		{"iframe", `<iframe src="https://x.test/"></iframe>`,
			[][]string{{"child-src", "https://x.test/"}}},
		{"audio", `<audio src="a.mp3"></audio>`,
			[][]string{{"media-src", "a.mp3"}}},
		{"video", `<video src="a.mp4"></video>`,
			[][]string{{"media-src", "a.mp4"}}},
		{"source in video", `<video><source src="a.webm"></video>`,
			[][]string{{"media-src", "a.webm"}}},
		{"nested elements", `<div><section><p><img src="a.png"></p></section></div>`,
			[][]string{{"img-src", "a.png"}}},
		{"document order", `<img src="1.png"><script src="2.js"></script><img src="3.png">`,
			[][]string{{"img-src", "1.png"}, {"script-src", "2.js"}, {"img-src", "3.png"}}},
		{"duplicates are kept", `<img src="a.png"><img src="a.png">`,
			[][]string{{"img-src", "a.png"}, {"img-src", "a.png"}}},

		// Inline scripts.
		{"inline script", `<script>a()</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"inline script with javascript type", `<script type="text/javascript">a()</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"inline module script", `<script type="module">a()</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"inline script with uppercase type", `<script type="TEXT/JAVASCRIPT">a()</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"inline script with other attribute", `<script id="a">a()</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"inline import map", `<script type="importmap">{}</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"inline script with padded type", `<script type=" module ">a()</script>`,
			[][]string{{"script-src", "unsafe-inline"}}},
		{"json data block", `<script type="application/ld+json">{}</script>`, nil},
		{"template data block", `<script type="text/template"><p></p></script>`, nil},
		{"empty script", `<script></script>`, nil},
		{"external script is not also inline", `<script src="a.js">ignored()</script>`,
			[][]string{{"script-src", "a.js"}}},

		// Inline styles.
		{"inline style with attribute", `<style media="print">a{}</style>`,
			[][]string{{"style-src", "unsafe-inline"}}},
		{"inline style with css type", `<style type="text/css">a{}</style>`,
			[][]string{{"style-src", "unsafe-inline"}}},
		{"style with non-css type", `<style type="text/x-less">a{}</style>`, nil},
		{"empty style", `<style></style>`, nil},

		// Only elements count.
		{"text matching a tag name", `<p>script</p><p>style</p>`, nil},
		{"comment matching a tag name", `<!--script-->`, nil},

		// Attributes that hold the URL.
		{"form action", `<form action="https://x.test/post"></form>`,
			[][]string{{"form-action", "https://x.test/post"}}},
		{"object data", `<object data="https://x.test/a.swf"></object>`,
			[][]string{{"object-src", "https://x.test/a.swf"}}},

		// rel is a case-insensitive, space-separated list.
		{"rel with other case", `<link rel="Stylesheet" href="a.css">`,
			[][]string{{"style-src", "a.css"}}},
		{"rel with several values", `<link rel="alternate stylesheet" href="a.css">`,
			[][]string{{"style-src", "a.css"}}},
		{"icon rel with other case", `<link rel="SHORTCUT Icon" href="a.ico">`,
			[][]string{{"img-src", "a.ico"}}},
		{"rel containing a value as a substring", `<link rel="apple-touch-icon" href="a.png">`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkSources(t, tt.input, tt.want)
		})
	}
}

// TestGetSourcesFixture runs the mikecb.org homepage from the project's
// original test.
func TestGetSourcesFixture(t *testing.T) {
	page, err := os.ReadFile("testdata/mikecb-org.html")
	if err != nil {
		t.Fatal(err)
	}
	got := minimalcsp.GetSources(string(page))
	want := [][]string{
		{"img-src", "images/favicon/favicon.ico"},
		{"img-src", "images/favicon/favicon.ico"},
		{"script-src", "js/material.min.js"},
		{"style-src", "stylesheets/material.cyan-deep_orange.min.css"},
		{"style-src", "stylesheets/icon.css"},
		{"style-src", "https://fonts.googleapis.com/css?family=Open+Sans:300"},
		{"style-src", "stylesheets/home.css"},
		{"script-src", "unsafe-inline"},
		{"script-src", "https://www.google-analytics.com/analytics.js"},
		{"style-src", "unsafe-inline"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fixture sources\n got %q\nwant %q", got, want)
	}
}

// policyFor returns what MakePolicy prints to stdout for the given page.
func policyFor(t *testing.T, page string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	minimalcsp.MakePolicy(page)

	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestMakePolicyIncludesEverySource(t *testing.T) {
	got := policyFor(t, `<img src="a.png"><script src="b.js"></script>`)
	for _, want := range []string{"img-src", "a.png", "script-src", "b.js"} {
		if !strings.Contains(got, want) {
			t.Errorf("policy %q is missing %q", got, want)
		}
	}
}

func TestMakePolicyDeduplicates(t *testing.T) {
	got := policyFor(t, `<img src="a.png"><img src="a.png">`)
	if n := strings.Count(got, "a.png"); n != 1 {
		t.Errorf("a.png appears %d times in %q, want 1", n, got)
	}
}

func TestMakePolicyGroupsDirectives(t *testing.T) {
	got := policyFor(t, `<img src="a.png"><img src="b.png">`)
	if n := strings.Count(got, "img-src"); n != 1 {
		t.Errorf("img-src appears %d times in %q, want 1", n, got)
	}
}

func TestMakePolicyIsNotAGoSlice(t *testing.T) {
	got := policyFor(t, `<img src="a.png"><script src="b.js"></script>`)
	if strings.HasPrefix(got, "[") || !strings.Contains(got, ";") {
		t.Errorf("policy %q is not semicolon-separated CSP", got)
	}
}

func TestMakePolicyFormat(t *testing.T) {
	got := policyFor(t, `<img src="1.png"><script src="2.js"></script><img src="3.png"><img src="1.png"><style>a{}</style>`)
	want := "img-src 1.png 3.png; script-src 2.js; style-src 'unsafe-inline'\n"
	if got != want {
		t.Errorf("policy\n got %q\nwant %q", got, want)
	}
}

func TestMakePolicyQuotesKeywords(t *testing.T) {
	got := policyFor(t, `<style>a{}</style>`)
	if !strings.Contains(got, "'unsafe-inline'") {
		t.Errorf("policy %q does not quote 'unsafe-inline'", got)
	}
}
