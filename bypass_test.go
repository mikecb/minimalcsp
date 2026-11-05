package minimalcsp

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestBypassWarnings(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []string // A substring of each expected warning, in order.
	}{
		{"no scripts", "default-src 'none'; img-src https://www.google.com", nil},
		{"unlisted host", "script-src https://scripts.example", nil},
		{"keywords and hashes", "script-src 'self' 'sha256-a/b+c=' 'nonce-abc' 'unsafe-inline' data: blob:", nil},
		{"JSONP", "script-src 'self' https://www.google.com", []string{
			"script-src allows https://www.google.com, which has a JSONP endpoint at https://www.google.com/complete/search",
		}},
		{"AngularJS", "script-src https://ajax.googleapis.com", []string{
			"script-src allows https://ajax.googleapis.com, which serves AngularJS at https://ajax.googleapis.com/ajax/libs/angularjs/",
		}},
		{"public CDN", "script-src https://cdn.jsdelivr.net", []string{
			"script-src allows https://cdn.jsdelivr.net, which lets anyone publish files, such as https://cdn.jsdelivr.net/npm/",
		}},
		{"one warning per source", "script-src https://*.google.com https://unpkg.com", []string{
			"https://*.google.com, which has a JSONP", "https://unpkg.com, which lets anyone",
		}},
		{"default-src", "default-src https://www.google.com", []string{"default-src allows https://www.google.com"}},
		{"script-src-elem", "script-src 'self'; script-src-elem https://www.google.com", []string{
			"script-src-elem allows https://www.google.com",
		}},
		{"script-src over default-src", "default-src https://www.google.com; script-src 'self'", nil},
		{"script-src-elem over script-src", "script-src https://www.google.com; script-src-elem 'self'", nil},
		{"strict-dynamic", "script-src 'strict-dynamic' https://www.google.com", nil},
		{"strict-dynamic in any case", "script-src 'Strict-Dynamic' https://www.google.com", nil},
		{"strict-dynamic elsewhere", "script-src https://www.google.com; style-src 'strict-dynamic'", []string{"www.google.com"}},

		{"the reCAPTCHA path", "script-src https://www.google.com/recaptcha/", nil},
		{"one site on a shared platform", "script-src https://me.github.io", nil},
		{"every site on a shared platform", "script-src https://*.github.io", []string{"https://attacker.github.io/x.js"}},
		{"one bucket", "script-src https://storage.googleapis.com/my-bucket/", nil},
		{"every bucket", "script-src https://storage.googleapis.com", []string{"storage.googleapis.com"}},
		{"one file on a CDN", "script-src https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js", nil},
		{"one JSONP endpoint", "script-src https://www.google.com/complete/search", []string{"JSONP"}},

		{"any host", "script-src *", []string{"script-src allows *, so injected markup can load a script from any host"}},
		{"a scheme", "script-src https:", []string{"script-src allows https:, so injected markup"}},
		{"a wildcard", "script-src https://*", []string{"script-src allows https://*, so injected markup"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsePolicy(tt.header).Warnings
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

func TestBuildWarnsAboutBypasses(t *testing.T) {
	page := func(rawURL string) *Page {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		return &Page{
			URL:      &url.URL{Scheme: "https", Host: "site.example", Path: "/"},
			Findings: []Finding{{Directive: "script-src", URL: u, Hashes: []string{"sha256-a"}}},
		}
	}
	warned := func(p *Policy) bool {
		return slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "JSONP") })
	}

	endpoint := page("https://www.google.com/complete/search?jsonp=a")
	if !warned(Build(endpoint, Options{Scripts: ByURL})) {
		t.Error("listing a JSONP endpoint by URL should warn")
	}
	if warned(Build(endpoint, Options{Scripts: ByHash})) {
		t.Error("trusting a script by hash lists no host, so it shouldn't warn")
	}
	if warned(Build(endpoint, Options{Scripts: ByNonce})) {
		t.Error("trusting a script by nonce lists no host, so it shouldn't warn")
	}
	if warned(Build(page("https://www.google.com/a.js"), Options{Scripts: ByURL})) {
		t.Error("an exact URL elsewhere on the host shouldn't warn")
	}
}

func TestBypassEntries(t *testing.T) {
	for _, b := range bypasses {
		if !strings.HasPrefix(b.path, "/") || b.host != strings.ToLower(b.host) {
			t.Errorf("%+v isn't a lowercase host and an absolute path", b)
		}
		if !hostSourceAllows("https://"+b.host, b.host, b.path) {
			t.Errorf("%s doesn't match itself", b.host)
		}
		if strings.Count(b.why, "%s") != 1 {
			t.Errorf("%s has a bad reason: %q", b.host, b.why)
		}
	}
}
