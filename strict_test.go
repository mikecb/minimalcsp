package minimalcsp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/mikecb/minimalcsp"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func scriptSources(t *testing.T, policy *minimalcsp.Policy) []string {
	t.Helper()
	for _, d := range policy.Directives {
		if d.Name == "script-src" {
			return d.Sources
		}
	}
	return nil
}

func TestHashIsTheDefault(t *testing.T) {
	if got := (minimalcsp.Options{}).Scripts; got != minimalcsp.ByHash {
		t.Errorf("default = %v, want ByHash", got)
	}
}

func TestBuildByHash(t *testing.T) {
	const (
		rootHash  = "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="
		otherHash = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	)
	root := func(raw string, hashes ...string) minimalcsp.Finding {
		return minimalcsp.Finding{Directive: "script-src", URL: mustURL(t, raw), Hashes: hashes}
	}
	loaded := func(raw string) minimalcsp.Finding {
		return minimalcsp.Finding{Directive: "script-src", URL: mustURL(t, raw), Loaded: true}
	}
	inline := minimalcsp.Finding{Directive: "script-src", Code: "x()"}

	tests := []struct {
		name     string
		findings []minimalcsp.Finding
		want     []string
	}{
		{"nothing", nil, nil},
		{"inline code", []minimalcsp.Finding{inline}, []string{hash("x()")}},
		{"external script", []minimalcsp.Finding{root(testURL+"a.js", rootHash)}, []string{"'" + rootHash + "'"}},
		{
			"several hashes",
			[]minimalcsp.Finding{root(testURL+"a.js", otherHash, rootHash)},
			[]string{"'" + rootHash + "'", "'" + otherHash + "'"},
		},
		{"repeated", []minimalcsp.Finding{root(testURL+"a.js", rootHash), root(testURL+"a.js", rootHash)}, []string{"'" + rootHash + "'"}},
		{
			"loaded scripts rely on strict-dynamic",
			[]minimalcsp.Finding{root(testURL+"a.js", rootHash), loaded("https://cdn.test/b.js")},
			[]string{"'" + rootHash + "'", "'strict-dynamic'"},
		},
		{
			"loaded inline code relies on strict-dynamic",
			[]minimalcsp.Finding{inline, {Directive: "script-src", Code: "y()", Loaded: true}},
			[]string{hash("x()"), "'strict-dynamic'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := &minimalcsp.Page{URL: mustURL(t, testURL), Findings: tt.findings}
			policy := minimalcsp.Build(page, minimalcsp.Options{})
			got := scriptSources(t, policy)
			want := slices.Sorted(slices.Values(tt.want))
			if !slices.Equal(got, want) {
				t.Errorf("script-src = %v, want %v", got, want)
			}
			if err := checkCSP(policy.String()); err != nil {
				t.Errorf("%v in %s", err, policy)
			}
			if len(policy.Warnings) != 0 {
				t.Errorf("warnings = %v", policy.Warnings)
			}
		})
	}
}

func TestBuildByHashNeverListsURLs(t *testing.T) {
	policy := policyStrict(t, `<script src="https://cdn.test/a.js"></script><script src="/b.js"></script>`, minimalcsp.ByHash)
	if got := scriptSources(t, policy); got != nil {
		t.Errorf("script-src = %v", got)
	}
	var unhashed int
	for _, warning := range policy.Warnings {
		if strings.HasPrefix(warning, "couldn't hash") {
			unhashed++
		}
	}
	if unhashed != 2 {
		t.Errorf("warnings = %v, want one for each unhashed script", policy.Warnings)
	}
	if strings.Contains(strings.Join(policy.Warnings, "\n"), "by URL") {
		t.Errorf("warnings = %v", policy.Warnings)
	}
}

func policyStrict(t *testing.T, input string, trust minimalcsp.ScriptTrust) *minimalcsp.Policy {
	t.Helper()
	return minimalcsp.Build(parseAt(t, testURL, input), minimalcsp.Options{Scripts: trust})
}

func TestIntegrityAttributesAreRead(t *testing.T) {
	const a = "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="
	const b = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
	tests := []struct {
		attr string
		want []string
	}{
		{a, []string{a}},
		{"  " + a + "\n" + b + " ", []string{a, b}},
		{a + "?ct=application/javascript", []string{a}},
		{"md5-abc", nil},
		{"", nil},
	}
	for _, tt := range tests {
		page := parseAt(t, testURL, `<script src="/a.js" integrity="`+tt.attr+`"></script>`)
		if got := page.Findings[0].Hashes; !slices.Equal(got, tt.want) {
			t.Errorf("%q: got %v, want %v", tt.attr, got, tt.want)
		}
	}
}

func TestPolicyIntegrity(t *testing.T) {
	const a = "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="
	page := &minimalcsp.Page{URL: mustURL(t, "https://x.test/"), Findings: []minimalcsp.Finding{
		{Directive: "script-src", URL: mustURL(t, "https://x.test/a.js"), Hashes: []string{a}},
		{Directive: "script-src", URL: mustURL(t, "https://x.test/a.js"), Hashes: []string{a}},
		{Directive: "script-src", URL: mustURL(t, "https://cdn.test/b.js"), Hashes: []string{a}},
		{Directive: "script-src", URL: mustURL(t, "https://cdn.test/c.js"), Loaded: true},
	}}
	policy := minimalcsp.Build(page, minimalcsp.Options{})
	var got []string
	for _, i := range policy.Integrity {
		got = append(got, i.String())
	}
	want := []string{
		`https://x.test/a.js needs integrity="` + a + `"`,
		`https://cdn.test/b.js needs integrity="` + a + `" crossorigin="anonymous"`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildByNonce(t *testing.T) {
	const nonce = "'nonce-{nonce}'"
	tests := []struct {
		name, input string
		want        []string
	}{
		{"no scripts", `<p>hello`, nil},
		{"inline", `<script>x()</script>`, []string{nonce}},
		{"external", `<script src="https://cdn.test/a.js"></script>`, []string{nonce}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := policyStrict(t, tt.input, minimalcsp.ByNonce)
			if got := scriptSources(t, policy); !slices.Equal(got, tt.want) {
				t.Errorf("script-src = %v, want %v", got, tt.want)
			}
			if len(policy.Warnings) > 1 || len(policy.Integrity) != 0 {
				t.Errorf("warnings = %v, integrity = %v", policy.Warnings, policy.Integrity)
			}
		})
	}
}

func TestBuildByNonceWithLoadedScripts(t *testing.T) {
	page := &minimalcsp.Page{URL: mustURL(t, testURL), Findings: []minimalcsp.Finding{
		{Directive: "script-src", Code: "x()"},
		{Directive: "script-src", URL: mustURL(t, "https://cdn.test/b.js"), Loaded: true},
	}}
	policy := minimalcsp.Build(page, minimalcsp.Options{Scripts: minimalcsp.ByNonce})
	if got, want := scriptSources(t, policy), []string{"'nonce-{nonce}'", "'strict-dynamic'"}; !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	header := policy.WithNonce("YWJj")
	if strings.Contains(header, minimalcsp.NoncePlaceholder) || !strings.Contains(header, "'nonce-YWJj'") {
		t.Errorf("header = %s", header)
	}
	if err := checkCSP(header); err != nil {
		t.Errorf("%v in %s", err, header)
	}
}

func TestStrictModesLeaveOtherDirectivesAlone(t *testing.T) {
	const input = `<img src="https://cdn.test/i.png"><style>p{}</style><script>x()</script>`
	imgs := func(p *minimalcsp.Policy) string {
		_, rest, _ := strings.Cut(p.String(), "img-src ")
		first, _, _ := strings.Cut(rest, ";")
		return first
	}
	for _, trust := range []minimalcsp.ScriptTrust{minimalcsp.ByHash, minimalcsp.ByNonce} {
		policy := policyStrict(t, input, trust)
		if got := imgs(policy); got != "https://cdn.test" {
			t.Errorf("img-src = %q", got)
		}
		if !strings.Contains(policy.String(), "style-src "+hash("p{}")) {
			t.Errorf("policy = %s", policy)
		}
	}
}

func TestApply(t *testing.T) {
	const a = "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="
	policy := &minimalcsp.Policy{Integrity: []minimalcsp.Integrity{
		{URL: mustURL(t, "https://x.test/dir/a.js"), Value: a},
		{URL: mustURL(t, "https://cdn.test/b.js"), Value: a, CrossOrigin: true},
	}}
	ia := ` integrity="` + a + `"`
	tests := []struct{ name, input, want string }{
		{"relative", `<script src="a.js"></script>`, `<script src="a.js"` + ia + `></script>`},
		{"absolute path", `<script src="/dir/a.js"></script>`, `<script src="/dir/a.js"` + ia + `></script>`},
		{"unquoted, upper case", `<SCRIPT SRC=a.js></SCRIPT>`, `<SCRIPT SRC=a.js` + ia + `></SCRIPT>`},
		{"self-closing", `<script src="a.js"/>`, `<script src="a.js"` + ia + `/>`},
		{"unquoted slash stays in the value", `<script src=a.js/></script>`, `<script src=a.js/></script>`},
		{"cross-origin", `<script src="https://cdn.test/b.js"></script>`, `<script src="https://cdn.test/b.js"` + ia + ` crossorigin="anonymous"></script>`},
		{"keeps existing attributes", `<script src="a.js" integrity="sha256-other"></script>`, `<script src="a.js" integrity="sha256-other"></script>`},
		{"base tag", `<base href="/"><script src="dir/a.js"></script>`, `<base href="/"><script src="dir/a.js"` + ia + `></script>`},
		{"entity in an attribute", `<script src="a.js" data-x="1&amp;2&lt;3"></script>`, `<script src="a.js" data-x="1&amp;2&lt;3"` + ia + `></script>`},
		{"upper case entity tag", `<SCRIPT SRC="a.js" DATA-X="&amp;"></SCRIPT>`, `<SCRIPT SRC="a.js" DATA-X="&amp;"` + ia + `></SCRIPT>`},
		{"other scripts", `<script src="c.js"></script><script>x()</script>`, `<script src="c.js"></script><script>x()</script>`},
		{"code that mentions a tag", `<script>"<script src=a.js>"</script>`, `<script>"<script src=a.js>"</script>`},
		{"comment", `<!-- <script src="a.js"></script> -->`, `<!-- <script src="a.js"></script> -->`},
		{"keeps bytes exactly", "<!DOCTYPE html>\r\n<P CLASS=x>caf\xe9 &amp; <br/>\r\n", "<!DOCTYPE html>\r\n<P CLASS=x>caf\xe9 &amp; <br/>\r\n"},
		{"unfinished tag", `<script src="a.js"`, `<script src="a.js"`},
		{"empty", ``, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(policy.Apply([]byte(tt.input), mustURL(t, "https://x.test/dir/page.html")))
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestEditScriptTagsPassesInlineScripts(t *testing.T) {
	var got []string
	out := minimalcsp.EditScriptTags([]byte(`<script>x()</script><script src="/a.js"></script>`), mustURL(t, testURL),
		func(src *url.URL) []html.Attribute {
			if src == nil {
				got = append(got, "inline")
			} else {
				got = append(got, src.String())
			}
			return []html.Attribute{{Key: "nonce", Val: "abc"}}
		})
	if want := []string{"inline", "https://x.test/a.js"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if want := `<script nonce="abc">x()</script><script src="/a.js" nonce="abc"></script>`; string(out) != want {
		t.Errorf("got %s", out)
	}
}

func TestNonceMiddleware(t *testing.T) {
	policy := policyStrict(t, `<script>x()</script>`, minimalcsp.ByNonce)
	var seen []string
	handler := minimalcsp.NonceMiddleware{Policy: policy}.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, minimalcsp.Nonce(r.Context()))
	}))
	shape := regexp.MustCompile(`^[A-Za-z0-9+/]{22}==$`)
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		nonce := seen[len(seen)-1]
		if !shape.MatchString(nonce) {
			t.Errorf("nonce = %q, want 128 random bits in base64", nonce)
		}
		header := w.Header().Get("Content-Security-Policy")
		if want := policy.WithNonce(nonce); header != want {
			t.Errorf("header = %q, want %q", header, want)
		}
		if got := w.Header().Get("Content-Security-Policy-Report-Only"); got != "" {
			t.Errorf("report-only header = %q", got)
		}
	}
	if seen[0] == seen[1] {
		t.Errorf("nonce repeated: %q", seen[0])
	}
}

func TestNonceMiddlewareReportOnly(t *testing.T) {
	policy := policyStrict(t, `<script>x()</script>`, minimalcsp.ByNonce)
	handler := minimalcsp.NonceMiddleware{Policy: policy, ReportOnly: true}.Wrap(http.NotFoundHandler())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Header().Get("Content-Security-Policy-Report-Only") == "" || w.Header().Get("Content-Security-Policy") != "" {
		t.Errorf("headers = %v", w.Header())
	}
}

func TestNonceOutsideMiddleware(t *testing.T) {
	if got := minimalcsp.Nonce(context.Background()); got != "" {
		t.Errorf("got %q", got)
	}
}
