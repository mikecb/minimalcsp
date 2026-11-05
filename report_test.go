package minimalcsp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// These are the bodies Chrome 156 sent, apart from the host.
const (
	reportURIBody = `{"csp-report":{"document-uri":"https://site.test/uri?id=1","referrer":"","violated-directive":"img-src","effective-directive":"img-src","original-policy":"default-src 'none'; report-uri /report-uri","disposition":"report","blocked-uri":"https://other.test/pixel.png?token=secret","line-number":5,"column-number":65,"source-file":"https://site.test/uri","status-code":200,"script-sample":""}}`
	reportToBody  = `[{"age":2,"body":{"blockedURL":"inline","columnNumber":9,"disposition":"report","documentURL":"https://site.test/to?id=2","effectiveDirective":"script-src-elem","lineNumber":2,"originalPolicy":"default-src 'none'; report-to ep","referrer":"","sample":"window.inlineCode = \"this is an inline s","sourceFile":"https://site.test/to","statusCode":200},"type":"csp-violation","url":"https://site.test/to?id=2","user_agent":"Mozilla/5.0"}]`
)

func TestParseReports(t *testing.T) {
	tests := []struct {
		name, body, contentType string
		want                    []Report
	}{
		{"report-uri", reportURIBody, "application/csp-report", []Report{{
			Page:      "https://site.test/uri",
			Directive: "img-src",
			Blocked:   "https://other.test/pixel.png",
			Source:    "https://site.test/uri",
		}}},
		{"report-to", reportToBody, "application/reports+json", []Report{{
			Page:      "https://site.test/to",
			Directive: "script-src-elem",
			Blocked:   "inline",
			Sample:    `window.inlineCode = "this is an inline s`,
			Source:    "https://site.test/to",
		}}},
		{"content type parameters", reportURIBody, "application/csp-report; charset=utf-8", []Report{{
			Page:      "https://site.test/uri",
			Directive: "img-src",
			Blocked:   "https://other.test/pixel.png",
			Source:    "https://site.test/uri",
		}}},
		{"plain json", `{"csp-report":{"document-uri":"https://a.test/","effective-directive":"img-src","blocked-uri":"data"}}`, "application/json",
			[]Report{{Page: "https://a.test/", Directive: "img-src", Blocked: "data"}}},
		{"only violated-directive", `{"csp-report":{"document-uri":"https://a.test/","violated-directive":"img-src 'none'","blocked-uri":"data"}}`, "application/csp-report",
			[]Report{{Page: "https://a.test/", Directive: "img-src", Blocked: "data"}}},
		{"other report types", `[{"type":"deprecation","body":{"id":1}}]`, "application/reports+json", nil},
		{"private parts of URLs", `{"csp-report":{"document-uri":"https://user:pass@a.test/p?token=1#top","blocked-uri":"https://b.test/x?y=1#z","source-file":"https://c.test/s.js?v=1"}}`, "application/csp-report",
			[]Report{{Page: "https://a.test/p", Blocked: "https://b.test/x", Source: "https://c.test/s.js"}}},
		{"data URLs", `{"csp-report":{"document-uri":"https://a.test/","blocked-uri":"data:image/png;base64,AAAA"}}`, "application/csp-report",
			[]Report{{Page: "https://a.test/", Blocked: "data"}}},
		{"unparseable URL", `{"csp-report":{"document-uri":"https://a.test/%zz","blocked-uri":"inline"}}`, "application/csp-report",
			[]Report{{Blocked: "inline"}}},
		{"long samples", `{"csp-report":{"script-sample":"` + strings.Repeat("é", 100) + `"}}`, "application/csp-report",
			[]Report{{Sample: strings.Repeat("é", 40)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseReports([]byte(tt.body), tt.contentType)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseReportsFails(t *testing.T) {
	tests := []struct{ name, body, contentType string }{
		{"bad csp-report", `{`, "application/csp-report"},
		{"bad batch", `{`, "application/reports+json"},
		{"bad batch body", `[{"type":"csp-violation","body":{"sample":1}}]`, "application/reports+json"},
		{"wrong type", `{"csp-report":{"blocked-uri":1}}`, "application/csp-report"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseReports([]byte(tt.body), tt.contentType); err == nil {
				t.Error("no error")
			}
		})
	}
}

func post(t *testing.T, h http.Handler, method, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/reports", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestReportHandler(t *testing.T) {
	var got []Report
	h := ReportHandler{Receive: func(r Report) { got = append(got, r) }}
	tests := []struct {
		name, method, contentType, body string
		status, reports                 int
	}{
		{"report-uri", http.MethodPost, "application/csp-report", reportURIBody, http.StatusNoContent, 1},
		{"report-to", http.MethodPost, "application/reports+json", reportToBody, http.StatusNoContent, 1},
		{"not reports", http.MethodPost, "text/plain", "hello", http.StatusUnsupportedMediaType, 0},
		{"no content type", http.MethodPost, "", "hello", http.StatusUnsupportedMediaType, 0},
		{"bad json", http.MethodPost, "application/csp-report", "{", http.StatusBadRequest, 0},
		{"get", http.MethodGet, "", "", http.StatusMethodNotAllowed, 0},
		{"too big", http.MethodPost, "application/csp-report", strings.Repeat(" ", maxReportBody+1), http.StatusRequestEntityTooLarge, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = nil
			w := post(t, h, tt.method, tt.contentType, tt.body)
			if w.Code != tt.status {
				t.Errorf("status = %d, want %d", w.Code, tt.status)
			}
			if len(got) != tt.reports {
				t.Errorf("reports = %v", got)
			}
		})
	}
}

func TestReportHandlerPreflight(t *testing.T) {
	w := post(t, ReportHandler{Receive: func(Report) { t.Error("received a report") }}, http.MethodOptions, "", "")
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d", w.Code)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "POST",
		"Access-Control-Allow-Headers": "Content-Type",
	} {
		if got := w.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestReportClients(t *testing.T) {
	var got []Report
	h := ReportHandler{Receive: func(r Report) { got = append(got, r) }}
	from := func(address string) string {
		t.Helper()
		got = nil
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(reportURIBody))
		r.Header.Set("Content-Type", "application/csp-report")
		r.RemoteAddr = address
		h.ServeHTTP(httptest.NewRecorder(), r)
		if len(got) != 1 {
			t.Fatalf("reports = %v", got)
		}
		return got[0].Client
	}
	first := from("192.0.2.1:1234")
	if first == "" || strings.Contains(first, "192.0.2.1") {
		t.Errorf("client = %q", first)
	}
	if other := from("192.0.2.1:9999"); other != first {
		t.Error("a new port counted as a new client")
	}
	if other := from("192.0.2.2:1234"); other == first {
		t.Error("two addresses counted as one client")
	}
	if other := from("[::ffff:192.0.2.1]:1234"); other != first {
		t.Error("a mapped address counted as a new client")
	}
	if from("[2001:db8:0:1::1]:1") != from("[2001:db8:0:1:ffff::2]:1") {
		t.Error("one IPv6 /64 counted as two clients")
	}
	if from("[2001:db8:0:1::1]:1") == from("[2001:db8:0:2::1]:1") {
		t.Error("two IPv6 networks counted as one client")
	}
	if from("not an address") == from("something else") {
		t.Error("addresses that don't parse counted as one client")
	}
	if from("nonsense:1") == from("rubbish:1") {
		t.Error("hosts that don't parse counted as one client")
	}

	h.ClientID = func(r *http.Request) string { return "fixed" }
	if from("192.0.2.1:1") != from("192.0.2.2:1") {
		t.Error("ClientID wasn't used")
	}
	if from("192.0.2.1:1") == "fixed" {
		t.Error("ClientID wasn't hashed")
	}
}

func site(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://site.test/")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// addFrom adds a report from n clients.
func addFrom(tally *Tally, n int, r Report) {
	if r.Page == "" {
		r.Page = "https://site.test/page"
	}
	for i := range n {
		r.Client = fmt.Sprint("client", i)
		tally.Add(r)
	}
}

func findings(p *Page, opts Options) string {
	return Build(p, opts).String()
}

func TestTallyBuildsAPolicy(t *testing.T) {
	tally := &Tally{Site: site(t)}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://cdn.test/a.png"})
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://site.test/b.png"})
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "data"})
	addFrom(tally, 3, Report{Directive: "media-src", Blocked: "blob"})
	addFrom(tally, 3, Report{Directive: "style-src-elem", Blocked: "https://fonts.test/f.css"})
	addFrom(tally, 3, Report{Directive: "connect-src", Blocked: "wss://live.test/socket"})
	got := findings(tally.Page(), Options{})
	for _, want := range []string{
		"img-src 'self' data: https://cdn.test",
		"media-src blob:",
		"style-src https://fonts.test",
		"connect-src wss://live.test",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("%q isn't in %s", want, got)
		}
	}
}

func TestTallyMergesWithACollectedPage(t *testing.T) {
	collected := &Page{URL: site(t), Findings: []Finding{{Directive: "img-src", URL: &url.URL{Scheme: "https", Host: "a.test", Path: "/x"}}}}
	tally := &Tally{Site: site(t)}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://b.test/y"})
	got := Build(Merge(collected, tally.Page()), Options{}).String()
	if !strings.Contains(got, "img-src https://a.test https://b.test") {
		t.Errorf("policy = %s", got)
	}
}

func TestTallyNeedsRepeats(t *testing.T) {
	tests := []struct {
		name       string
		minClients int
		clients    int
		want       bool
	}{
		{"default, too few", 0, 2, false},
		{"default, enough", 0, 3, true},
		{"raised, too few", 5, 4, false},
		{"raised, enough", 5, 5, true},
		{"lowered", 1, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tally := &Tally{Site: site(t), MinClients: tt.minClients}
			addFrom(tally, tt.clients, Report{Directive: "img-src", Blocked: "https://a.test/x"})
			if got := len(tally.Page().Findings) == 1; got != tt.want {
				t.Errorf("found = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTallyCountsClientsNotReports(t *testing.T) {
	tally := &Tally{Site: site(t)}
	for range 100 {
		tally.Add(Report{Page: "https://site.test/", Directive: "img-src", Blocked: "https://a.test/x", Client: "same"})
	}
	if got := tally.Page().Findings; len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
}

func TestTallyGroupsByOrigin(t *testing.T) {
	tally := &Tally{Site: site(t)}
	for i := range 3 {
		tally.Add(Report{Page: "https://site.test/", Directive: "img-src", Blocked: fmt.Sprintf("https://a.test/%d", i), Client: fmt.Sprint(i)})
	}
	if got := findings(tally.Page(), Options{}); !strings.Contains(got, "img-src https://a.test") {
		t.Errorf("policy = %s", got)
	}

	exact := &Tally{Site: site(t), ExactPaths: true}
	for i := range 3 {
		exact.Add(Report{Page: "https://site.test/", Directive: "img-src", Blocked: fmt.Sprintf("https://a.test/%d", i), Client: fmt.Sprint(i)})
	}
	if got := exact.Page().Findings; len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
	addFrom(exact, 3, Report{Directive: "img-src", Blocked: "https://a.test/x.png"})
	if got := findings(exact.Page(), Options{ExactPaths: true}); !strings.Contains(got, "img-src https://a.test/x.png") {
		t.Errorf("policy = %s", got)
	}
}

func TestTallyIgnoresNoise(t *testing.T) {
	tests := []struct {
		name string
		r    Report
	}{
		{"chrome extension", Report{Directive: "img-src", Blocked: "chrome-extension://abc/i.png"}},
		{"firefox extension", Report{Directive: "img-src", Blocked: "moz-extension://abc/i.png"}},
		{"safari extension", Report{Directive: "img-src", Blocked: "safari-web-extension://abc/i.png"}},
		{"older safari extension", Report{Directive: "img-src", Blocked: "safari-extension://abc/i.png"}},
		{"edge extension", Report{Directive: "img-src", Blocked: "ms-browser-extension://abc/i.png"}},
		{"bare extension scheme", Report{Directive: "img-src", Blocked: "chrome-extension"}},
		{"code from an extension", Report{Directive: "script-src-elem", Blocked: "inline", Sample: "x", Source: "chrome-extension://abc/content.js"}},
		{"resource from an extension", Report{Directive: "img-src", Blocked: "https://a.test/x", Source: "moz-extension://abc/content.js"}},
		{"another site's page", Report{Page: "https://translate.test/site", Directive: "img-src", Blocked: "https://a.test/x"}},
		{"another port", Report{Page: "https://site.test:8443/", Directive: "img-src", Blocked: "https://a.test/x"}},
		{"another scheme", Report{Page: "http://site.test/", Directive: "img-src", Blocked: "https://a.test/x"}},
		{"unparseable page", Report{Page: "%zz", Directive: "img-src", Blocked: "https://a.test/x"}},
		{"unknown directive", Report{Directive: "frame-ancestors", Blocked: "https://a.test/x"}},
		{"keyword for another directive", Report{Directive: "img-src", Blocked: "inline"}},
		{"keyword for an unknown directive", Report{Directive: "evil", Blocked: "eval"}},
		{"other keyword", Report{Directive: "img-src", Blocked: "self"}},
		{"empty", Report{Directive: "img-src"}},
		{"other scheme", Report{Directive: "img-src", Blocked: "ftp://a.test/x"}},
		{"about", Report{Directive: "img-src", Blocked: "about:blank"}},
		{"unparseable blocked URL", Report{Directive: "img-src", Blocked: "https://a.test/%zz"}},
		{"host-less URL", Report{Directive: "img-src", Blocked: "https:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tally := &Tally{Site: site(t)}
			addFrom(tally, 3, tt.r)
			page := tally.Page()
			if len(page.Findings)+len(page.Blockers)+len(page.Warnings) != 0 {
				t.Errorf("page = %+v", page)
			}
		})
	}
}

func TestTallyWithoutASite(t *testing.T) {
	tally := &Tally{}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://a.test/x"})
	if got := tally.Page().Findings; len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
}

// A blocked URL ends up in a policy, so it mustn't be able to change its shape.
func TestTallyRejectsPolicyInjection(t *testing.T) {
	for _, blocked := range []string{
		"https://a.test;script-src *",
		"https://a.test,script-src",
		"https://a.test'unsafe-inline'",
		"https://a.test *",
		"https://*",
		"https://[::1]/x",
		"https://a.test:port/x",
		"https://a_b.test/x",
		"wss://a.test;x",
		"data;script-src",
		"blob ",
		"'unsafe-inline'",
		"*",
	} {
		t.Run(blocked, func(t *testing.T) {
			tally := &Tally{Site: site(t)}
			addFrom(tally, 3, Report{Directive: "img-src", Blocked: blocked})
			if got := tally.Page().Findings; len(got) != 0 {
				t.Errorf("findings = %v", got)
			}
		})
	}
	// Paths are kept with ExactPaths, so they have to stay in one piece.
	tally := &Tally{Site: site(t), ExactPaths: true}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://a.test/x;script-src,*%20y z"})
	if got := findings(tally.Page(), Options{ExactPaths: true}); strings.Count(got, "script-src") != 0 && !strings.Contains(got, "%3Bscript-src%2C") {
		t.Errorf("policy = %s", got)
	}
}

func TestTallyNeverTrustsCode(t *testing.T) {
	tests := []struct {
		name string
		r    Report
		want string
	}{
		{"script", Report{Directive: "script-src-elem", Blocked: "https://a.test/x.js"}, "a script's hash"},
		{"script fallback", Report{Directive: "script-src", Blocked: "https://a.test/x.js"}, "a script's hash"},
		{"worker", Report{Directive: "worker-src", Blocked: "https://a.test/w.js"}, "under worker-src, which can run code"},
		{"object", Report{Directive: "object-src", Blocked: "https://a.test/o"}, "object-src"},
		{"base", Report{Directive: "base-uri", Blocked: "https://a.test/"}, "base-uri"},
		{"inline script", Report{Directive: "script-src-elem", Blocked: "inline", Sample: "evil()"}, "evil()"},
		{"inline style", Report{Directive: "style-src-elem", Blocked: "inline", Sample: "a{}"}, "a{}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tally := &Tally{Site: site(t)}
			addFrom(tally, 3, tt.r)
			page := tally.Page()
			if len(page.Findings) != 0 {
				t.Errorf("findings = %v", page.Findings)
			}
			if len(page.Warnings) != 1 || !strings.Contains(page.Warnings[0], tt.want) || !strings.Contains(page.Warnings[0], "3 clients") {
				t.Errorf("warnings = %q, want %q", page.Warnings, tt.want)
			}
			for _, opts := range []Options{{}, {Scripts: ByNonce}, {Scripts: ByURL}} {
				policy := Build(page, opts).String()
				if strings.Contains(policy, "a.test") {
					t.Errorf("policy = %s", policy)
				}
			}
			if got := tally.Suggest(ParsePolicy("default-src 'none'")).Additions; len(got) != 0 {
				t.Errorf("additions = %v", got)
			}
		})
	}
}

func TestTallyFindsBlockers(t *testing.T) {
	tests := []struct {
		name   string
		r      Report
		reason string
	}{
		{"event handler", Report{Directive: "script-src-attr", Blocked: "inline", Sample: "go()"}, ReasonEventHandler},
		{"style attribute", Report{Directive: "style-src-attr", Blocked: "inline", Sample: "margin:0"}, ReasonStyleAttribute},
		{"eval", Report{Directive: "script-src", Blocked: "eval", Sample: "1+1"}, ReasonEval},
		{"wasm", Report{Directive: "script-src", Blocked: "wasm-eval"}, ReasonEval},
		{"javascript: URL", Report{Directive: "script-src-elem", Blocked: "inline", Sample: "javascript:alert(1)"}, ReasonJavaScriptURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tally := &Tally{Site: site(t)}
			addFrom(tally, 3, tt.r)
			got := tally.Suggest(ParsePolicy("default-src 'none'")).Blockers
			if want := []Blocker{{Reason: tt.reason, Value: tt.r.Sample}}; !slices.Equal(got, want) {
				t.Errorf("blockers = %v, want %v", got, want)
			}
		})
	}
}

func TestTallySamplesDontJoinUp(t *testing.T) {
	tally := &Tally{Site: site(t)}
	for i, sample := range []string{"a()", "b()", "c()"} {
		tally.Add(Report{Page: "https://site.test/", Directive: "script-src-elem", Blocked: "inline", Sample: sample, Client: fmt.Sprint(i)})
	}
	if got := tally.Page().Warnings; len(got) != 0 {
		t.Errorf("warnings = %q", got)
	}
}

func TestSampleOnAResourceIsNotABlocker(t *testing.T) {
	tally := &Tally{Site: site(t)}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://a.test/x", Sample: "javascript:x"})
	if page := tally.Page(); len(page.Findings) != 1 || len(page.Blockers) != 0 {
		t.Errorf("page = %+v", page)
	}
}

func TestSuggest(t *testing.T) {
	tally := &Tally{Site: site(t)}
	addFrom(tally, 5, Report{Directive: "img-src", Blocked: "https://cdn.test/a.png", Page: "https://site.test/one"})
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://cdn.test/b.png", Page: "https://site.test/two"})
	addFrom(tally, 4, Report{Directive: "font-src", Blocked: "https://fonts.test/f.woff2"})
	addFrom(tally, 2, Report{Directive: "media-src", Blocked: "https://rare.test/v.mp4"})
	addFrom(tally, 3, Report{Directive: "connect-src", Blocked: "https://api.test/x"})
	addFrom(tally, 3, Report{Directive: "style-src-elem", Blocked: "https://site.test/s.css"})
	addFrom(tally, 3, Report{Directive: "script-src-elem", Blocked: "https://a.test/x.js"})
	addFrom(tally, 3, Report{Directive: "script-src-attr", Blocked: "inline", Sample: "go()"})

	got := tally.Suggest(ParsePolicy("default-src 'none'; connect-src https://api.test; style-src 'self'"))
	if len(got.Additions) != 2 {
		t.Fatalf("additions = %+v", got.Additions)
	}
	first := got.Additions[0]
	if first.Directive != "img-src" || first.Source != "https://cdn.test" || first.Clients != 5 || first.Reports != 8 {
		t.Errorf("first = %+v", first)
	}
	if !slices.Equal(first.Pages, []string{"https://site.test/one", "https://site.test/two"}) {
		t.Errorf("pages = %v", first.Pages)
	}
	if !slices.Equal(first.Blocked, []string{"https://cdn.test/a.png", "https://cdn.test/b.png"}) {
		t.Errorf("blocked = %v", first.Blocked)
	}
	want := "img-src https://cdn.test: 8 reports from 5 clients, such as https://cdn.test/a.png on https://site.test/one"
	if first.String() != want {
		t.Errorf("String() = %q", first)
	}
	if second := got.Additions[1]; second.Directive != "font-src" || second.Source != "https://fonts.test" {
		t.Errorf("second = %+v", second)
	}
	if len(got.Blockers) != 1 || len(got.Warnings) != 1 {
		t.Errorf("blockers = %v, warnings = %v", got.Blockers, got.Warnings)
	}
}

func TestSuggestUsesDefaultSrc(t *testing.T) {
	tally := &Tally{Site: site(t)}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://a.test/x"})
	if got := tally.Suggest(ParsePolicy("default-src https://a.test; script-src 'none'")).Additions; len(got) != 0 {
		t.Errorf("additions = %v", got)
	}
	if got := tally.Suggest(ParsePolicy("script-src 'none'")).Additions; len(got) != 1 {
		t.Errorf("additions = %v", got)
	}
	// A directive of its own replaces default-src, as it does in browsers.
	if got := tally.Suggest(ParsePolicy("default-src https://a.test; img-src 'self'")).Additions; len(got) != 1 {
		t.Errorf("additions = %v", got)
	}
	if got := tally.Suggest(ParsePolicy("img-src 'self'; default-src https://a.test")).Additions; len(got) != 1 {
		t.Errorf("additions = %v", got)
	}
}

func TestSuggestOrderIsStable(t *testing.T) {
	want := []string{"connect-src https://a.test", "font-src https://a.test", "img-src https://a.test", "img-src https://b.test"}
	for range 20 {
		tally := &Tally{Site: site(t)}
		addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://b.test/x"})
		addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://a.test/x"})
		addFrom(tally, 3, Report{Directive: "font-src", Blocked: "https://a.test/x"})
		addFrom(tally, 3, Report{Directive: "connect-src", Blocked: "https://a.test/x"})
		var got []string
		for _, a := range tally.Suggest(ParsePolicy("")).Additions {
			got = append(got, a.Directive+" "+a.Source)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestTallyEvidenceIsLimited(t *testing.T) {
	tally := &Tally{Site: site(t)}
	for i := range 20 {
		tally.Add(Report{
			Page:      fmt.Sprintf("https://site.test/%d", i),
			Directive: "img-src",
			Blocked:   fmt.Sprintf("https://a.test/%d", i),
			Client:    fmt.Sprint(i),
		})
	}
	got := tally.Suggest(ParsePolicy("")).Additions
	if len(got) != 1 || len(got[0].Pages) != evidenceLimit || len(got[0].Blocked) != evidenceLimit || got[0].Reports != 20 {
		t.Errorf("additions = %+v", got)
	}
}

func TestTallyMemoryIsLimited(t *testing.T) {
	tally := &Tally{Site: site(t)}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://real.test/x"})
	for i := range tallyLimit + 5 {
		tally.Add(Report{Page: "https://site.test/", Directive: "img-src", Blocked: fmt.Sprintf("https://%d.test/", i), Client: "flood"})
	}
	if len(tally.entries) != tallyLimit {
		t.Errorf("entries = %d", len(tally.entries))
	}
	page := tally.Page()
	if len(page.Findings) != 1 {
		t.Errorf("findings = %v", page.Findings)
	}
	if len(page.Warnings) != 1 || !strings.HasPrefix(page.Warnings[0], "6 reports weren't counted") {
		t.Errorf("warnings = %q", page.Warnings)
	}
	addFrom(tally, 3, Report{Directive: "img-src", Blocked: "https://real.test/y"})
	if got := len(tally.Page().Findings); got != 1 {
		t.Errorf("findings = %d", got)
	}

	busy := &Tally{Site: site(t), MinClients: 1}
	for i := range clientLimit + 5 {
		busy.Add(Report{Page: "https://site.test/", Directive: "img-src", Blocked: "https://a.test/x", Client: fmt.Sprint(i)})
	}
	got := busy.Suggest(ParsePolicy("")).Additions
	if len(got) != 1 || got[0].Clients != clientLimit || got[0].Reports != clientLimit+5 {
		t.Errorf("additions = %+v", got)
	}
}

func TestTallyWithConcurrentReports(t *testing.T) {
	tally := &Tally{Site: site(t)}
	h := ReportHandler{
		Receive:  tally.Add,
		ClientID: func(r *http.Request) string { return r.Header.Get("X-Client") },
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
				`{"csp-report":{"document-uri":"https://site.test/","effective-directive":"img-src","blocked-uri":"https://a.test/x"}}`))
			r.Header.Set("Content-Type", "application/csp-report")
			r.Header.Set("X-Client", fmt.Sprint(i))
			h.ServeHTTP(httptest.NewRecorder(), r)
			tally.Page()
		})
	}
	wg.Wait()
	got := tally.Suggest(ParsePolicy("")).Additions
	if len(got) != 1 || got[0].Clients != 20 {
		t.Errorf("additions = %+v", got)
	}
}

func TestParsePolicy(t *testing.T) {
	got := ParsePolicy(" Default-Src 'none' ;; img-src 'self'  https://a.test; img-src https://b.test; upgrade-insecure-requests; ")
	want := "default-src 'none'; img-src 'self' https://a.test; upgrade-insecure-requests"
	if got.String() != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := ParsePolicy(""); len(got.Directives) != 0 {
		t.Errorf("directives = %v", got.Directives)
	}
}

func TestReportingTo(t *testing.T) {
	policy := ParsePolicy("default-src 'none'; script-src 'sha256-x'; style-src 'self'; img-src 'self'")
	got := policy.ReportingTo("/reports").String()
	want := "default-src 'none'; script-src 'sha256-x' 'report-sample'; style-src 'self' 'report-sample'; img-src 'self'; report-uri /reports"
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	if strings.Contains(policy.String(), "report") {
		t.Errorf("the original changed: %s", policy)
	}
}

func TestNonceMiddlewareReports(t *testing.T) {
	policy := &Policy{Directives: []Directive{{"script-src", []string{"'nonce-" + NoncePlaceholder + "'"}}}}
	var nonce string
	handler := NonceMiddleware{Policy: policy, ReportOnly: true, ReportTo: "/reports"}.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		nonce = Nonce(r.Context())
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	want := "script-src 'nonce-" + nonce + "' 'report-sample'; report-uri /reports"
	if got := w.Header().Get("Content-Security-Policy-Report-Only"); got != want {
		t.Errorf("policy = %q, want %q", got, want)
	}

	w = httptest.NewRecorder()
	NonceMiddleware{Policy: policy}.Wrap(http.NewServeMux()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := w.Header().Get("Content-Security-Policy"); strings.Contains(got, "report") {
		t.Errorf("policy = %q", got)
	}
}
