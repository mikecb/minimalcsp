package browser_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/mikecb/minimalcsp"
)

// serveTLS is serve over HTTPS, which the Reporting API needs.
func serveTLS(t *testing.T, s site) string {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if handler, ok := s[host+r.URL.Path]; ok {
			handler(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// visit loads pageURL in plain Chrome and keeps it open until done reports true.
// Reports are sent in the background, so closing Chrome early loses them.
func visit(t *testing.T, pageURL string, wait time.Duration, done func() bool) {
	t.Helper()
	opts := append(slices.Clone(chromedp.DefaultExecAllocatorOptions[:]), collector().Options...)
	opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	allocator, stop := chromedp.NewExecAllocator(context.Background(), opts...)
	defer stop()
	ctx, cancel := chromedp.NewContext(allocator)
	defer cancel()
	err := chromedp.Do(ctx, chromedp.Navigate(pageURL))
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		requireChrome(t, fmt.Errorf("starting Chrome: %w", err))
	}
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(wait); time.Now().Before(deadline) && !done(); {
		time.Sleep(50 * time.Millisecond)
	}
}

// inbox keeps what a ReportHandler receives.
type inbox struct {
	mu      sync.Mutex
	reports []minimalcsp.Report
}

func (i *inbox) add(r minimalcsp.Report) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.reports = append(i.reports, r)
}

func (i *inbox) has(blocked string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.ContainsFunc(i.reports, func(r minimalcsp.Report) bool { return strings.HasSuffix(r.Blocked, blocked) })
}

func (i *inbox) all() []minimalcsp.Report {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.reports)
}

// reportingPage serves body under policy in report-only mode, the way the
// library's docs say to.
func reportingPage(policy *minimalcsp.Policy, endpoint, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", policy.ReportingTo(endpoint).String())
		html(body)(w, nil)
	}
}

// reportToPage sets up the Reporting API by hand. The library doesn't generate
// this, but a site already using it can point it at a ReportHandler.
func reportToPage(endpoint, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'none'; img-src 'self'; report-to ep")
		w.Header().Set("Reporting-Endpoints", fmt.Sprintf("ep=%q", endpoint))
		html(body)(w, nil)
	}
}

// reportOnly is the policy tests start from. It allows the icon, so that the
// only report is the one a test is looking for.
func reportOnly() *minimalcsp.Policy {
	return minimalcsp.ParsePolicy("default-src 'none'; img-src 'self'")
}

func TestReportingToReachesTheHandler(t *testing.T) {
	var got inbox
	s := site{"site.test/reports": minimalcsp.ReportHandler{Receive: got.add}.ServeHTTP}
	port := serveTLS(t, s)
	s["site.test/"] = reportingPage(reportOnly(), "/reports", `<img src="https://cdn.test:`+port+`/a.png?token=secret">`)
	visit(t, "https://site.test:"+port+"/?id=1", 10*time.Second, func() bool { return got.has("/a.png") })

	reports := got.all()
	if len(reports) != 1 {
		t.Fatalf("reports = %+v", reports)
	}
	r := reports[0]
	if want := "https://cdn.test:" + port + "/a.png"; r.Blocked != want {
		t.Errorf("blocked = %q, want %q", r.Blocked, want)
	}
	if want := "https://site.test:" + port + "/"; r.Page != want {
		t.Errorf("page = %q, want %q", r.Page, want)
	}
	if r.Directive != "img-src" || r.Client == "" {
		t.Errorf("report = %+v", r)
	}
}

// With report-to in the policy as well, Chrome would send nothing from this page.
func TestReportingToOnHTTP(t *testing.T) {
	var got inbox
	s := site{"site.test/reports": minimalcsp.ReportHandler{Receive: got.add}.ServeHTTP}
	port := serve(t, s)
	s["site.test/"] = reportingPage(reportOnly(), "/reports", `<img src="http://cdn.test:`+port+`/a.png">`)
	visit(t, "http://site.test:"+port+"/", 10*time.Second, func() bool { return got.has("/a.png") })
	if !got.has("/a.png") {
		t.Errorf("reports = %+v", got.all())
	}
}

func TestReportingToAnotherOrigin(t *testing.T) {
	var got inbox
	s := site{"reports.test/in": minimalcsp.ReportHandler{Receive: got.add}.ServeHTTP}
	port := serve(t, s)
	s["site.test/"] = reportingPage(reportOnly(), "http://reports.test:"+port+"/in", `<img src="http://cdn.test:`+port+`/a.png">`)
	visit(t, "http://site.test:"+port+"/", 10*time.Second, func() bool { return got.has("/a.png") })
	if !got.has("/a.png") {
		t.Errorf("reports = %+v", got.all())
	}
}

func TestReportingAPIReachesTheHandler(t *testing.T) {
	var got inbox
	s := site{"site.test/reports": minimalcsp.ReportHandler{Receive: got.add}.ServeHTTP}
	port := serveTLS(t, s)
	s["site.test/"] = reportToPage("https://site.test:"+port+"/reports", `<img src="https://cdn.test:`+port+`/a.png">`)
	visit(t, "https://site.test:"+port+"/", 30*time.Second, func() bool { return got.has("/a.png") })
	if !got.has("/a.png") {
		t.Errorf("reports = %+v", got.all())
	}
}

// This needs the preflight answered.
func TestReportingAPIToAnotherOrigin(t *testing.T) {
	var got inbox
	s := site{"reports.test/in": minimalcsp.ReportHandler{Receive: got.add}.ServeHTTP}
	port := serveTLS(t, s)
	s["site.test/"] = reportToPage("https://reports.test:"+port+"/in", `<img src="https://cdn.test:`+port+`/a.png">`)
	visit(t, "https://site.test:"+port+"/", 30*time.Second, func() bool { return got.has("/a.png") })
	if !got.has("/a.png") {
		t.Errorf("reports = %+v", got.all())
	}
}

// This is the whole path: a policy that's missing something, a real browser
// reporting it, and a suggestion that fixes it.
func TestReportsFixAPolicy(t *testing.T) {
	var got inbox
	s := site{"site.test/reports": minimalcsp.ReportHandler{Receive: got.add}.ServeHTTP}
	port := serve(t, s)
	pageURL := "http://site.test:" + port + "/"
	body := `<img src="/late.png"><img src="http://cdn.test:` + port + `/a.png"><script>eval("1")</script><p onclick="go()"></p>`
	policy := minimalcsp.ParsePolicy("default-src 'none'; img-src 'self'; script-src 'unsafe-inline'")

	s["site.test/"] = reportingPage(policy, "/reports", body)
	visit(t, pageURL, 10*time.Second, func() bool { return got.has("/a.png") && got.has("eval") })

	parsed, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	tally := &minimalcsp.Tally{Site: parsed, MinClients: 1}
	for _, r := range got.all() {
		tally.Add(r)
	}
	suggestions := tally.Suggest(policy)
	if len(suggestions.Additions) != 1 || suggestions.Additions[0].Directive != "img-src" ||
		suggestions.Additions[0].Source != "http://cdn.test:"+port {
		t.Fatalf("additions = %+v, reports = %+v", suggestions.Additions, got.all())
	}
	if !slices.ContainsFunc(suggestions.Blockers, func(b minimalcsp.Blocker) bool { return b.Reason == minimalcsp.ReasonEval }) {
		t.Errorf("blockers = %+v, reports = %+v", suggestions.Blockers, got.all())
	}

	// The fixed policy must leave nothing for the browser to report.
	for i, d := range policy.Directives {
		if d.Name == "img-src" {
			policy.Directives[i].Sources = append(d.Sources, suggestions.Additions[0].Source)
		}
	}
	var after inbox
	s["site.test/reports"] = minimalcsp.ReportHandler{Receive: after.add}.ServeHTTP
	visit(t, pageURL+"?again", 2*time.Second, func() bool { return after.has("/a.png") })
	if after.has("/a.png") {
		t.Errorf("reports = %+v", after.all())
	}
}
