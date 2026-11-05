package browser_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/mikecb/minimalcsp"
	"github.com/mikecb/minimalcsp/browser"
)

var _ minimalcsp.Collector = browser.Collector{}

// site is a fake website. Every host resolves to one local server, so tests can
// be cross-origin, and handlers route on "host/path". Hosts in routes leave out
// the port.
type site map[string]http.HandlerFunc

// html serves a page. It declares the favicon that Chrome would otherwise fetch
// at some point after the page loads, which keeps results the same on every run.
func html(body string) http.HandlerFunc {
	return content("text/html; charset=utf-8", `<!doctype html><link rel=icon href=/favicon.ico>`+body)
}

func content(contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		fmt.Fprint(w, body)
	}
}

// serve starts s and returns the port it listens on.
func serve(t *testing.T, s site) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// localNetworkAllowed keeps the features chromedp turns off by default.
var localNetworkAllowed = chromedp.Flag("disable-features", "Translate,BlinkGenPropertyTrees,LocalNetworkAccessChecks")

func collector() browser.Collector {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.Flag("host-resolver-rules", "MAP * 127.0.0.1"),
		// The fake hosts resolve to a local address, like a site on a private network.
		localNetworkAllowed,
	}
	if os.Getenv("CI") != "" {
		// CI runners don't allow the unprivileged namespaces Chrome's sandbox needs.
		opts = append(opts, chromedp.NoSandbox)
	}
	return browser.Collector{Options: opts, Settle: 150 * time.Millisecond}
}

// requireChrome skips tests on machines without Chrome. CI must have it, so the
// browser tests can't silently stop running there.
func requireChrome(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "starting Chrome") && os.Getenv("CI") == "" {
		t.Skip(err)
	}
}

func collect(t *testing.T, c browser.Collector, pageURL string) *minimalcsp.Page {
	t.Helper()
	page, err := c.Collect(t.Context(), pageURL)
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func hash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func sources(t *testing.T, policy *minimalcsp.Policy, name string) []string {
	t.Helper()
	for _, d := range policy.Directives {
		if d.Name == name {
			return d.Sources
		}
	}
	t.Fatalf("no %s in %s", name, policy)
	return nil
}

// TestFindsWhatStaticAnalysisCant covers each kind of resource that only exists
// once a page runs. Each page is also loaded under its own generated policy,
// which is the promise that matters: the policy works.
func TestFindsWhatStaticAnalysisCant(t *testing.T) {
	const font = `@font-face { font-family: F; src: url(http://fonts.test:%[1]s/f.woff2); } body { font-family: F; }`
	tests := []struct {
		name  string
		pages func(port string) site
		want  map[string][]string
	}{
		{
			name: "font from a stylesheet",
			pages: func(port string) site {
				return site{
					"site.test/":      html(`<link rel=stylesheet href=/s.css><body>text`),
					"site.test/s.css": content("text/css", fmt.Sprintf(font, port)),
				}
			},
			want: map[string][]string{"font-src": {"http://fonts.test:%s"}, "style-src": {"'self'"}},
		},
		{
			name: "request from a script",
			pages: func(port string) site {
				return site{
					"site.test/":     html(`<script src=/a.js></script>`),
					"site.test/a.js": content("text/javascript", fmt.Sprintf(`fetch("http://api.test:%s/data")`, port)),
				}
			},
			want: map[string][]string{"connect-src": {"http://api.test:%s"}},
		},
		{
			name: "image added by a script",
			pages: func(port string) site {
				return site{
					"site.test/":     html(`<script src=/a.js></script>`),
					"site.test/a.js": content("text/javascript", fmt.Sprintf(`new Image().src = "http://img.test:%s/i.png"`, port)),
				}
			},
			want: map[string][]string{"img-src": {"'self'", "http://img.test:%s"}},
		},
		{
			name: "script added by a script",
			pages: func(port string) site {
				return site{
					"site.test/":     html(`<script src=/a.js></script>`),
					"site.test/a.js": content("text/javascript", `document.head.appendChild(Object.assign(document.createElement("script"), {src: "/b.js", onload() { this.remove() }}))`),
					"site.test/b.js": content("text/javascript", `window.ranB = 1`),
				}
			},
			want: map[string][]string{"script-src": {"http://site.test:%[1]s/a.js", "http://site.test:%[1]s/b.js"}},
		},
		{
			name: "data image",
			pages: func(string) site {
				return site{"site.test/": html(`<script>new Image().src = "data:image/gif;base64,R0lGODlhAQABAAAAACw="</script>`)}
			},
			want: map[string][]string{"img-src": {"'self'", "data:"}},
		},
		{
			name: "web socket",
			pages: func(port string) site {
				return site{"site.test/": html(fmt.Sprintf(`<script>new WebSocket("ws://chat.test:%s/")</script>`, port))}
			},
			want: map[string][]string{"connect-src": {"ws://chat.test:%s"}},
		},
		{
			name: "frame",
			pages: func(port string) site {
				return site{
					"site.test/":  html(fmt.Sprintf(`<iframe src="http://frame.test:%s/"></iframe>`, port)),
					"frame.test/": html(`hello`),
				}
			},
			want: map[string][]string{"frame-src": {"http://frame.test:%s"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := site{}
			port := serve(t, s)
			for path, handler := range tt.pages(port) {
				s[path] = handler
			}
			c := collector()
			pageURL := "http://site.test:" + port + "/"

			policy := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{})
			for name, want := range tt.want {
				var expanded []string
				for _, source := range want {
					if strings.Contains(source, "%") {
						source = fmt.Sprintf(source, port)
					}
					expanded = append(expanded, source)
				}
				if got := sources(t, policy, name); !slices.Equal(got, expanded) {
					t.Errorf("%s = %v, want %v\n%s", name, got, expanded, policy)
				}
			}

			violations, err := c.Verify(t.Context(), policy.String(), pageURL)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range violations {
				t.Errorf("generated policy broke the page: %v\n%s", v, policy)
			}
		})
	}
}

func TestInlineCode(t *testing.T) {
	const script = `window.ran = 1;`
	const removing = `document.currentScript.remove();`
	const style = `body { color: red; }`
	port := serve(t, site{
		"site.test/": html(`<style>` + style + `</style><script>` + script + `</script><script>` + removing + `</script>
			<script type="application/json">{"not": "code"}</script>`),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{})

	if got, want := sources(t, policy, "style-src"), []string{hash(style)}; !slices.Equal(got, want) {
		t.Errorf("style-src = %v, want %v", got, want)
	}
	got, want := sources(t, policy, "script-src"), []string{hash(script), hash(removing)}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	if strings.Contains(policy.String(), "unsafe") {
		t.Errorf("policy has an unsafe keyword: %s", policy)
	}
	violations, err := c.Verify(t.Context(), policy.String(), pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v\n%s", violations, policy)
	}
}

func TestInertRemovedCodeIsNotAllowed(t *testing.T) {
	const inert = `not really code`
	port := serve(t, site{
		"site.test/": html(`<script type="text/plain" id=x>` + inert + `</script><script>window.ran = 1</script><script src=/a.js></script>`),
		"site.test/a.js": content("text/javascript", `document.getElementById("x").remove();
			document.head.appendChild(Object.assign(document.createElement("script"), {type: "text/plain", textContent: "more"})).remove()`),
	})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	policy := minimalcsp.Build(page, minimalcsp.Options{})
	if got := policy.String(); strings.Contains(got, hash(inert)) || strings.Contains(got, hash("more")) {
		t.Errorf("policy allows code that never ran: %s", got)
	}
}

func TestBlockers(t *testing.T) {
	tests := []struct {
		name, body string
		reason     string
		element    string // Empty if it may be gone when the browser reports it.
		value      string
	}{
		{"handler in the HTML", `<p onclick="go()">x</p>`, minimalcsp.ReasonEventHandler, "p", "go()"},
		{
			"handler added at runtime",
			`<div id=x></div><script>document.getElementById("x").setAttribute("onclick", "go()");
				document.getElementById("x").click()</script>`,
			minimalcsp.ReasonEventHandler, "div", "go()",
		},
		{
			"handler that ran and was removed",
			`<img id=x src=data:,x onerror="this.remove()">`,
			minimalcsp.ReasonEventHandler, "", "this.remove()",
		},
		{
			"style attribute added by HTML that scripts removed",
			`<div id=x style="color: red"></div><script>document.getElementById("x").remove()</script>`,
			minimalcsp.ReasonStyleAttribute, "", "color: red",
		},
		{"eval", `<script>try { eval("1+1") } catch {}</script>`, minimalcsp.ReasonEval, "", "1+1"},
		{
			"javascript: URL that ran",
			`<a id=x href="javascript:void(0)">x</a><script>document.getElementById("x").click()</script>`,
			minimalcsp.ReasonJavaScriptURL, "a", "javascript:void(0)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := serve(t, site{"site.test/": html(tt.body)})
			page := collect(t, collector(), "http://site.test:"+port+"/")
			var matching []minimalcsp.Blocker
			for _, b := range page.Blockers {
				if b.Reason == tt.reason {
					matching = append(matching, b)
				}
			}
			if len(matching) != 1 {
				t.Fatalf("got %+v, want one %q blocker", page.Blockers, tt.reason)
			}
			if b := matching[0]; (tt.element != "" && b.Element != tt.element) || !strings.HasPrefix(b.Value, tt.value) {
				t.Errorf("got %+v, want <%s> %q", b, tt.element, tt.value)
			}
		})
	}
}

func TestPageIsComplete(t *testing.T) {
	port := serve(t, site{
		"site.test/":     html(`<script src=/a.js></script>`),
		"site.test/a.js": content("text/javascript", ``),
	})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if page.Incomplete {
		t.Error("a browser sees what a page loads, so the page shouldn't be Incomplete")
	}
}

func TestPagesOwnPolicyDoesNotHideResources(t *testing.T) {
	for _, header := range []string{"Content-Security-Policy", "content-security-policy-report-only"} {
		t.Run(header, func(t *testing.T) {
			s := site{}
			port := serve(t, s)
			s["site.test/"] = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(header, "default-src 'none'; script-src 'nonce-x'")
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<script>new Image().src = "http://img.test:%s/i.png"</script>`, port)
			}
			policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{})
			want := []string{"'self'", "http://img.test:" + port}
			if got := sources(t, policy, "img-src"); !slices.Equal(got, want) {
				t.Errorf("img-src = %v, want %v\n%s", got, want, policy)
			}
		})
	}
}

func TestMetaPolicyIsReported(t *testing.T) {
	port := serve(t, site{
		"site.test/": html(`<meta http-equiv="Content-Security-Policy" content="img-src 'none'"><img src=/i.png>`),
	})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "<meta>") }) {
		t.Errorf("warnings = %v", page.Warnings)
	}
}

func TestCollectFollowsRedirects(t *testing.T) {
	s := site{}
	port := serve(t, s)
	s["old.test/"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://new.test:"+port+"/final", http.StatusFound)
	}
	s["new.test/final"] = html(`<img src=/i.png>`)
	page := collect(t, collector(), "http://old.test:"+port+"/")
	if got, want := page.URL.String(), "http://new.test:"+port+"/final"; got != want {
		t.Errorf("URL = %s, want %s", got, want)
	}
	policy := minimalcsp.Build(page, minimalcsp.Options{})
	if got := sources(t, policy, "img-src"); !slices.Equal(got, []string{"'self'"}) {
		t.Errorf("img-src = %v", got)
	}
}

func TestCollectDecodesCharset(t *testing.T) {
	// "é" in windows-1252. The browser hashes the decoded text.
	port := serve(t, site{
		"site.test/": content("text/html; charset=windows-1252", "<script>window.x = '\xe9';</script>"),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{})
	want := []string{hash("window.x = 'é';")}
	if got := sources(t, policy, "script-src"); !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	violations, err := c.Verify(t.Context(), policy.String(), pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}

func TestCollectFails(t *testing.T) {
	port := serve(t, site{})
	c := collector()
	c.Timeout = 10 * time.Second
	_, err := c.Collect(t.Context(), "http://site.test:"+port+"/missing")
	requireChrome(t, err)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want a 404", err)
	}
	if _, err := c.Collect(t.Context(), "http://127.0.0.1:1/"); err == nil {
		t.Error("expected an error for a refused connection")
	}
}

func TestStartFails(t *testing.T) {
	c := browser.Collector{Options: []chromedp.ExecAllocatorOption{chromedp.ExecPath("no-such-browser")}}
	for name, call := range map[string]func(ctx context.Context) error{
		"Collect": func(ctx context.Context) error { _, err := c.Collect(ctx, "http://x.test/"); return err },
		"Verify":  func(ctx context.Context) error { _, err := c.Verify(ctx, "", "http://x.test/"); return err },
		"Crawl":   func(ctx context.Context) error { _, err := c.Crawl(ctx, "http://x.test/", 1); return err },
	} {
		if err := call(t.Context()); err == nil || !strings.Contains(err.Error(), "starting Chrome") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSlowResourcesAreWaitedFor(t *testing.T) {
	s := site{}
	port := serve(t, s)
	s["site.test/"] = html(`<script src=/a.js></script>`)
	s["site.test/a.js"] = content("text/javascript", `fetch("/slow").then(() => setTimeout(() => { new Image().src = "/after.png" }, 50))`)
	s["site.test/slow"] = func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(600 * time.Millisecond)
	}
	c := collector()
	c.Settle = 500 * time.Millisecond
	policy := minimalcsp.Build(collect(t, c, "http://site.test:"+port+"/"), minimalcsp.Options{ExactPaths: true})
	if !strings.Contains(policy.String(), "/after.png") {
		t.Errorf("the image after a slow request is missing: %s", policy)
	}
}

func TestBusyPageGetsAWarning(t *testing.T) {
	port := serve(t, site{
		"site.test/":      html(`<script>setInterval(() => fetch("/poll"), 20)</script>`),
		"site.test/poll":  html(``),
		"site.test/other": html(``),
	})
	c := collector()
	c.MaxWait = 300 * time.Millisecond
	page := collect(t, c, "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "still making requests") }) {
		t.Errorf("warnings = %v", page.Warnings)
	}
}

func TestActions(t *testing.T) {
	port := serve(t, site{
		"site.test/": html(`<button id=b>Open</button><script>
			document.getElementById("b").addEventListener("click", () => { new Image().src = "/menu.png" })
		</script>`),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"

	before := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{ExactPaths: true})
	if strings.Contains(before.String(), "/menu.png") {
		t.Fatalf("the image shouldn't load without the click: %s", before)
	}

	c.Actions = []chromedp.Action[chromedp.Void]{chromedp.Click("#b")}
	after := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{ExactPaths: true})
	if !strings.Contains(after.String(), "/menu.png") {
		t.Errorf("the image after the click is missing: %s", after)
	}
}

func TestVerifyFindsWhatAPolicyBlocks(t *testing.T) {
	port := serve(t, site{
		"site.test/":     html(`<img src=/i.png><script src=/a.js></script>`),
		"site.test/a.js": content("text/javascript", `new Image().src = "/needs-the-script.png"`),
	})
	violations, err := collector().Verify(t.Context(), "default-src 'none'; img-src 'none'", "http://site.test:"+port+"/")
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	// Report-only means a blocked resource can't hide what depends on it.
	var blocked []string
	for _, v := range violations {
		blocked = append(blocked, v.Directive+" "+v.BlockedURI)
	}
	slices.Sort(blocked)
	want := []string{
		"img-src http://site.test:" + port + "/favicon.ico",
		"img-src http://site.test:" + port + "/i.png",
		"img-src http://site.test:" + port + "/needs-the-script.png",
		"script-src-elem http://site.test:" + port + "/a.js",
	}
	if !slices.Equal(blocked, want) {
		t.Errorf("got %v, want %v", blocked, want)
	}
}

func TestViolationString(t *testing.T) {
	tests := []struct {
		v    browser.Violation
		want string
	}{
		{browser.Violation{Directive: "img-src", BlockedURI: "https://x.test/i.png"}, "img-src blocked https://x.test/i.png"},
		{browser.Violation{Directive: "script-src", BlockedURI: "inline", Sample: "go()"}, `script-src blocked inline: "go()"`},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func crawlSite(port string) site {
	u := func(host, path string) string { return "http://" + host + ":" + port + path }
	return site{
		"site.test/": html(fmt.Sprintf(`<a href=/one#top>one</a> <a href=/one#bottom>one again</a>
			<a href=/two>two</a> <a href=/broken>broken</a> <a href=%s>elsewhere</a> <a href=mailto:a@b.test>mail</a>`, u("other.test", "/"))),
		"site.test/one":   html(`<img src=/one.png><a href=/>home</a><a href=/three>three</a>`),
		"site.test/two":   html(`<style>p { color: red }</style>`),
		"site.test/three": html(fmt.Sprintf(`<img src=%s>`, u("cdn.test", "/three.png"))),
		"other.test/":     html(`<img src=/other.png>`),
	}
}

func TestCrawl(t *testing.T) {
	s := site{}
	port := serve(t, s)
	for k, v := range crawlSite(port) {
		s[k] = v
	}
	pages, err := collector().Crawl(t.Context(), "http://site.test:"+port+"/", 10)
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range pages {
		paths = append(paths, p.URL.Host+p.URL.Path)
	}
	want := []string{"site.test:" + port + "/", "site.test:" + port + "/one", "site.test:" + port + "/two", "site.test:" + port + "/three"}
	if !slices.Equal(paths, want) {
		t.Errorf("crawled %v, want %v", paths, want)
	}
	if !slices.ContainsFunc(pages[0].Warnings, func(w string) bool { return strings.Contains(w, "/broken") }) {
		t.Errorf("warnings = %v, want one for the broken link", pages[0].Warnings)
	}

	policy := minimalcsp.Build(minimalcsp.Merge(pages...), minimalcsp.Options{})
	if got, want := sources(t, policy, "img-src"), []string{"'self'", "http://cdn.test:" + port}; !slices.Equal(got, want) {
		t.Errorf("img-src = %v, want %v", got, want)
	}
	if got := sources(t, policy, "style-src"); len(got) != 1 {
		t.Errorf("style-src = %v, want one hash", got)
	}
}

func TestCrawlStopsAtMaxPages(t *testing.T) {
	s := site{}
	port := serve(t, s)
	for k, v := range crawlSite(port) {
		s[k] = v
	}
	pages, err := collector().Crawl(t.Context(), "http://site.test:"+port+"/", 2)
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Errorf("got %d pages, want 2", len(pages))
	}
}

func TestCrawlFailsOnFirstPage(t *testing.T) {
	port := serve(t, site{})
	_, err := collector().Crawl(t.Context(), "http://site.test:"+port+"/", 2)
	requireChrome(t, err)
	if err == nil {
		t.Error("expected an error")
	}
}

func TestCancelledContext(t *testing.T) {
	port := serve(t, site{"site.test/": html(``)})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := collector().Collect(ctx, "http://site.test:"+port+"/"); err == nil {
		t.Error("expected an error")
	}
}

func TestLinksAreAbsolute(t *testing.T) {
	port := serve(t, site{"site.test/": html(`<a href="/x">x</a>`)})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	want, err := url.Parse("http://site.test:" + port + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Links) != 1 || *page.Links[0] != *want {
		t.Errorf("links = %v, want %v", page.Links, want)
	}
}

func TestVerifyReportsRepeatedRequestsOnce(t *testing.T) {
	port := serve(t, site{"site.test/": html(`<script>fetch("/data")</script>`)})
	violations, err := collector().Verify(t.Context(), "default-src 'none'", "http://site.test:"+port+"/")
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, v := range violations {
		if v.Directive == "connect-src" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d connect-src violations, want 1: %v", count, violations)
	}
}

// Without the feature turned off, Chrome blocks what these pages load. Missing
// that would look like a page that needs nothing.
func TestBlockedRequestsAreReported(t *testing.T) {
	port := serve(t, site{
		"site.test/":     html(`<script src=/a.js></script>`),
		"site.test/a.js": content("text/javascript", ``),
	})
	c := collector()
	c.Options = append(c.Options, chromedp.Flag("disable-features", "Translate"))
	page := collect(t, c, "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Warnings, func(w string) bool {
		return strings.Contains(w, "blocked") && strings.Contains(w, "/a.js")
	}) {
		t.Errorf("warnings = %v", page.Warnings)
	}
}

func TestVerifyChangesOnlySamples(t *testing.T) {
	port := serve(t, site{
		"site.test/":     html(`<script src=/a.js></script><script>window.y = 1</script>`),
		"site.test/a.js": content("text/javascript", ``),
	})
	tests := []struct {
		name, policy string
		want         []string
	}{
		{"script-src", "default-src 'self'; script-src 'self'", []string{"window.y = 1"}},
		{"default-src", "default-src 'self'", []string{"window.y = 1"}},
		{"already sampled", "default-src 'self' 'report-sample'", []string{"window.y = 1"}},
		{"no scripts covered", "img-src 'self'", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := collector().Verify(t.Context(), tt.policy, "http://site.test:"+port+"/")
			requireChrome(t, err)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range violations {
				got = append(got, v.Sample)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %+v, want samples %q", violations, tt.want)
			}
		})
	}
}

func TestRemovedStyleIsAllowed(t *testing.T) {
	const style = `p { color: red; }`
	port := serve(t, site{
		"site.test/": html(`<style id=s>` + style + `</style><script>document.getElementById("s").remove()</script>`),
	})
	policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{})
	if got, want := sources(t, policy, "style-src"), []string{hash(style)}; !slices.Equal(got, want) {
		t.Errorf("style-src = %v, want %v", got, want)
	}
}

// A script that rewrites itself ran with code that's no longer anywhere, so its
// hash can't be known.
func TestUncapturedCodeIsReported(t *testing.T) {
	port := serve(t, site{
		"site.test/": html(`<script id=s>document.getElementById("s").textContent = "changed"</script>`),
	})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "couldn't capture") }) {
		t.Errorf("warnings = %v", page.Warnings)
	}
}

func TestBaseAddedByScript(t *testing.T) {
	s := site{}
	port := serve(t, s)
	s["site.test/"] = html(fmt.Sprintf(`<script>
		document.head.appendChild(Object.assign(document.createElement("base"), {href: "http://base.test:%[1]s/"}));
	</script>`, port))
	policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{})
	if got, want := sources(t, policy, "base-uri"), []string{"http://base.test:" + port}; !slices.Equal(got, want) {
		t.Errorf("base-uri = %v, want %v\n%s", got, want, policy)
	}
}

func TestShadowRoots(t *testing.T) {
	const open, nested = `:host { color: red; }`, `p { color: blue; }`
	const attach = `const host = document.body.appendChild(document.createElement("div"));
		const root = host.attachShadow({mode: "open"});
		root.appendChild(document.createElement("style")).textContent = ` + "`" + open + "`" + `;
		const inner = root.appendChild(document.createElement("div")).attachShadow({mode: "open"});
		inner.appendChild(document.createElement("style")).textContent = ` + "`" + nested + "`" + `;`
	port := serve(t, site{"site.test/": html(`<body><script>` + attach + `</script>`)})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{})
	got, want := sources(t, policy, "style-src"), []string{hash(open), hash(nested)}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("style-src = %v, want %v", got, want)
	}
	violations, err := c.Verify(t.Context(), policy.String(), pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}

func TestClosedShadowRootIsReported(t *testing.T) {
	port := serve(t, site{"site.test/": html(`<body><script>
		document.body.appendChild(document.createElement("div")).attachShadow({mode: "closed"})
			.appendChild(document.createElement("style")).textContent = "p { color: red; }";
	</script>`)})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "couldn't capture") }) {
		t.Errorf("warnings = %v", page.Warnings)
	}
}

func TestEmptyInlineCodeIsNotABlocker(t *testing.T) {
	port := serve(t, site{"site.test/": html(`<div id=x></div>
		<script>document.getElementById("x").setAttribute("style", "")</script>`)})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if len(page.Blockers) != 0 || len(page.Warnings) != 0 {
		t.Errorf("blockers = %v, warnings = %v", page.Blockers, page.Warnings)
	}
}

// Chrome hands over a decoded body, which has to survive being sent back with
// the headers that say it's compressed.
func TestCompressedPage(t *testing.T) {
	const script = `new Image().src = "/compressed.png";`
	port := serve(t, site{"site.test/": func(w http.ResponseWriter, _ *http.Request) {
		var compressed bytes.Buffer
		zipped := gzip.NewWriter(&compressed)
		fmt.Fprint(zipped, `<!doctype html><script>`+script+`</script>`+strings.Repeat("<p>padding", 100))
		zipped.Close()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(compressed.Len()))
		w.Write(compressed.Bytes())
	}})
	policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{ExactPaths: true})
	if !strings.Contains(policy.String(), hash(script)) || !strings.Contains(policy.String(), "/compressed.png") {
		t.Errorf("policy = %s", policy)
	}
}

// Frames aren't part of the page's policy, so their responses must stay as sent.
func TestFramesKeepTheirOwnPolicy(t *testing.T) {
	s := site{}
	port := serve(t, s)
	s["site.test/"] = html(fmt.Sprintf(`<iframe src="http://frame.test:%s/"></iframe>
		<script>addEventListener("message", () => { new Image().src = "/frame-script-ran.png" })</script>`, port))
	s["frame.test/"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'none'")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script>parent.postMessage("ran", "*")</script>`)
	}
	policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{ExactPaths: true})
	if strings.Contains(policy.String(), "/frame-script-ran.png") {
		t.Errorf("the frame lost its policy: %s", policy)
	}
}

func TestRemovedCodeWithSurroundingSpace(t *testing.T) {
	const script = "\n\t\tdocument.currentScript.remove();\n\t"
	port := serve(t, site{"site.test/": html(`<script>` + script + `</script>`)})
	policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{})
	if got, want := sources(t, policy, "script-src"), []string{hash(script)}; !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
}

func TestJavaScriptURLThatRemovedItself(t *testing.T) {
	port := serve(t, site{"site.test/": html(`<body><script>
		const a = document.body.appendChild(Object.assign(document.createElement("a"), {href: "javascript:void(1)"}));
		a.click();
		a.remove();
	</script>`)})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Blockers, func(b minimalcsp.Blocker) bool {
		return b.Reason == minimalcsp.ReasonJavaScriptURL && strings.HasPrefix(b.Value, "javascript:void(1)")
	}) {
		t.Errorf("blockers = %v, warnings = %v", page.Blockers, page.Warnings)
	}
}

func TestPagesCantSeeTheRecorder(t *testing.T) {
	port := serve(t, site{"site.test/": html(fmt.Sprintf(`<script>
		if (window.%s) new Image().src = "/visible.png";
	</script>`, "__minimalcspReport"))})
	policy := minimalcsp.Build(collect(t, collector(), "http://site.test:"+port+"/"), minimalcsp.Options{ExactPaths: true})
	if strings.Contains(policy.String(), "/visible.png") {
		t.Errorf("policy = %s", policy)
	}
}

// Violations of a page's own report-only policy aren't violations of the policy
// being verified.
func TestVerifyIgnoresThePagesOwnReportOnlyPolicy(t *testing.T) {
	s := site{}
	port := serve(t, s)
	s["site.test/"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "img-src 'none'")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><link rel=icon href=/i.png><img src=/i.png>`)
	}
	violations, err := collector().Verify(t.Context(), "img-src 'self'", "http://site.test:"+port+"/")
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}
