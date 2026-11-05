package browser_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/mikecb/minimalcsp"
	"github.com/mikecb/minimalcsp/browser"
)

func integrity(code string) string { return strings.Trim(hash(code), "'") }

func strictPolicy(t *testing.T, c browser.Collector, pageURL string, trust minimalcsp.ScriptTrust) *minimalcsp.Policy {
	t.Helper()
	return minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{Scripts: trust})
}

func verifyPolicy(t *testing.T, c browser.Collector, policy *minimalcsp.Policy, pageURL string) []browser.Violation {
	t.Helper()
	violations, err := c.VerifyPolicy(t.Context(), policy, pageURL)
	requireChrome(t, err)
	if err != nil {
		t.Fatal(err)
	}
	return violations
}

func TestHashesScriptsInThePage(t *testing.T) {
	const script = `window.ran = 1;`
	port := serve(t, site{
		"site.test/":     html(`<script src=/a.js></script>`),
		"site.test/a.js": content("text/javascript", script),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	if got, want := sources(t, policy, "script-src"), []string{hash(script)}; !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	if len(policy.Integrity) != 1 || policy.Integrity[0].Value != integrity(script) || policy.Integrity[0].CrossOrigin {
		t.Errorf("integrity = %v", policy.Integrity)
	}
	if violations := verifyPolicy(t, c, policy, pageURL); len(violations) != 0 {
		t.Errorf("violations = %v\n%s", violations, policy)
	}
}

// The policy has to match the bytes the server sends, not decoded text.
func TestHashesScriptBytes(t *testing.T) {
	const latin1 = "window.x = '\xe9';"
	const plain = `window.y = "compressed";`
	port := serve(t, site{
		"site.test/":     html(`<script src=/a.js></script><script src=/z.js></script>`),
		"site.test/a.js": content("text/javascript; charset=windows-1252", latin1),
		"site.test/z.js": func(w http.ResponseWriter, _ *http.Request) {
			var compressed bytes.Buffer
			zipped := gzip.NewWriter(&compressed)
			fmt.Fprint(zipped, plain)
			zipped.Close()
			w.Header().Set("Content-Type", "text/javascript")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(compressed.Len()))
			w.Write(compressed.Bytes())
		},
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	got := sources(t, policy, "script-src")
	want := []string{hash(latin1), hash(plain)}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	if violations := verifyPolicy(t, c, policy, pageURL); len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}

func TestLoadedScriptsRelyOnStrictDynamic(t *testing.T) {
	const parent = `const s = document.createElement("script"); s.src = "/child.js"; document.head.appendChild(s);
		const i = document.createElement("script"); i.textContent = "window.inlineChild = 1"; document.head.appendChild(i);`
	port := serve(t, site{
		"site.test/":          html(`<script src=/parent.js></script>`),
		"site.test/parent.js": content("text/javascript", parent),
		"site.test/child.js":  content("text/javascript", `window.child = 1`),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	want := []string{hash(parent), "'strict-dynamic'"}
	slices.Sort(want)
	if got := sources(t, policy, "script-src"); !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	if violations := verifyPolicy(t, c, policy, pageURL); len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}

func TestServedCodeIsHashedEvenIfItChanged(t *testing.T) {
	const script = `document.getElementById("s").textContent = "changed"`
	port := serve(t, site{"site.test/": html(`<script id=s>` + script + `</script>`)})
	policy := strictPolicy(t, collector(), "http://site.test:"+port+"/", minimalcsp.ByHash)
	if got := sources(t, policy, "script-src"); !slices.Contains(got, hash(script)) {
		t.Errorf("script-src = %v", got)
	}
}

// A page can use a stronger hash than the one minimalcsp computes. The policy has
// to list what the attribute says.
func TestExistingIntegrityIsUsed(t *testing.T) {
	const script = `window.ran = 1;`
	sum := sha512.Sum384([]byte(script))
	existing := "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
	port := serve(t, site{
		"site.test/":     html(fmt.Sprintf(`<script src=/a.js integrity=%q></script>`, existing)),
		"site.test/a.js": content("text/javascript", script),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	if got, want := sources(t, policy, "script-src"), []string{"'" + existing + "'"}; !slices.Equal(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	if violations := verifyPolicy(t, c, policy, pageURL); len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}

func TestBrokenIntegrityIsReported(t *testing.T) {
	port := serve(t, site{
		"site.test/":     html(fmt.Sprintf(`<script src=/a.js integrity=%q></script>`, integrity("something else"))),
		"site.test/a.js": content("text/javascript", `window.ran = 1`),
	})
	page := collect(t, collector(), "http://site.test:"+port+"/")
	if !slices.ContainsFunc(page.Warnings, func(w string) bool { return strings.Contains(w, "failed its integrity check") }) {
		t.Errorf("warnings = %v", page.Warnings)
	}
}

func TestCrossOriginScripts(t *testing.T) {
	const script = `window.ran = 1;`
	cors := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		content("text/javascript", script)(w, r)
	}
	s := site{"cors.test/a.js": cors, "nocors.test/a.js": content("text/javascript", script)}
	port := serve(t, s)
	c := collector()
	pageURL := "http://site.test:" + port + "/"

	t.Run("with CORS", func(t *testing.T) {
		s["site.test/"] = html(fmt.Sprintf(`<script src="http://cors.test:%s/a.js"></script>`, port))
		policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
		if len(policy.Integrity) != 1 || !policy.Integrity[0].CrossOrigin {
			t.Errorf("integrity = %v", policy.Integrity)
		}
		if violations := verifyPolicy(t, c, policy, pageURL); len(violations) != 0 {
			t.Errorf("violations = %v", violations)
		}
	})
	// Chrome refuses the script without a policy being involved, so this would
	// otherwise look like a page with nothing wrong.
	t.Run("without CORS", func(t *testing.T) {
		s["site.test/"] = html(fmt.Sprintf(`<script src="http://nocors.test:%s/a.js"></script>`, port))
		policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
		violations := verifyPolicy(t, c, policy, pageURL)
		if !slices.ContainsFunc(violations, func(v browser.Violation) bool {
			return v.Directive == "integrity" && strings.Contains(v.BlockedURI, "nocors.test")
		}) {
			t.Errorf("violations = %v", violations)
		}
	})
}

func TestImports(t *testing.T) {
	modules := func(page string) site {
		return site{
			"site.test/":        html(page),
			"site.test/main.js": content("text/javascript", `import "/dep.js";`),
			"site.test/dyn.js":  content("text/javascript", `import("/dep.js");`),
			"site.test/dep.js":  content("text/javascript", `window.dep = 1;`),
		}
	}
	const static, dynamic = `<script type=module src=/main.js></script>`, `<script src=/dyn.js></script>`
	tests := []struct {
		name, page string
		trust      minimalcsp.ScriptTrust
		blocked    bool
	}{
		{"static import by hash", static, minimalcsp.ByHash, true},
		{"dynamic import by hash", dynamic, minimalcsp.ByHash, true},
		{"static import by nonce", static, minimalcsp.ByNonce, false},
		{"dynamic import by nonce", dynamic, minimalcsp.ByNonce, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := serve(t, modules(tt.page))
			c := collector()
			pageURL := "http://site.test:" + port + "/"
			policy := strictPolicy(t, c, pageURL, tt.trust)
			violations := verifyPolicy(t, c, policy, pageURL)
			if blocked := len(violations) > 0; blocked != tt.blocked {
				t.Errorf("violations = %v, want blocked = %v\n%s", violations, tt.blocked, policy)
			}
		})
	}
}

func TestVerifyTriesNoncesOnAPageWithout(t *testing.T) {
	port := serve(t, site{
		"site.test/":     html(`<script>window.x = 1</script><script src=/a.js></script>`),
		"site.test/a.js": content("text/javascript", `window.y = 1`),
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByNonce)
	if len(policy.Integrity) != 0 {
		t.Errorf("integrity = %v", policy.Integrity)
	}
	if violations := verifyPolicy(t, c, policy, pageURL); len(violations) != 0 {
		t.Errorf("violations = %v\n%s", violations, policy)
	}
}

// noncePage serves pageTemplate through NonceMiddleware, as a real server would.
func noncePage(policy *minimalcsp.Policy, pageTemplate string, reportOnly bool) http.HandlerFunc {
	parsed := template.Must(template.New("page").Parse(`<!doctype html><link rel=icon href=/favicon.ico>` + pageTemplate))
	middleware := minimalcsp.NonceMiddleware{Policy: policy, ReportOnly: reportOnly}
	return middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		parsed.Execute(w, struct{ Nonce string }{minimalcsp.Nonce(r.Context())})
	})).ServeHTTP
}

func TestVerifyUsesThePagesOwnNonce(t *testing.T) {
	policy := &minimalcsp.Policy{Directives: []minimalcsp.Directive{
		{Name: "default-src", Sources: []string{"'self'"}},
		{Name: "script-src", Sources: []string{"'nonce-" + minimalcsp.NoncePlaceholder + "'", "'strict-dynamic'"}},
	}}
	tests := []struct {
		name, page string
		reportOnly bool
		want       int
	}{
		{"every script has it", `<script nonce="{{.Nonce}}">window.x = 1</script>`, false, 0},
		{"report-only", `<script nonce="{{.Nonce}}">window.x = 1</script>`, true, 0},
		{"one is missing it", `<script nonce="{{.Nonce}}">window.x = 1</script><script>window.y = 1</script>`, false, 1},
		{"one has a stale nonce", `<script nonce="old">window.y = 1</script>`, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := serve(t, site{"site.test/": noncePage(policy, tt.page, tt.reportOnly)})
			violations := verifyPolicy(t, collector(), policy, "http://site.test:"+port+"/")
			if len(violations) != tt.want {
				t.Errorf("violations = %v, want %d", violations, tt.want)
			}
		})
	}
}

// running tracks which scripts ran on a page under a real, enforced policy.
type running struct {
	mu   sync.Mutex
	seen []string
}

func (r *running) handler(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, req.URL.Query().Get("name"))
}

func (r *running) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Sorted(slices.Values(r.seen))
}

func marker(name string) string { return fmt.Sprintf(`new Image().src = "/ran?name=%s";`, name) }

// open loads pageURL in plain Chrome, with nothing replacing its policy.
func open(t *testing.T, pageURL string) {
	t.Helper()
	opts := append(slices.Clone(chromedp.DefaultExecAllocatorOptions[:]), collector().Options...)
	allocator, stop := chromedp.NewExecAllocator(context.Background(), opts...)
	defer stop()
	ctx, cancel := chromedp.NewContext(allocator)
	defer cancel()
	timed, cancelTimeout := context.WithTimeout(ctx, 20*time.Second)
	defer cancelTimeout()
	err := chromedp.Do(timed, chromedp.Navigate(pageURL), chromedp.Sleep(500*time.Millisecond))
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		requireChrome(t, fmt.Errorf("starting Chrome: %w", err))
	}
	if err != nil {
		t.Fatal(err)
	}
}

// These run the generated policy for real, in a browser enforcing it, with an
// attacker's script in the page. Nothing else shows that it stops one.
func TestEnforcedHashPolicy(t *testing.T) {
	root := marker("root") + `const s = document.createElement("script"); s.src = "/child.js"; document.head.appendChild(s);`
	const page = `<script src=/root.js></script>`
	r := &running{}
	s := site{
		"site.test/root.js":     content("text/javascript", root),
		"site.test/child.js":    content("text/javascript", marker("child")),
		"site.test/evil.js":     content("text/javascript", marker("evil-external")),
		"site.test/ran":         r.handler,
		"site.test/":            html(page),
		"site.test/favicon.ico": http.NotFound,
	}
	port := serve(t, s)
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, collector(), pageURL, minimalcsp.ByHash)
	r.seen = nil // Collecting ran the scripts too.

	parsed, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	const injected = `<script>` + `new Image().src = "/ran?name=evil-inline";` + `</script><script src=/evil.js></script>`
	enforced := policy.Apply([]byte(`<!doctype html><link rel=icon href=data:,>`+page+injected), parsed)
	s["site.test/"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src "+strings.Join(sources(t, policy, "script-src"), " "))
		w.Header().Set("Content-Type", "text/html")
		w.Write(enforced)
	}
	open(t, pageURL)
	if got, want := r.names(), []string{"child", "root"}; !slices.Equal(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
}

func TestEnforcedNoncePolicy(t *testing.T) {
	r := &running{}
	s := site{
		"site.test/mod.js": content("text/javascript", `import "/dep.js"; `+marker("mod")),
		"site.test/dep.js": content("text/javascript", marker("dep")),
		"site.test/ran":    r.handler,
	}
	policy := &minimalcsp.Policy{Directives: []minimalcsp.Directive{
		{Name: "script-src", Sources: []string{"'nonce-" + minimalcsp.NoncePlaceholder + "'", "'strict-dynamic'"}},
	}}
	s["site.test/"] = noncePage(policy, `<script nonce="{{.Nonce}}" type=module src=/mod.js></script>
		<script>new Image().src = "/ran?name=evil-inline";</script>`, false)
	port := serve(t, s)
	open(t, "http://site.test:"+port+"/")
	if got, want := r.names(), []string{"dep", "mod"}; !slices.Equal(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
}

func TestVerifyMeta(t *testing.T) {
	const script = `window.ran = 1;`
	const inline = `window.inline = 1;`
	port := serve(t, site{
		"site.test/":      html(`<script src=/a.js></script><script>` + inline + `</script><img src=/i.png>`),
		"site.test/a.js":  content("text/javascript", script),
		"site.test/i.png": http.NotFound,
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	violations, err := c.VerifyMeta(t.Context(), policy, pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v\n%s", violations, policy)
	}
}

// The policy really has to be in force: a report would still load the image.
func TestVerifyMetaEnforces(t *testing.T) {
	var loaded atomic.Bool
	port := serve(t, site{
		"site.test/": html(`<img src=/i.png>`),
		"site.test/i.png": func(w http.ResponseWriter, _ *http.Request) {
			loaded.Store(true)
			http.NotFound(w, nil)
		},
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	policy.Directives = slices.DeleteFunc(policy.Directives, func(d minimalcsp.Directive) bool { return d.Name == "img-src" })
	loaded.Store(false)
	violations, err := c.VerifyMeta(t.Context(), policy, pageURL)
	if err != nil {
		t.Fatal(err)
	}
	blocked := slices.DeleteFunc(violations, func(v browser.Violation) bool {
		return v.Directive != "img-src" || !strings.HasSuffix(v.BlockedURI, "/i.png") || v.Page != pageURL
	})
	if len(blocked) != 1 {
		t.Errorf("blocked = %v, want the image once", blocked)
	}
	if loaded.Load() {
		t.Error("the image loaded, so the policy wasn't enforced")
	}
}

// A page's own policy mustn't be counted against the one being tried.
func TestVerifyMetaReplacesThePagesPolicies(t *testing.T) {
	const page = `<meta http-equiv=Content-Security-Policy content="script-src 'none'"><script>window.a = 1;</script>`
	port := serve(t, site{
		"site.test/": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Security-Policy", "script-src 'none'")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><link rel=icon href=/favicon.ico>`+page)
		},
	})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := minimalcsp.Build(collect(t, c, pageURL), minimalcsp.Options{})
	violations, err := c.VerifyMeta(t.Context(), policy, pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v\n%s", violations, policy)
	}
}

// Violations need samples, or the CLI can't tell which blockers they are.
func TestVerifyMetaHasSamples(t *testing.T) {
	port := serve(t, site{"site.test/": html(`<p onclick="go()">x</p><script>eval("1")</script>`)})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	violations, err := c.VerifyMeta(t.Context(), policy, pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(violations, func(v browser.Violation) bool { return v.Sample != "" }) {
		t.Errorf("violations = %v", violations)
	}
}

func TestVerifyMetaWithCharset(t *testing.T) {
	// In windows-1251 this byte is a letter, so the hash only matches if the
	// browser still reads the charset once the tag is in the page.
	const page = "<!doctype html><head><meta charset=windows-1251><title>t</title><script>window.text = '\xe9';</script>"
	var scripts strings.Builder
	for i := range 40 {
		fmt.Fprintf(&scripts, "<script>window.n%d = %d;</script>", i, i)
	}
	port := serve(t, site{"site.test/": content("text/html", page+scripts.String())})
	c := collector()
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, c, pageURL, minimalcsp.ByHash)
	if !slices.Contains(sources(t, policy, "script-src"), hash("window.text = 'й';")) {
		t.Fatalf("script-src = %v", sources(t, policy, "script-src"))
	}
	violations, err := c.VerifyMeta(t.Context(), policy, pageURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("violations = %v", violations)
	}
}

func TestEnforcedMetaPolicy(t *testing.T) {
	root := marker("root") + `const s = document.createElement("script"); s.src = "/child.js"; document.head.appendChild(s);`
	const page = `<script src=/root.js></script>`
	r := &running{}
	s := site{
		"site.test/root.js":     content("text/javascript", root),
		"site.test/child.js":    content("text/javascript", marker("child")),
		"site.test/evil.js":     content("text/javascript", marker("evil-external")),
		"site.test/ran":         r.handler,
		"site.test/":            html(page),
		"site.test/favicon.ico": http.NotFound,
	}
	port := serve(t, s)
	pageURL := "http://site.test:" + port + "/"
	policy := strictPolicy(t, collector(), pageURL, minimalcsp.ByHash)
	policy.Directives = append(policy.Directives, minimalcsp.Directive{Name: "img-src", Sources: []string{"'self'", "data:"}})
	r.seen = nil // Collecting ran the scripts too.

	parsed, err := url.Parse(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	const injected = `<script>` + `new Image().src = "/ran?name=evil-inline";` + `</script><script src=/evil.js></script>`
	s["site.test/"] = content("text/html; charset=utf-8", string(policy.ApplyMeta([]byte(`<!doctype html><link rel=icon href=data:,>`+page+injected), parsed)))
	open(t, pageURL)
	if got, want := r.names(), []string{"child", "root"}; !slices.Equal(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
}
