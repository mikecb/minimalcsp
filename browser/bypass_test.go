package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/mikecb/minimalcsp"
)

// TestBypassWarningsAgreeWithChrome injects a script tag for a known bypass
// into pages with each policy, and checks that a policy gets a warning exactly
// when Chrome would have loaded the script. Nothing leaves the machine, since
// the test's Chrome resolves every host to a local address.
func TestBypassWarningsAgreeWithChrome(t *testing.T) {
	const target = "https://www.google.com/complete/search?jsonp=a"
	policies := []string{
		"script-src https://www.google.com",
		"script-src HTTPS://WWW.GOOGLE.COM",
		"script-src www.google.com",
		"script-src http://www.google.com",
		"script-src wss://www.google.com",
		"script-src https://www.google.com:443",
		"script-src https://www.google.com:8443",
		"script-src https://www.google.com:*",
		"script-src https://www.google.com/",
		"script-src https://www.google.com/complete/",
		"script-src https://www.google.com/complete",
		"script-src https://www.google.com/complete/search",
		"script-src https://www.google.com/complete/search/",
		"script-src https://www.google.com/Complete/search",
		"script-src https://www.google.com/recaptcha/",
		"script-src https://*.google.com",
		"script-src *.google.com",
		"script-src https://google.com",
		"script-src https://ww.google.com",
		"script-src https://www.google.com.example",
		"script-src https://*",
		"script-src *",
		"script-src https:",
		"script-src HTTPS:",
		"script-src http:",
		"script-src data:",
		"script-src 'self'",
		"script-src 'none'",
		"script-src 'unsafe-inline'",
		"default-src https://www.google.com",
		"default-src https://www.google.com; script-src 'self'",
		"script-src https://www.google.com; script-src-elem 'self'",
		"script-src 'self'; script-src-elem https://www.google.com",
		"script-src 'strict-dynamic' https://www.google.com",
		"script-src 'nonce-abc' https://www.google.com",
		"script-src 'nonce-abc' 'strict-dynamic' https://www.google.com",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := r.URL.Query().Get("policy")
		if policy == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", policy)
		fmt.Fprintf(w, `<!doctype html><script src=%q></script>`, target)
	}))
	defer server.Close()

	opts := append(slices.Clone(chromedp.DefaultExecAllocatorOptions[:]), collector().Options...)
	allocator, stop := chromedp.NewExecAllocator(context.Background(), opts...)
	defer stop()
	ctx, cancel := chromedp.NewContext(allocator)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelTimeout()
	if err := chromedp.Do(ctx, chromedp.Navigate("about:blank")); err != nil {
		requireChrome(t, err)
		t.Fatal(err)
	}
	// This has to come from outside the page, since the policies would block it.
	_, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{
		Source: `addEventListener("securitypolicyviolation", () => { window.blocked = true });`,
	})
	if err != nil {
		t.Fatal(err)
	}

	sawAllowed, sawBlocked := false, false
	for _, policy := range policies {
		pageURL := server.URL + "/?policy=" + url.QueryEscape(policy)
		if err := chromedp.Do(ctx, chromedp.Navigate(pageURL)); err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		blocked, err := chromedp.Run(ctx, chromedp.Evaluate[bool](`window.blocked === true`))
		if err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		sawAllowed, sawBlocked = sawAllowed || !blocked, sawBlocked || blocked
		warnings := minimalcsp.ParsePolicy(policy).Warnings
		if len(warnings) == 0 && !blocked {
			t.Errorf("%s: Chrome allowed the script, but there's no warning", policy)
		}
		if len(warnings) != 0 && blocked {
			t.Errorf("%s: Chrome blocked the script, but got %q", policy, warnings)
		}
	}
	if !sawAllowed || !sawBlocked {
		t.Errorf("allowed = %v, blocked = %v, so the test isn't telling them apart", sawAllowed, sawBlocked)
	}
}
