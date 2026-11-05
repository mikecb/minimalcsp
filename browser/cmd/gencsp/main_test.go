package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mikecb/minimalcsp"
	"github.com/mikecb/minimalcsp/browser"
)

const prefix = "<!doctype html><link rel=icon href=/favicon.ico>"

// gencsp runs the command against a page on a loopback address, which works
// without any special browser flags.
func gencsp(t *testing.T, handler http.HandlerFunc, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if os.Getenv("CI") != "" {
		args = append([]string{"-no-sandbox"}, args...)
	}
	var out, errOut bytes.Buffer
	code = run(t.Context(), append(args, server.URL), &out, &errOut)
	if strings.Contains(errOut.String(), "starting Chrome") && os.Getenv("CI") == "" {
		t.Skip(errOut.String())
	}
	return code, out.String(), errOut.String()
}

func page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, prefix+body)
		case "/other":
			fmt.Fprint(w, prefix+"<img src=/other.png>")
		default:
			http.NotFound(w, r)
		}
	}
}

func TestRun(t *testing.T) {
	code, stdout, stderr := gencsp(t, page(`<script>new Image().src = "/i.png"</script>`))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "default-src 'none';") || !strings.Contains(stdout, "img-src 'self'") {
		t.Errorf("stdout = %q", stdout)
	}
	if strings.Contains(stderr, "violation:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestExactPaths(t *testing.T) {
	_, stdout, stderr := gencsp(t, page(`<img src=/i.png>`), "-exact-paths")
	if !strings.Contains(stdout, "/i.png") {
		t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
	}
}

func TestPages(t *testing.T) {
	_, stdout, stderr := gencsp(t, page(`<a href=/other>other</a>`), "-pages", "2", "-exact-paths")
	if !strings.Contains(stdout, "/other.png") {
		t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
	}
}

func TestVerifyCoversEveryPage(t *testing.T) {
	var count int
	code, _, stderr := gencsp(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, prefix+`<a href=/changing>changing</a>`)
		case "/changing":
			count++
			fmt.Fprintf(w, "%s<style>p { order: %d }</style>", prefix, count)
		}
	}, "-pages", "2")
	if code != 1 || !strings.Contains(stderr, "/changing: style-src") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
}

func TestWarningsAndBlockers(t *testing.T) {
	code, _, stderr := gencsp(t, page(`<script src=/missing.js></script><p onclick="go()">x</p>`), "-scripts", "url")
	if code != 0 {
		t.Errorf("exit %d: code the policy says it blocks isn't a failure", code)
	}
	for _, want := range []string{"warning: script-src allows", "blocked: inline event handler"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want %q", stderr, want)
		}
	}
	if strings.Contains(stderr, "violation:") {
		t.Errorf("stderr = %q", stderr)
	}
}

// A page that changes on every load can't be covered by one policy, which is
// what verifying exists to catch.
func TestVerifyFailure(t *testing.T) {
	var count int
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			return
		}
		count++
		fmt.Fprintf(w, "%s<style>p { order: %d }</style>", prefix, count)
	}
	code, _, stderr := gencsp(t, handler)
	if code != 1 || !strings.Contains(stderr, "violation: ") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}

	code, _, stderr = gencsp(t, handler, "-no-verify")
	if code != 0 || strings.Contains(stderr, "violation:") {
		t.Errorf("-no-verify: exit %d, stderr = %q", code, stderr)
	}
}

func TestUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{{}, {"a", "b"}, {"-unknown", "x"}, {"-scripts", "other", "x"}} {
		if code := run(context.Background(), args, &out, &errOut); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
	if !strings.Contains(errOut.String(), "usage: gencsp") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestLoadFailure(t *testing.T) {
	code, _, stderr := gencsp(t, http.NotFound)
	if code != 1 || !strings.Contains(stderr, "404") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
}

func TestVerifyLoadFailure(t *testing.T) {
	var count int
	code, _, stderr := gencsp(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			return
		}
		if count++; count > 1 {
			http.Error(w, "gone", http.StatusInternalServerError)
		}
	})
	if code != 1 || !strings.Contains(stderr, "verifying") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
}

func TestExplained(t *testing.T) {
	policy := &minimalcsp.Policy{Blockers: []minimalcsp.Blocker{{Value: "go(); and much more"}}}
	tests := []struct {
		v    browser.Violation
		want bool
	}{
		{browser.Violation{Sample: "go();"}, true},
		{browser.Violation{Sample: "other()"}, false},
		{browser.Violation{BlockedURI: "http://x.test/"}, false},
	}
	for _, tt := range tests {
		if got := explained(tt.v, policy); got != tt.want {
			t.Errorf("explained(%+v) = %v", tt.v, got)
		}
	}
}

// scriptPage serves a page with one external script.
func scriptPage(script string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, prefix+`<script src=/a.js></script>`)
		case "/a.js", "/b.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, script)
		}
	}
}

func TestHashByDefault(t *testing.T) {
	code, stdout, stderr := gencsp(t, scriptPage(`window.ran = 1`))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "script-src 'sha256-") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "change: ") || !strings.Contains(stderr, `/a.js needs integrity="sha256-`) {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestScriptsNonce(t *testing.T) {
	code, stdout, stderr := gencsp(t, scriptPage(`window.ran = 1`), "-scripts", "nonce")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "script-src 'nonce-{nonce}'") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "change: every script element") || strings.Contains(stderr, "integrity") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestHintsAtNonces(t *testing.T) {
	code, _, stderr := gencsp(t, scriptPage(`if (!window.again) { window.again = 1; import("/b.js") }`))
	if code != 1 || !strings.Contains(stderr, "hint: ") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
	if code, _, stderr := gencsp(t, scriptPage(`if (!window.again) { window.again = 1; import("/b.js") }`), "-scripts", "nonce"); code != 0 {
		t.Errorf("nonce: exit %d, stderr = %q", code, stderr)
	}
}

func TestMeta(t *testing.T) {
	code, stdout, stderr := gencsp(t, scriptPage(`window.a = 1`), "-meta")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, `<meta http-equiv="Content-Security-Policy" content="default-src 'none';`) || !strings.HasSuffix(stdout, "\">\n") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "change: the tag goes") || !strings.Contains(stderr, "warning: a <meta> policy") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestMetaIsVerified(t *testing.T) {
	code, _, stderr := gencsp(t, func() http.HandlerFunc {
		var calls atomic.Int32
		return func(w http.ResponseWriter, r *http.Request) {
			// A script that only appears on the second load isn't in the policy.
			if r.URL.Path == "/" && calls.Add(1) > 1 {
				fmt.Fprint(w, prefix+`<script>window.late = 1</script>`)
				return
			}
			page(``)(w, r)
		}
	}(), "-meta")
	if code != 1 || !strings.Contains(stderr, "violation: ") || !strings.Contains(stderr, "window.late") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
}

func TestMetaWithNonce(t *testing.T) {
	code, _, stderr := gencsp(t, page(``), "-meta", "-scripts", "nonce")
	if code != 2 || !strings.Contains(stderr, "can't be used") {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
}

// A stale tag stays in force under a header, but -meta replaces it.
func TestMetaReplacesTagsInThePage(t *testing.T) {
	const body = `<meta http-equiv=Content-Security-Policy content="img-src 'none'"><img src=/i.png>`
	if code, _, stderr := gencsp(t, page(body), "-meta"); code != 0 {
		t.Errorf("exit %d, stderr = %q", code, stderr)
	}
	if code, _, stderr := gencsp(t, page(body)); code != 1 {
		t.Errorf("without -meta: exit %d, stderr = %q", code, stderr)
	}
}
