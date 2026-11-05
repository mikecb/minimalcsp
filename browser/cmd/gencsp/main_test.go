package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	code, _, stderr := gencsp(t, page(`<script src=/missing.js></script><p onclick="go()">x</p>`))
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
	for _, args := range [][]string{{}, {"a", "b"}, {"-unknown", "x"}} {
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
