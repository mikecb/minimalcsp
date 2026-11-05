package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// sending returns a page that sends header, with an image on it.
func sending(name, value string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if value != "" {
			w.Header().Set(name, value)
		}
		page(`<img src=/a.png>`)(w, r)
	}
}

func TestVerifyPolicyFromTheCommandLine(t *testing.T) {
	code, stdout, stderr := gencsp(t, page(`<img src=/a.png>`), "verify", "-policy", "default-src 'self'")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if want := "checked 1 page: 0 violations\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}

	code, stdout, stderr = gencsp(t, page(`<img src=/a.png>`), "verify", "-policy", "default-src 'none'; img-src https://other.example")
	if code != 1 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "violation: ") || !strings.Contains(stderr, "/a.png") {
		t.Errorf("stderr = %q", stderr)
	}
	if !strings.HasPrefix(stdout, "checked 1 page: ") || !strings.HasSuffix(stdout, " violations\n") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestVerifyPolicyFromAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.txt")
	if err := os.WriteFile(file, []byte("default-src 'self'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := gencsp(t, page(`<img src=/a.png>`), "verify", "-policy-file", file)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.HasSuffix(stdout, "0 violations\n") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestVerifyThePolicyAPageSends(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
		want   int
	}{
		{"enforced, allowing it", "Content-Security-Policy", "default-src 'self'", 0},
		{"enforced, blocking it", "Content-Security-Policy", "default-src 'none'", 1},
		{"report-only, allowing it", "Content-Security-Policy-Report-Only", "default-src 'self'", 0},
		{"report-only, blocking it", "Content-Security-Policy-Report-Only", "default-src 'none'", 1},
		{"two policies, the second blocking it", "Content-Security-Policy", "default-src 'self', img-src 'none'", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := gencsp(t, sending(tt.header, tt.value), "verify")
			if code != tt.want {
				t.Errorf("exit %d, want %d: %s", code, tt.want, stderr)
			}
		})
	}
}

func TestVerifyPrefersTheEnforcedPolicy(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'none'")
		page(`<img src=/a.png>`)(w, r)
	}
	if code, _, stderr := gencsp(t, handler, "verify"); code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestVerifyGivenPolicyReplacesTheOneThePageSends(t *testing.T) {
	code, _, stderr := gencsp(t, sending("Content-Security-Policy", "default-src 'none'"), "verify", "-policy", "default-src 'self'")
	if code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// A nonce only works on the response it came with, and each load gets a new one.
func TestVerifyThePolicyAPageSendsWithNonces(t *testing.T) {
	var responses atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			nonce := fmt.Sprintf("nonce%d", responses.Add(1))
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-"+nonce+"'")
			fmt.Fprintf(w, `%s<script nonce=%s src=/a.js></script>`, prefix, nonce)
		case "/a.js":
			w.Header().Set("Content-Type", "text/javascript")
		default:
			http.NotFound(w, r)
		}
	}
	code, _, stderr := gencsp(t, handler, "verify")
	if code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if responses.Load() < 2 {
		t.Errorf("the page loaded %d times, so its nonce didn't change", responses.Load())
	}
}

func TestVerifyWithNoPolicy(t *testing.T) {
	code, stdout, stderr := gencsp(t, page(`<img src=/a.png>`), "verify")
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(stderr, "sends no policy") || !strings.Contains(stderr, "no policy to check") {
		t.Errorf("stderr = %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestVerifyWarnsAboutBypasses(t *testing.T) {
	code, _, stderr := gencsp(t, page(`<img src=/a.png>`), "verify", "-policy", "default-src 'self'; script-src https://www.google.com")
	if code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "warning: script-src allows https://www.google.com, which has a JSONP endpoint") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestVerifyCrawls(t *testing.T) {
	links := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'none'")
		if r.URL.Path == "/" {
			fmt.Fprint(w, prefix+`<a href=/other>Other</a>`)
			return
		}
		page("")(w, r)
	}
	code, stdout, stderr := gencsp(t, links, "verify", "-pages", "2", "-policy", "default-src 'self'; img-src 'none'")
	if code != 1 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "checked 2 pages: ") {
		t.Errorf("stdout = %q", stdout)
	}
	if strings.Count(stderr, "/other.png") != 1 {
		t.Errorf("the image should be reported once, but stderr = %q", stderr)
	}
}

func TestVerifyReadsEachPolicyInAHeader(t *testing.T) {
	handler := sending("Content-Security-Policy", "default-src 'self', script-src https://www.google.com")
	code, _, stderr := gencsp(t, handler, "verify")
	if code != 0 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "warning: script-src allows https://www.google.com") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestVerifyGroupsPagesByPolicy(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			fmt.Fprint(w, prefix+`<a href=/other>Other</a><img src=/a.png>`)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'none'")
		page("")(w, r)
	}
	code, stdout, stderr := gencsp(t, handler, "verify", "-pages", "2")
	if code != 1 {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "checked 2 pages: ") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "/other") || strings.Contains(stderr, "/a.png") {
		t.Errorf("each page should be checked under its own policy, but stderr = %q", stderr)
	}
}

func TestVerifyUsage(t *testing.T) {
	file := filepath.Join(t.TempDir(), "blank.txt")
	if err := os.WriteFile(file, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no URL", []string{"verify"}, "usage: gencsp verify"},
		{"both sources", []string{"verify", "-policy", "a", "-policy-file", "b", "https://a.test"}, "usage: gencsp verify"},
		{"unknown flag", []string{"verify", "-meta", "https://a.test"}, "usage: gencsp verify"},
		{"missing file", []string{"verify", "-policy-file", filepath.Join(t.TempDir(), "none"), "https://a.test"}, "gencsp: "},
		{"blank file", []string{"verify", "-policy-file", file, "https://a.test"}, "the policy is empty"},
		{"blank policy", []string{"verify", "-policy", " ", "https://a.test"}, "the policy is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if code := run(t.Context(), tt.args, &stdout, &stderr); code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestVerifyUnreachablePage(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(t.Context(), []string{"verify", "http://127.0.0.1:1/"}, &stdout, &stderr); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "gencsp: ") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestVerifyBadURL(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(t.Context(), []string{"verify", "http://a b/"}, &stdout, &stderr); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
}
