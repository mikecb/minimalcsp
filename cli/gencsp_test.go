package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMain lets each test run the real main in a child process, since main
// reads os.Args and exits through log.Fatal.
func TestMain(m *testing.M) {
	if os.Getenv("GENCSP_RUN_MAIN") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func gencsp(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GENCSP_RUN_MAIN=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func TestFetchesPageAndPrintsSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<img src="a.png"><script src="b.js"></script>`))
	}))
	defer srv.Close()

	stdout, stderr, err := gencsp(t, srv.URL)
	if err != nil {
		t.Fatalf("gencsp failed: %v\n%s", err, stderr)
	}
	for _, want := range []string{"img-src a.png", "script-src b.js"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output %q is missing %q", stdout, want)
		}
	}
}

func TestUnreachableURLFails(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	if _, _, err := gencsp(t, url); err == nil {
		t.Error("gencsp succeeded against a closed server, want an error")
	}
}

func TestMissingURLReportsUsage(t *testing.T) {
	_, stderr, err := gencsp(t)
	if err == nil {
		t.Error("gencsp succeeded with no URL, want an error")
	}
	if strings.Contains(stderr, "panic:") {
		t.Errorf("gencsp panicked instead of reporting usage:\n%s", stderr)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr is missing usage text:\n%s", stderr)
	}
}

func TestHTTPErrorStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<img src="error.png">`))
	}))
	defer srv.Close()

	stdout, _, err := gencsp(t, srv.URL)
	if err == nil {
		t.Error("gencsp succeeded on a 404, want an error")
	}
	if strings.Contains(stdout, "error.png") {
		t.Errorf("gencsp printed sources from an error page: %q", stdout)
	}
}
