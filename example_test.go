package minimalcsp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/mikecb/minimalcsp"
)

func ExampleTally() {
	site, err := url.Parse("https://site.example/")
	if err != nil {
		panic(err)
	}
	tally := &minimalcsp.Tally{Site: site}
	handler := minimalcsp.ReportHandler{Receive: tally.Add}

	// Three visitors load an image the policy doesn't allow.
	const report = `{"csp-report":{
		"document-uri": "https://site.example/about",
		"effective-directive": "img-src",
		"blocked-uri": "https://cdn.example/logo.png"
	}}`
	for _, address := range []string{"192.0.2.1:1234", "192.0.2.2:1234", "192.0.2.3:1234"} {
		request := httptest.NewRequest(http.MethodPost, "/csp-reports", strings.NewReader(report))
		request.Header.Set("Content-Type", "application/csp-report")
		request.RemoteAddr = address
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	policy := minimalcsp.ParsePolicy("default-src 'none'; img-src 'self'")
	for _, addition := range tally.Suggest(policy).Additions {
		fmt.Println(addition)
	}
	// Output:
	// img-src https://cdn.example: 3 reports from 3 clients, such as https://cdn.example/logo.png on https://site.example/about
}
