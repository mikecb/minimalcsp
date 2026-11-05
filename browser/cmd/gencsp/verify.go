package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/chromedp/chromedp"

	"github.com/mikecb/minimalcsp"
	"github.com/mikecb/minimalcsp/browser"
)

// verify checks pages against a policy that already exists, either one given
// on the command line or the one each page sends.
func verify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gencsp verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	given := flags.String("policy", "", "the policy to check, instead of the one each page sends")
	file := flags.String("policy-file", "", "read the policy to check from this file")
	maxPages := flags.Int("pages", 1, "crawl up to this many pages on the same origin from each URL")
	noSandbox := flags.Bool("no-sandbox", false, "run Chrome without its sandbox, which some containers need")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: gencsp verify [flags] <url>...")
		flags.PrintDefaults()
	}
	if flags.Parse(args) != nil {
		return 2
	}
	if flags.NArg() == 0 || (*given != "" && *file != "") {
		flags.Usage()
		return 2
	}
	policy := *given
	if *file != "" {
		content, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(stderr, "gencsp:", err)
			return 2
		}
		policy = string(content)
	}
	if (*given != "" || *file != "") && len(minimalcsp.ParsePolicy(policy).Directives) == 0 {
		fmt.Fprintln(stderr, "gencsp: the policy is empty")
		return 2
	}

	var collector browser.Collector
	if *noSandbox {
		collector.Options = append(collector.Options, chromedp.NoSandbox)
	}
	urls := flags.Args()
	if *maxPages > 1 {
		urls = nil
		for _, start := range flags.Args() {
			pages, err := collector.Crawl(ctx, start, *maxPages)
			if err != nil {
				fmt.Fprintln(stderr, "gencsp:", err)
				return 1
			}
			for _, page := range pages {
				urls = append(urls, page.URL.String())
			}
		}
	}

	// Pages that share a policy are checked together, with one browser.
	var policies []string
	pagesUnder := map[string][]string{}
	for _, pageURL := range urls {
		list := []string{strings.TrimSpace(policy)}
		if *given == "" && *file == "" {
			var err error
			if list, err = sentPolicies(ctx, pageURL); err != nil {
				fmt.Fprintln(stderr, "gencsp:", err)
				return 1
			}
			if len(list) == 0 {
				fmt.Fprintf(stderr, "warning: %s sends no policy in a header, so it wasn't checked. For a <meta> policy, use -policy\n", pageURL)
			}
		}
		for _, p := range list {
			if pagesUnder[p] == nil {
				policies = append(policies, p)
			}
			pagesUnder[p] = append(pagesUnder[p], pageURL)
		}
	}
	if len(policies) == 0 {
		fmt.Fprintln(stderr, "gencsp: there was no policy to check")
		return 1
	}

	found := 0
	for _, p := range policies {
		for _, warning := range minimalcsp.ParsePolicy(p).Warnings {
			fmt.Fprintln(stderr, "warning:", warning)
		}
		violations, err := collector.Verify(ctx, p, pagesUnder[p]...)
		if err != nil {
			fmt.Fprintln(stderr, "gencsp: verifying:", err)
			return 1
		}
		for _, v := range violations {
			fmt.Fprintf(stderr, "violation: %s: %s\n", v.Page, v)
		}
		found += len(violations)
	}
	fmt.Fprintf(stdout, "checked %d %s: %d %s\n", len(urls), plural(len(urls), "page", "pages"), found, plural(found, "violation", "violations"))
	if found > 0 {
		return 1
	}
	return 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// nonceSource matches a nonce, which only suits the response it came from.
var nonceSource = regexp.MustCompile(`'nonce-[^']*'`)

// sentPolicies returns the policies pageURL sends in its headers, or its
// report-only ones if it enforces none. A header can hold several, separated by
// commas, and a browser applies each of them separately. Nonces become
// minimalcsp.NoncePlaceholder, so that each is checked with the nonce of the
// response it's loaded with.
func sentPolicies(ctx context.Context, pageURL string) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	values := response.Header.Values("Content-Security-Policy")
	if len(values) == 0 {
		values = response.Header.Values("Content-Security-Policy-Report-Only")
	}
	var policies []string
	for _, value := range values {
		for policy := range strings.SplitSeq(value, ",") {
			if policy = strings.TrimSpace(policy); policy != "" {
				policies = append(policies, nonceSource.ReplaceAllString(policy, "'nonce-"+minimalcsp.NoncePlaceholder+"'"))
			}
		}
	}
	return policies, nil
}
