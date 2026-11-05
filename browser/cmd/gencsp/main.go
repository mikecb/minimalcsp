// Command gencsp runs a page in headless Chrome, prints the minimal working
// Content Security Policy for it, and checks that the page works under that
// policy. It needs Chrome or Chromium installed.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/chromedp/chromedp"

	"github.com/mikecb/minimalcsp"
	"github.com/mikecb/minimalcsp/browser"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gencsp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	scripts := flags.String("scripts", "hash", "how to trust scripts: hash for static sites, nonce for servers, or url to leave the page unchanged")
	meta := flags.Bool("meta", false, "print a <meta> tag instead of a header value, for hosts that can't set headers")
	reportTo := flags.String("report-to", "", "add reporting to this endpoint to the printed policy")
	exactPaths := flags.Bool("exact-paths", false, "list resources by URL rather than by origin")
	maxPages := flags.Int("pages", 1, "crawl up to this many pages on the same origin")
	skipVerify := flags.Bool("no-verify", false, "don't check the page under the generated policy")
	noSandbox := flags.Bool("no-sandbox", false, "run Chrome without its sandbox, which some containers need")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: gencsp [flags] <url>")
		flags.PrintDefaults()
	}
	if flags.Parse(args) != nil {
		return 2
	}
	trust, ok := map[string]minimalcsp.ScriptTrust{
		"hash":  minimalcsp.ByHash,
		"nonce": minimalcsp.ByNonce,
		"url":   minimalcsp.ByURL,
	}[*scripts]
	if flags.NArg() != 1 || !ok {
		flags.Usage()
		return 2
	}
	if *meta && trust == minimalcsp.ByNonce {
		fmt.Fprintln(stderr, "gencsp: -meta can't be used with -scripts nonce, because a nonce needs a server, and a server can set a header")
		return 2
	}

	if *meta && *reportTo != "" {
		fmt.Fprintln(stderr, "gencsp: -meta can't be used with -report-to, because browsers ignore reporting in a <meta> tag")
		return 2
	}

	var collector browser.Collector
	if *noSandbox {
		collector.Options = append(collector.Options, chromedp.NoSandbox)
	}
	pages, err := collector.Crawl(ctx, flags.Arg(0), *maxPages)
	if err != nil {
		fmt.Fprintln(stderr, "gencsp:", err)
		return 1
	}
	policy := minimalcsp.Build(minimalcsp.Merge(pages...), minimalcsp.Options{Scripts: trust, ExactPaths: *exactPaths})

	switch {
	case *meta:
		fmt.Fprintln(stdout, policy.MetaTag())
	case *reportTo != "":
		fmt.Fprintln(stdout, policy.ReportingTo(*reportTo))
	default:
		fmt.Fprintln(stdout, policy)
	}
	for _, warning := range policy.Warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	if *meta {
		fmt.Fprintln(stderr, "warning: a <meta> policy can't run in report-only mode, report violations, or stop other sites framing the page, so use a header if you can")
	}
	for _, blocker := range policy.Blockers {
		fmt.Fprintln(stderr, "blocked:", blocker)
	}
	for _, integrity := range policy.Integrity {
		fmt.Fprintln(stderr, "change:", integrity)
	}
	if trust == minimalcsp.ByNonce {
		fmt.Fprintln(stderr, "change: every script element in the page as served needs the nonce")
	}
	if *meta {
		fmt.Fprintln(stderr, "change: the tag goes at the start of <head>, after any <meta charset>, and replaces any tag already there")
	}
	if *reportTo != "" {
		fmt.Fprintln(stderr, "change: send the policy in a Content-Security-Policy-Report-Only header to collect reports without blocking anything")
	}
	if *skipVerify {
		return 0
	}

	urls := make([]string, len(pages))
	for i, page := range pages {
		urls[i] = page.URL.String()
	}
	verify := collector.VerifyPolicy
	if *meta {
		verify = collector.VerifyMeta
	}
	violations, err := verify(ctx, policy, urls...)
	if err != nil {
		fmt.Fprintln(stderr, "gencsp: verifying:", err)
		return 1
	}
	status := 0
	for _, v := range violations {
		if !explained(v, policy) {
			fmt.Fprintf(stderr, "violation: %s: %s\n", v.Page, v)
			status = 1
		}
	}
	if status != 0 && trust == minimalcsp.ByHash {
		fmt.Fprintln(stderr, "hint: scripts trusted by hash can't use import, and need CORS if they're cross-origin, so try -scripts nonce")
	}
	return status
}

// explained reports whether v is code the policy already says it blocks.
func explained(v browser.Violation, policy *minimalcsp.Policy) bool {
	return v.Sample != "" && slices.ContainsFunc(policy.Blockers, func(b minimalcsp.Blocker) bool {
		return strings.HasPrefix(b.Value, v.Sample)
	})
}
