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
	if flags.NArg() != 1 {
		flags.Usage()
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
	policy := minimalcsp.Build(minimalcsp.Merge(pages...), minimalcsp.Options{ExactPaths: *exactPaths})

	fmt.Fprintln(stdout, policy)
	for _, warning := range policy.Warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	for _, blocker := range policy.Blockers {
		fmt.Fprintln(stderr, "blocked:", blocker)
	}
	if *skipVerify {
		return 0
	}

	urls := make([]string, len(pages))
	for i, page := range pages {
		urls[i] = page.URL.String()
	}
	violations, err := collector.Verify(ctx, policy.String(), urls...)
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
	return status
}

// explained reports whether v is code the policy already says it blocks.
func explained(v browser.Violation, policy *minimalcsp.Policy) bool {
	return v.Sample != "" && slices.ContainsFunc(policy.Blockers, func(b minimalcsp.Blocker) bool {
		return strings.HasPrefix(b.Value, v.Sample)
	})
}
