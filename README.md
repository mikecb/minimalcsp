# minimalcsp

[![CI](https://github.com/mikecb/minimalcsp/actions/workflows/ci.yml/badge.svg)](https://github.com/mikecb/minimalcsp/actions/workflows/ci.yml)

Generate the minimal working Content Security Policy (CSP) for a given webpage.

> **Status: early.** minimalcsp runs a page in headless Chrome, generates a strict policy, and checks the page under that policy. Policies deny by default, so anything a run doesn't reach gets blocked, such as a page behind a login. Try a policy with `Content-Security-Policy-Report-Only` before enforcing it. See the [roadmap](TODO.md).

## Why

A Content Security Policy tells browsers which resources a page may load and run, which limits the damage from cross-site scripting (XSS). A policy that's too strict breaks the page, and one that's too loose protects very little. Writing one by hand means tracking every resource a page uses and keeping that list current as the page changes.

Loose policies are common. A 2016 Google study, [CSP Is Dead, Long Live CSP!](https://research.google.com/pubs/archive/45542.pdf), found that 94.72% of 26,011 distinct policies were trivially bypassable, largely because of URL allowlists.

## Goals

1. **Effective:** the policy protects against XSS, not just satisfies a scanner. minimalcsp never emits `'unsafe-inline'`, and it aims to trust scripts by hash or nonce rather than by URL.
2. **Working:** the policy is checked in a real browser, so it's known not to break the page it was generated for.
3. **Minimal:** the policy allows only what the page needs. Every entry is there because of something observed on the page.
4. **Easy to adopt:** the same library works for any deployment, from a static site to a dynamic server, without trading away tightness.
5. **Honest:** when a page can't meet a strict policy, or minimalcsp can't tell what it needs, it says so rather than guessing or silently widening the policy.

## Design

The [roadmap](TODO.md) tracks what's left.

| Area | Approach | Status |
|---|---|---|
| Finding resources | A headless browser, plus report-only collection from real traffic | Headless browser and HTML parsing built |
| Checking policies | Load the page under the policy in report-only mode | Built |
| Inline code | Hashes and nonces only, never `'unsafe-inline'` | Hashes built |
| Scripts | Trusted by hash or nonce with `'strict-dynamic'`, not URL allowlists | Listed by exact URL with a warning for now |
| Other resources | Origins by default, with exact paths as an option | Built |
| Static sites | Hashes, delivered in a header or a `<meta>` tag | Header value built |
| Dynamic servers | Nonces, with middleware for Go servers | Planned |
| Unfixable inline code | Event handlers, `style` attributes, `javascript:` URLs and `eval` are reported for the site to fix | Built |
| Interfaces | A Go library first, with a CLI and CI check built on it | Library and CLIs built |

## Usage

Requires Go 1.27.3 or later. The browser collector also needs Chrome or Chromium.

The repository has two Go modules, so that users of the library don't depend on a browser driver:

| Module | Contains |
|---|---|
| `github.com/mikecb/minimalcsp` | The library, an HTML-only collector and a small CLI |
| `github.com/mikecb/minimalcsp/browser` | The headless Chrome collector and its CLI |

### Command line

```bash
go -C browser run ./cmd/gencsp https://example.com
```

This runs the page in headless Chrome and prints a policy on stdout:

```text
default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; img-src data:; script-src https://example.com/s.js; style-src 'sha256-zQhcS0BkpPhIWxF5sE2D1PEgBIvlKsPn21RDpgKhXxM='
```

It then loads the page again under that policy. Anything you should know goes to stderr:

```text
warning: script-src allows https://example.com/s.js by URL, which is weaker than a hash or nonce
blocked: inline event handler: <p onclick="go()">
violation: https://example.com/: img-src blocked https://example.com/late.png
```

- `warning:` lines are weaknesses in the policy, or gaps in what was seen.
- `blocked:` lines are inline code that the policy blocks and that has to change.
- `violation:` lines are anything else the page did that the policy didn't allow. Any of these make the command exit with status 1.

| Flag | Effect |
|---|---|
| `-pages n` | Crawl up to `n` pages on the same origin, and build one policy for all of them |
| `-exact-paths` | List resources by URL rather than by origin, which is tighter but needs regenerating whenever a resource moves |
| `-no-verify` | Don't load the page again under the policy |
| `-no-sandbox` | Run Chrome without its sandbox, which some containers need |

`go run ./cli <url>` from the repository root does the same without a browser, by reading only the HTML. It can't see fonts, requests made by scripts, or anything added at runtime, and it says so.

### Library

```go
collector := browser.Collector{}
page, err := collector.Collect(ctx, "https://example.com")
if err != nil {
	return err
}
policy := minimalcsp.Build(page, minimalcsp.Options{})

violations, err := collector.Verify(ctx, policy.String(), "https://example.com")
if err != nil {
	return err
}
for _, violation := range violations {
	log.Println(violation)
}
```

Use `collector.Crawl` with `minimalcsp.Merge` to cover several pages. To reach resources behind a click or a login, set `collector.Actions` to [chromedp](https://github.com/chromedp/chromedp) actions, which run on each page after it loads.

Without a browser, use `minimalcsp.StaticCollector{}` or, if you already have the HTML, `minimalcsp.Parse`. `browser` needs a tagged release of the library before it can be used from another module.

## Limitations

- A run only sees what the page does during that run. Add `Actions` to reach resources behind interaction, and try the policy in report-only mode with real traffic.
- Hashes match a page's exact inline code, so any change to it means generating a new policy. A page whose inline code differs on every load can't have a working hash-based policy, and verifying shows this.
- External scripts are allowed by URL, which isn't as strong as a hash or nonce.
- Code in closed shadow roots, and code that a script rewrites after it runs, can't be captured. Each case gets a warning.
- To collect a site on a private network, turn off Chrome's `LocalNetworkAccessChecks` feature in `Options`. Otherwise Chrome blocks what the page loads, which shows up as warnings. Loopback addresses aren't affected.

## Development

Before opening a pull request, run the same checks CI runs:

```bash
bash scripts/check.sh
```

This checks formatting, `go.mod`, `go vet`, the build and the tests for both modules, and fails if coverage drops below 95% for the library or 85% for the browser module. The browser tests skip themselves without Chrome, except in CI.

Changes reach `master` only through pull requests. To merge, the `CI passed` check must succeed on a branch that's up to date with `master`, and every review thread must be resolved. That check covers:

- `scripts/check.sh` on Linux, Windows and macOS
- The race detector
- `govulncheck`, which also runs weekly

Dependabot proposes dependency and action updates weekly.

## License

MIT. See [license.md](license.md).
