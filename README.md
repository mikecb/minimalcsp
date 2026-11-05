# minimalcsp

[![CI](https://github.com/mikecb/minimalcsp/actions/workflows/ci.yml/badge.svg)](https://github.com/mikecb/minimalcsp/actions/workflows/ci.yml)

Generate the minimal working Content Security Policy (CSP) for a given webpage.

> **Status: early.** minimalcsp generates valid, strict policies, but so far it reads only a page's HTML. Policies deny by default, so anything it can't see gets blocked. Try a policy with `Content-Security-Policy-Report-Only` before enforcing it. See the [roadmap](TODO.md).

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
| Finding resources | A headless browser, plus report-only collection from real traffic | HTML parsing only so far |
| Inline code | Hashes and nonces only, never `'unsafe-inline'` | Hashes built |
| Scripts | Trusted by hash or nonce with `'strict-dynamic'`, not URL allowlists | Listed by exact URL with a warning for now |
| Other resources | Origins by default, with exact paths as an option | Built |
| Static sites | Hashes, delivered in a header or a `<meta>` tag | Header value built |
| Dynamic servers | Nonces, with middleware for Go servers | Planned |
| Unfixable inline code | Event handlers, `style` attributes and `javascript:` URLs are reported for the site to fix | Built |
| Interfaces | A Go library first, with a CLI and CI check built on it | Library and basic CLI built |

## Usage

Requires Go 1.27.3 or later.

### Command line

```bash
go run ./cli https://example.com
```

This fetches the page and prints a policy on stdout:

```text
default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; img-src data:; script-src https://example.com/s.js; style-src 'sha256-zQhcS0BkpPhIWxF5sE2D1PEgBIvlKsPn21RDpgKhXxM='
```

Anything you should know before deploying it goes to stderr:

```text
warning: static analysis can't see what this page's scripts and stylesheets load, such as fonts and API requests
warning: script-src allows https://example.com/s.js by URL, which is weaker than a hash or nonce
```

Lines starting with `blocked:` show inline code that the policy blocks and that has to change. To list resources by URL rather than by origin, add `-exact-paths`, which is tighter but needs regenerating whenever a resource moves.

### Library

```go
page, err := minimalcsp.StaticCollector{}.Collect(ctx, "https://example.com")
if err != nil {
	return err
}
policy := minimalcsp.Build(page, minimalcsp.Options{})

w.Header().Set("Content-Security-Policy-Report-Only", policy.String())
for _, blocker := range policy.Blockers {
	log.Println(blocker)
}
```

If you already have the HTML, use `minimalcsp.Parse` instead of a collector.

## Limitations

- It can't see anything loaded after the HTML, such as fonts referenced from CSS or requests made by scripts. Policies block these until the browser collector in [phase 3](TODO.md#phase-3-headless-browser) can find them.
- Hashes match a page's exact inline code, so any change to it means generating a new policy.
- External scripts are allowed by URL, which isn't as strong as a hash or nonce.
- Each policy covers one page. Other pages on the same site may need more.

## Development

Before opening a pull request, run the same checks CI runs:

```bash
bash scripts/check.sh
```

This checks formatting, `go.mod`, `go vet`, the build and the tests, and fails if coverage drops below 95%.

Changes reach `master` only through pull requests. To merge, the `CI passed` check must succeed on a branch that's up to date with `master`, and every review thread must be resolved. That check covers:

- `scripts/check.sh` on Linux, Windows and macOS
- The race detector
- `govulncheck`, which also runs weekly

Dependabot proposes dependency and action updates weekly.

## License

MIT. See [license.md](license.md).
