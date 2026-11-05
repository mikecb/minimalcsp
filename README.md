# minimalcsp

Generate the minimal working Content Security Policy (CSP) for a given webpage.

> **Status: early prototype.** minimalcsp finds many of a page's resources, but it doesn't produce a valid policy yet. Don't deploy its output. See the [roadmap](TODO.md).

## Why

A Content Security Policy tells browsers which resources a page may load and run, which limits the damage from cross-site scripting (XSS). A policy that's too strict breaks the page, and one that's too loose protects very little. Writing one by hand means tracking every resource a page uses and keeping that list current as the page changes.

Loose policies are common. A 2016 Google study, [CSP Is Dead, Long Live CSP!](https://research.google.com/pubs/archive/45542.pdf), found that 94.72% of 26,011 distinct policies were trivially bypassable, largely because of URL allowlists.

## Goals

1. **Effective:** the policy protects against XSS, not just satisfies a scanner. minimalcsp never emits `'unsafe-inline'`, and it trusts scripts by hash or nonce rather than by URL.
2. **Working:** the policy is checked in a real browser, so it's known not to break the page it was generated for.
3. **Minimal:** the policy allows only what the page needs. Every entry is there because of something observed on the page.
4. **Easy to adopt:** the same library works for any deployment, from a static site to a dynamic server, without trading away tightness.
5. **Honest:** when a page can't meet a strict policy, or minimalcsp can't tell what it needs, it says so rather than guessing or silently widening the policy.

## Design

This is the planned design, and most of it isn't built yet. The [roadmap](TODO.md) tracks progress.

| Area | Approach |
|---|---|
| Finding resources | A headless browser, plus report-only collection from real traffic |
| Inline code | Hashes and nonces only, never `'unsafe-inline'` |
| Scripts | Trusted by hash or nonce with `'strict-dynamic'`, not URL allowlists |
| Other resources | Origins by default, with exact paths as an option |
| Static sites | Hashes, delivered in a header or a `<meta>` tag |
| Dynamic servers | Nonces, with middleware for Go servers |
| Unfixable inline code | Event handlers and `style` attributes are reported for the site to fix |
| Interfaces | A Go library first, with a CLI and CI check built on it |

## Usage

Requires Go 1.27.3 or later.

```bash
go run ./cli https://example.com
```

This fetches the page and prints a draft policy built from what it found:

```text
img-src data:,; style-src 'unsafe-inline'; script-src /s.js
```

The output has the right shape, but it isn't usable yet:

- Relative paths like `/s.js` aren't valid CSP sources.
- `data:,` contains a comma, which splits a header into two policies.
- Inline code still produces `'unsafe-inline'`, which [phase 2](TODO.md#phase-2-library-core) replaces with hashes.
- It reads only the HTML of the page you give it, so it can't see anything loaded later, such as fonts referenced from CSS or requests made by scripts.

## Development

```bash
go test ./...
```

## License

MIT. See [license.md](license.md).
