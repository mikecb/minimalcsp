# minimalcsp

[![CI](https://github.com/mikecb/minimalcsp/actions/workflows/ci.yml/badge.svg)](https://github.com/mikecb/minimalcsp/actions/workflows/ci.yml)

Generate the minimal working Content Security Policy (CSP) for a given webpage.

> **Status: early.** minimalcsp runs a page in headless Chrome, generates a strict policy, and checks the page under that policy. Policies deny by default, so anything a run doesn't reach gets blocked, such as a page behind a login. Try a policy in report-only mode before enforcing it, as [Rolling out a policy](#rolling-out-a-policy) describes. See the [roadmap](TODO.md).

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
| Finding resources | A headless browser, plus report-only collection from real traffic | Built, along with HTML parsing |
| Checking policies | Load the page under the policy in report-only mode | Built |
| Inline code | Hashes and nonces only, never `'unsafe-inline'` | Hashes built |
| Scripts | Trusted by hash or nonce with `'strict-dynamic'`, not URL allowlists | Built, with URLs as an explicit option |
| Other resources | Origins by default, with exact paths as an option | Built |
| Static sites | Hashes with `integrity` attributes, delivered in a header or a `<meta>` tag | Built |
| Dynamic servers | Nonces, with middleware for Go servers | Built |
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

Install `gencsp`, and give it a page:

```bash
go install github.com/mikecb/minimalcsp/browser/cmd/gencsp@latest
```

```bash
gencsp https://example.com
```

This runs the page in headless Chrome and prints a policy on stdout:

```text
default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; img-src data:; script-src 'sha256-U17yw0JanRIUvNGo1UMNkEREE15IpPETuh5vbimSWwo='; style-src 'sha256-zQhcS0BkpPhIWxF5sE2D1PEgBIvlKsPn21RDpgKhXxM='
```

It then loads the page again under that policy, with any changes the policy needs already made to the page. Anything you should know goes to stderr:

```text
change: https://example.com/s.js needs integrity="sha256-U17yw0JanRIUvNGo1UMNkEREE15IpPETuh5vbimSWwo="
warning: couldn't hash https://example.com/late.js, so the policy will block it
blocked: inline event handler: <p onclick="go()">
violation: https://example.com/: img-src blocked https://example.com/late.png
```

- `change:` lines are what the page needs before you deploy the policy.
- `warning:` lines are weaknesses in the policy, or gaps in what was seen.
- `blocked:` lines are inline code that the policy blocks and that has to change.
- `violation:` lines are anything else the page did that the policy didn't allow. Any of these make the command exit with status 1.

| Flag | Effect |
|---|---|
| `-scripts mode` | How to trust scripts: `hash`, `nonce` or `url`. See [Choosing how to trust scripts](#choosing-how-to-trust-scripts) |
| `-meta` | Print a `<meta>` tag instead of a header value, and check the page under that tag. See [Hosts that can't set headers](#hosts-that-cant-set-headers) |
| `-pages n` | Crawl up to `n` pages on the same origin, and build one policy for all of them |
| `-report-to url` | Add reporting to this endpoint to the printed policy. See [Collecting reports](#collecting-reports) |
| `-exact-paths` | List resources by URL rather than by origin, which is tighter but needs regenerating whenever a resource moves |
| `-no-verify` | Don't load the page again under the policy |
| `-no-sandbox` | Run Chrome without its sandbox, which some containers need |

The library's module has a smaller CLI, `github.com/mikecb/minimalcsp/cmd/gencsp`, which works without a browser by reading only the HTML. It installs under the same name, so install the one you want. It can't see fonts, requests made by scripts, or anything added at runtime, and it says so. It lists scripts by URL, because it never downloads them to hash them.

### Choosing how to trust scripts

| | `hash` (the default) | `nonce` | `url` |
|---|---|---|---|
| Use it for | Static sites | Sites with a server | Trying a policy on a page you can't change yet |
| Page changes | `integrity` attributes, which `Policy.Apply` adds | A nonce on every `<script>` in your templates | None |
| Scripts that change | Need a new policy | Keep working | Keep working |
| Cross-origin scripts | Need CORS | Keep working | Keep working |
| `import` and `import()` | Blocked | Keep working | Keep working |
| Strength | Strong | Strong | Weak: anything an attacker gets onto a listed URL runs |

Scripts added by trusted scripts don't need listing. `'strict-dynamic'` trusts them, and it's in the policy only if the page needs it. The `hash` and `nonce` modes need Chrome 59, Firefox 116 or Safari 15.6, or later.

If a policy lists hosts, `Warnings` names any source that lets injected markup run code: hosts with JSONP endpoints, hosts serving AngularJS, hosts where anyone can publish files, such as public CDNs, and anything that covers one of those, such as a wildcard. An exact URL on a public CDN is fine, but listing the whole host isn't, even if the page loads only one file from it. `Build` gives these warnings for the `url` mode, and `minimalcsp.ParsePolicy` gives them for a policy you already have. Browsers ignore host sources in a policy with `'strict-dynamic'`, so those policies get no warning.

If verifying fails under `hash` because scripts use `import`, switch to `nonce`.

### Hosts that can't set headers

Some static hosts, such as GitHub Pages, don't let you set response headers. For those, `-meta` prints the policy as a tag:

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ...">
```

The tag goes at the start of `<head>`, after any `<meta charset>`. It has to come before everything it governs, because it only applies to what follows it, and browsers ignore it outside `<head>`. In the library, `Policy.ApplyMeta` puts it there, and replaces any policy tag already in the page.

Use a header if you can, because a tag does less:

- It has no report-only mode, so the first time it runs in a browser, it's enforced. `-meta` checks the page in Chrome with the tag in force, which is the closest thing to a trial. One blocked resource can hide whatever depended on it, so a clean run matters more than it does with a header.
- It can't report violations, so you won't hear about pages it breaks.
- Browsers ignore `frame-ancestors`, `report-uri` and `sandbox` in it, so a tag can't stop other sites framing your page.

`-meta` doesn't work with `-scripts nonce`, because a nonce needs a server, and a server can set a header.

To regenerate a policy, collect from a copy of the page without the tag. A tag already in the page stays in force during collection, which hides whatever it blocks.

### Nonces on a Go server

```go
policy := minimalcsp.Build(page, minimalcsp.Options{Scripts: minimalcsp.ByNonce})
handler := minimalcsp.NonceMiddleware{Policy: policy}.Wrap(mux)
```

Each response gets a new nonce. Templates add it with `minimalcsp.Nonce(r.Context())`:

```html
<script nonce="{{.Nonce}}" src="/app.js"></script>
```

Put nonces in your templates, not in a filter that rewrites responses. A filter would give a nonce to every script in the page, including one an attacker managed to inject, which defeats the policy. Don't cache pages that use nonces.

For other servers, `-scripts nonce` prints the policy with `{nonce}` where each response's nonce goes.

### Collecting reports

A crawl only sees what happened during that run. Real visitors reach pages a crawl can't, in browsers it doesn't use. To learn what they need, send your policy in report-only mode and collect what browsers report:

```go
tally := &minimalcsp.Tally{Site: siteURL}
mux.Handle("/csp-reports", minimalcsp.ReportHandler{Receive: tally.Add})

// Send this in a Content-Security-Policy-Report-Only header.
header := policy.ReportingTo("/csp-reports").String()
```

For nonces, set `ReportOnly` and `ReportTo` on `NonceMiddleware` instead. On the command line, `-report-to /csp-reports` prints the policy with reporting added.

Then ask what the policy is missing:

```go
suggestions := tally.Suggest(policy)
for _, addition := range suggestions.Additions {
	log.Println(addition) // img-src https://cdn.example: 8 reports from 5 clients, such as ...
}
```

`Additions` are sources to review and add, `Blockers` are inline code that has to change, and `Warnings` are anything that needs a person. To regenerate a policy, pass `tally.Page()` to `minimalcsp.Merge` along with what a collector found, then to `Build`. If you only have a policy as text, `minimalcsp.ParsePolicy` reads it.

A `Tally` only counts something once `MinClients` different clients report it, which defaults to 3. It ignores anything from a browser extension, and anything from a page outside `Site`. Behind a proxy, set `ClientID` on the handler, or every report seems to come from the proxy and nothing ever counts.

**Reports aren't authenticated, so anyone can send one.** With enough addresses, someone can make anything repeat. To limit what that can do:

- A report never adds a source that can run code: `script-src`, `worker-src`, `object-src` or `base-uri`. Those become warnings. A script needs its hash anyway, which a report doesn't carry, so collect the page again.
- Inline code never gets hashed from a report, because a report only has its first 40 characters.
- Blocked URLs are checked before they can reach a policy, so a forged one can't add directives.

Other sources can still be forged, and one an attacker added could let them send data out. Review additions before you deploy them, and rate-limit the endpoint.

Reports can hold private data, so query strings are dropped, and clients are stored as a hash that changes on restart. Samples of inline code are kept. A `Tally` is kept in memory, so to keep reports past a restart or combine servers, store them from `Receive` and pass them to `Add` later.

`ReportingTo` uses `report-uri`, not the newer `report-to`. Chrome ignores `report-uri` when both are present, and `report-to` doesn't work on plain HTTP, so listing both loses every report from those pages. `ReportHandler` accepts both formats, so a site already using the Reporting API can point it there.

### Rolling out a policy

A policy that's too strict breaks your site for real visitors, so try it where it can't do any harm first.

**1. Generate a policy and fix what it finds.** Crawl enough of the site to cover its different kinds of page:

```bash
gencsp -pages 20 https://example.com
```

Work through the output until the command exits with status 0. `blocked:` lines are inline code to rewrite, and `violation:` lines are anything else the page did that the policy didn't allow.

**2. Make the page changes.** Deploy what the `change:` lines ask for, using `Policy.Apply` in a build step for `integrity` attributes, or your templates for nonces. These need to be live before you try the policy, or scripts get reported that are fine.

`integrity` attributes take effect right away, whatever the policy says. A cross-origin script without CORS fails as soon as it has one, and so does any script that later changes. `gencsp` tests for this, so don't skip step 1.

**3. Send the policy in report-only mode.** Nothing gets blocked, and browsers report what would have been. Set up a [`ReportHandler`](#collecting-reports), then print the policy with reporting added:

```bash
gencsp -pages 20 -report-to https://example.com/csp-reports https://example.com
```

Send the result in a `Content-Security-Policy-Report-Only` header. The endpoint can be on another origin, which is useful for a static site with nowhere to run a handler. For nonces, set `ReportOnly` and `ReportTo` on `NonceMiddleware`.

If you're replacing a policy that's already enforced, keep sending it as it is, and send the new one alongside it. Browsers enforce the old one and report on the new one.

**4. Collect reports for long enough to cover how the site gets used.** A day misses anything weekly, and a week misses anything monthly. Waiting costs nothing, since nothing is being blocked.

**5. Review what `Tally.Suggest` returns, and repeat.**

- Add the `Additions` you recognize, after checking each one. Reports can be forged.
- Rewrite the code in `Blockers`.
- For a script or inline code in `Warnings`, generate the policy again from a page that reaches it, using `Actions` if it's behind a login.

Go back to step 3 with the new policy, and keep going until only noise is left.

**6. Enforce it.** Send the same value in a `Content-Security-Policy` header. Keep `report-uri` in it, so that you hear about what it blocks from now on.

Deploy the policy along with the page it was generated for. Under `hash`, a page with old code and a policy with new hashes blocks that code, so watch for caches serving one without the other.

If something breaks, change the header back to `Content-Security-Policy-Report-Only`. That stops the blocking at once, except for `integrity` attributes, and you keep getting reports.

**7. Keep it current.** Under `hash`, a policy has to change whenever a script or inline code does, so generate it and run `Apply` in your build. Under `nonce`, it only changes when the page starts using something new. Either way, keep watching the reports.

Without response headers, steps 3 to 5 aren't available, because a `<meta>` tag has no report-only mode and can't report. Use `-meta` to check the page with the tag in force, try it on a preview of the site, and cover as many pages as you can with `-pages` and `Actions`, because nothing will tell you what it blocks in production.

### Library

```go
collector := browser.Collector{}
page, err := collector.Collect(ctx, "https://example.com")
if err != nil {
	return err
}
policy := minimalcsp.Build(page, minimalcsp.Options{})

violations, err := collector.VerifyPolicy(ctx, policy, "https://example.com")
if err != nil {
	return err
}
for _, violation := range violations {
	log.Println(violation)
}

// Add the integrity attributes the policy needs to a page.
updated := policy.Apply(document, pageURL)
```

`Apply` changes nothing else in the page, so it's safe to run in a build step. `collector.Verify` checks a policy string against a page as it stands.

For a host that can't set headers, use `policy.ApplyMeta` to add the tag too, and `collector.VerifyMeta` to check the page with it in force. `minimalcsp.InsertMeta` does the same for a policy you wrote yourself.

Use `collector.Crawl` with `minimalcsp.Merge` to cover several pages. To reach resources behind a click or a login, set `collector.Actions` to [chromedp](https://github.com/chromedp/chromedp) actions, which run on each page after it loads.

Without a browser, use `minimalcsp.StaticCollector{}` or, if you already have the HTML, `minimalcsp.Parse`.

## Limitations

- A run only sees what the page does during that run. Add `Actions` to reach resources behind interaction, and try the policy in report-only mode with real traffic.
- Hashes match a page's exact inline code, so any change to it means generating a new policy. A page whose inline code differs on every load can't have a working hash-based policy, and verifying shows this.
- Under `hash`, a script that changes needs a new policy, so scripts you don't control, such as analytics, can break the page without warning. Use `nonce` for those pages.
- `'strict-dynamic'` doesn't trust scripts added through `document.write` or other parser-inserted routes. Verifying reports these, and they have to change.
- Code in closed shadow roots, and code that a script added and that then rewrote itself, can't be captured. Each case gets a warning.
- The list of bypassable hosts is short and checked by hand, so a source with no warning isn't proof that a host is safe.
- To collect a site on a private network, turn off Chrome's `LocalNetworkAccessChecks` feature in `Options`. Otherwise Chrome blocks what the page loads, which shows up as warnings. Loopback addresses aren't affected.

## Development

Before opening a pull request, run the same checks CI runs:

```bash
bash scripts/check.sh
```

This checks formatting, `go.mod`, `go vet`, the build and the tests for both modules, and fails if coverage drops below 95% for the library or 85% for the browser module. The browser tests skip themselves without Chrome, except in CI.

`go.work` makes the `browser` module build against the library in this repository, rather than the released version it requires.

Changes reach `master` only through pull requests. To merge, the `CI passed` check must succeed on a branch that's up to date with `master`, and every review thread must be resolved. That check covers:

- `scripts/check.sh` on Linux, Windows and macOS
- The race detector
- `govulncheck`, which also runs weekly

Dependabot proposes dependency and action updates weekly.

### Releasing

The two modules have separate versions, and `browser` depends on the library, so the library goes first:

1. Tag the library on `master` with a version like `v0.2.0`.
2. In a pull request, update `browser/go.mod` to require that version, with `go -C browser get github.com/mikecb/minimalcsp@v0.2.0`.
3. Once that's merged, tag `master` with `browser/v0.2.0`.

A tag is permanent. The Go module proxy keeps every version it sees, even if the tag is later deleted, so a bad release can only be replaced by a newer one.

## License

MIT. See [LICENSE](LICENSE).
