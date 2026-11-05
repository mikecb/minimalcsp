# Roadmap

Each phase builds on the one before it. Goals and design are in the [README](README.md#goals).

## Decisions

- **Detection:** use a headless browser and report-only collection. Static HTML parsing can't see fonts from CSS, requests made by scripts, or anything added at runtime, so it can't show that a policy works. Its job is limited to a quick first pass.
- **Sources:** tightness and ease of use should both hold for any deployment. Scripts are trusted by hash or nonce with `'strict-dynamic'`, not by URL. Other resources default to origins, with exact paths as an option.
- **Inline code:** hashes and nonces only. minimalcsp never emits `'unsafe-inline'`, including as a fallback for old browsers.
- **Inline event handlers and `style` attributes:** these can't be hashed without `'unsafe-hashes'`, so that stays off, and each one is reported as a blocker for the site to fix.
- **Audience:** a Go library first. The CLI and CI check are thin layers on top of it.
- **Browser dependency:** the headless collector lives in its own module, built on chromedp, so that library users don't depend on it.

- **External scripts:** servers use nonces, which have no limits. Static sites use hashes with `integrity` attributes, which Chrome 59, Firefox 116 and Safari 15.6 support. A hashed inline loader was the other option, and testing in Chrome ruled it out: scripts it loads miss `DOMContentLoaded` and run after later inline scripts, which breaks ordinary pages without any error. Scripts trusted by hash can't use `import`, because they're parser-inserted and nothing carries their trust to what they import, so those pages need nonces.
- **Nonces:** these go in templates. A filter that adds them to responses would also nonce injected scripts, so the library deliberately doesn't offer one.
- **`<meta>` policies:** the tag is checked enforced, because it has no report-only mode, so a page is tested the way it will really run. It goes after `<meta charset>`, which has to stay in the first 1024 bytes, and after `<head>`, since going above it loses the element's attributes. `Build` never emits the directives `<meta>` ignores, so the warning is about what the tag can't do, such as stopping framing. A tag doesn't suit nonces: a page with a server can set a header.
- **Reports are untrusted:** anyone can send one, so a report never adds a source that can run code. Scripts need a hash, which reports don't have, and `base-uri`, `object-src` and `worker-src` could all let an attacker run code. These become warnings, and anything else is a suggestion for a person to review.
- **Report delivery:** policies use `report-uri`, which the specification calls deprecated. Chrome ignores it when `report-to` is present, and `report-to` doesn't work on plain HTTP, so listing both loses every report on those pages. Testing in Chrome found this. Revisit if a browser drops `report-uri`.
- **Bypass warnings:** the list of hosts is short, and each JSONP and AngularJS entry was run in Chrome, because most of the JSONP endpoints in Google's CSP Evaluator are gone. Warnings cover what a source allows, so a whole host warns and an exact URL usually doesn't. Flash isn't covered, since browsers no longer run it, and neither are hosts that need `'unsafe-eval'`. A site that loads AngularJS itself isn't covered, because that's about the page, not the host.
- **Default:** policies trust scripts by hash, even though that means changing the page, because a policy that lists URLs doesn't meet the first goal. Listing URLs is still available as an explicit choice.

## Open questions

- **Modules on static sites:** should pages that use `import` get a loader just for their module scripts? Module scripts already run late, so the loader's ordering problems may not apply, and it works in Chrome. For now these pages need nonces.

## Phase 1: Fix known bugs (done)

Source detection (`GetSources`):

- [x] Report inline scripts as `script-src`, not `script`
- [x] Detect inline scripts that have attributes, such as `type`
- [x] Detect inline styles that have attributes, such as `media`
- [x] Check node types so text like `<p>script</p>` isn't treated as an element
- [x] Read `action` on `<form>`
- [x] Read `data` on `<object>`
- [x] Compare `rel` case-insensitively

Policy output (`MakePolicy`):

- [x] Remove duplicate sources
- [x] Group sources under one entry per directive
- [x] Separate directives with semicolons instead of printing a Go slice
- [x] Single-quote keywords

CLI:

- [x] Show usage instead of panicking when no URL is given
- [x] Fail on HTTP error statuses

## Phase 2: Library core (done)

The first version that produces a usable policy, for pages without runtime resources.

API:

- [x] Define public types for a policy, a finding and a blocker
- [x] Define a collector interface, so static, browser and report sources feed the same policy builder
- [x] Have policy generation return a value instead of printing, so the CLI handles output
- [x] Return errors from the library instead of calling `log.Fatal`

No `unsafe-inline`:

- [x] Replace the `unsafe-inline` marker in `GetSources` with the inline code itself
- [x] Update the tests that expect `unsafe-inline`
- [x] Generate `sha256` hashes for inline scripts and styles
- [x] Report inline event handlers, `style` attributes and `javascript:` URLs as blockers

Valid output:

- [x] Resolve relative URLs against the page's URL and `<base>` tag
- [x] Convert same-origin sources to `'self'`
- [x] Reduce other sources to origins by default, with exact paths as an option
- [x] Reduce `data:` URIs to the `data:` scheme, and warn when `data:` is allowed for scripts
- [x] Start from `default-src 'none'`, and set `base-uri`, `form-action` and `object-src` explicitly
- [x] Use `frame-src` for iframes
- [x] Check output against the CSP grammar in tests

## Phase 3: Headless browser (done)

This phase is what makes the "working" goal testable.

- [x] Choose a browser driver, such as chromedp, and settle the browser dependency question
- [x] Load pages under a deny-all report-only policy and collect violations
- [x] Collect network requests, including `connect-src` and `font-src` resources
- [x] Hash the inline code the browser actually ran
- [x] Verify a generated policy by loading the page with it and failing on any violation
- [x] Crawl multiple pages of a site and merge the results
- [x] Add optional scripted interactions, so resources behind clicks and logins are found

Keep the static parser small. Don't add `srcset`, preload or CSS parsing, since the browser finds all of those.

## Phase 4: Report-only collection (done)

This catches what a crawl misses: real users, real browsers and logged-in pages.

- [x] Add an `http.Handler` that receives `report-uri` and Reporting API reports
- [x] Build a policy from collected reports, keeping only violations that repeat
- [x] Filter out noise from browser extensions, other sites and one-off clients. Injected scripts can't be told apart, so they rely on the repeat count
- [x] Don't hash from reports, since they carry only a short sample of inline code
- [x] Suggest additions to an existing policy, with evidence for each one

## Phase 5: Any deployment (done)

- [x] Add nonce middleware for Go servers
- [x] Support `'strict-dynamic'`, and stop listing external scripts by URL by default
- [x] Hash external scripts, and add the `integrity` attributes they need
- [x] Output a header value, or a `<meta>` tag for static hosts that can't set headers, warning about what `<meta>` doesn't support
- [x] Document a rollout path: report-only first, then enforce
- [x] Warn about allowlisted hosts known to allow bypasses
- [x] Add setup examples for common servers and static hosts

## Phase 6: CLI and CI check

- [x] Add a CLI that generates a policy and verifies it
- [ ] Add a CLI command that verifies an existing policy
- [ ] Add a CLI command that reads stored reports and prints suggestions
- [ ] Merge the two CLIs, so one command works with or without a browser
- [ ] Add a CI check that fails when a page needs something the policy doesn't allow
- [ ] Have the CI check fail on new blockers too
- [ ] Publish a GitHub Action for the CI check

## Project housekeeping

These can happen at any time.

- [x] Add CI on Linux, Windows and macOS, with a local check script
- [x] Add merge gates on `master`
- [x] Add Dependabot for dependencies and actions
- [x] Replace the deprecated `io/ioutil`
- [x] Remove the `canvas` and `figure` branches, since those elements have no `src`
- [x] Remove `plugin-types`, `referrer` and `reflected-xss` from the directive notes, since they're no longer part of CSP
- [x] Rename `cli/` to `cmd/gencsp/` so `go install` produces a `gencsp` binary
- [x] Set up tagged releases, which the `browser` module needs before anyone can use it from outside this repository
