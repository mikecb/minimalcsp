# Roadmap

Each phase builds on the one before it. Goals and design are in the [README](README.md#goals).

## Decisions

- **Detection:** use a headless browser and report-only collection. Static HTML parsing can't see fonts from CSS, requests made by scripts, or anything added at runtime, so it can't show that a policy works. Its job is limited to a quick first pass.
- **Sources:** tightness and ease of use should both hold for any deployment. Scripts are trusted by hash or nonce with `'strict-dynamic'`, not by URL. Other resources default to origins, with exact paths as an option.
- **Inline code:** hashes and nonces only. minimalcsp never emits `'unsafe-inline'`, including as a fallback for old browsers.
- **Inline event handlers and `style` attributes:** these can't be hashed without `'unsafe-hashes'`, so that stays off, and each one is reported as a blocker for the site to fix.
- **Audience:** a Go library first. The CLI and CI check are thin layers on top of it.

## Open questions

- **External scripts on static sites:** with no server to issue nonces, how do they load without a URL allowlist? The proposal is a hashed inline loader with `'strict-dynamic'`. The alternative is hashing external scripts through `integrity` attributes where browsers support it. Until this is settled, they're listed by exact URL with a warning, because `'strict-dynamic'` makes browsers ignore URLs.
- **Browser dependency:** should the headless collector live in its own module, so that library users who don't need it avoid the dependency?

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

## Phase 3: Headless browser

This phase is what makes the "working" goal testable.

- [ ] Choose a browser driver, such as chromedp, and settle the browser dependency question
- [ ] Load pages under a deny-all report-only policy and collect violations
- [ ] Collect network requests, including `connect-src` and `font-src` resources
- [ ] Hash the inline code the browser actually ran
- [ ] Verify a generated policy by loading the page with it and failing on any violation
- [ ] Crawl multiple pages of a site and merge the results
- [ ] Add optional scripted interactions, so resources behind clicks and logins are found

Keep the static parser small. Don't add `srcset`, preload or CSS parsing, since the browser finds all of those.

## Phase 4: Report-only collection

This catches what a crawl misses: real users, real browsers and logged-in pages.

- [ ] Add an `http.Handler` that receives `report-uri` and Reporting API reports
- [ ] Build a policy from collected reports, keeping only violations that repeat
- [ ] Filter out noise from browser extensions and injected scripts
- [ ] Don't hash from reports, since they carry only a short sample of inline code
- [ ] Suggest additions to an existing policy, with evidence for each one

## Phase 5: Any deployment

- [ ] Add nonce middleware for Go servers
- [ ] Support `'strict-dynamic'`, and stop listing external scripts by URL
- [ ] Output a header value, or a `<meta>` tag for static hosts that can't set headers, warning about directives `<meta>` doesn't support
- [ ] Document a rollout path: report-only first, then enforce
- [ ] Warn about allowlisted hosts known to allow bypasses
- [ ] Add setup examples for common servers and static hosts

## Phase 6: CLI and CI check

- [ ] Add CLI commands to generate a policy and to verify one
- [ ] Add a CI check that fails when a page needs something the policy doesn't allow
- [ ] Have the CI check fail on new blockers too
- [ ] Publish a GitHub Action for the CI check

## Project housekeeping

These can happen at any time.

- [ ] Add CI that runs `go build`, `go vet` and `go test`
- [x] Replace the deprecated `io/ioutil`
- [x] Remove the `canvas` and `figure` branches, since those elements have no `src`
- [x] Remove `plugin-types`, `referrer` and `reflected-xss` from the directive notes, since they're no longer part of CSP
- [ ] Rename `cli/` to `cmd/gencsp/` so `go install` produces a `gencsp` binary
- [ ] Set up tagged releases once phase 2 is done
