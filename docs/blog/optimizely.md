# Stopping a poisoned third-party script

*18 November 2026*

On 16 November, attackers changed the Optimizely snippets of about 178 organizations, including the BBC, CNN, Zoom, HSBC and IKEA. For about 16 hours, visitors to those sites ran code that stole card numbers and cookies, swapped cryptocurrency addresses, and sent exploit kits to iPhones. [Report URI](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/) and [StepSecurity](https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer) have the details.

The code arrived in the same file, at the same URL, that each site already loaded. So a Content Security Policy that allows `cdn.optimizely.com` did nothing, and neither did a nonce on the script tag. What mattered was everything else the policy allowed. Report URI checked 256 affected sites. 24 had a policy that blocked the payload, and 17 more blocked only the theft. 68 had no policy at all, and 50 had one that let everything through.

This post shows what a policy from minimalcsp does against that kind of attack, where it falls short, and how to set one up. The tests found gaps in minimalcsp too, which are now on the [roadmap](../../TODO.md#phase-7-compromised-third-party-scripts).

## What the attack needed

The injected code did four things, and each needs something from the policy:

| Step | What it did | What it needs |
|---|---|---|
| Load the payload | Added a script tag for `track.js` on the attacker's domain | That domain in `script-src`, or `'strict-dynamic'` |
| Fall back | Ran an inline copy of the payload through `eval` if the domain was blocked | `'unsafe-eval'` |
| Send data out | Posted cards, cookies and screenshots to the attacker's domain | That domain in `connect-src` |
| Target iPhones | Added more scripts and a hidden iframe | `script-src` and `frame-src` |

It also swapped cryptocurrency addresses in the page. That needs no request at all, so no policy stops it once the code is running.

## Testing it

The test is a page on one local origin that loads a vendor script from a second, with an attacker on a third. The vendor script changes a headline, as an experiment would, and sends an event back to the vendor. `gencsp` generated a policy for the clean page in each mode. Then the vendor script was poisoned in two ways, and the page was loaded in Chrome 158 with each policy enforced:

- **Like Optimizely:** the script adds a second script from the attacker, with an `eval` fallback. The payload sends data out, adds a hidden iframe, and swaps an address in the page.
- **Quieter:** the whole payload sits in the vendor script, with no second script and no `eval`.

The page came in two versions. In one, the clean vendor script adds another script of its own, as most tag tools do, so the policy needs `'strict-dynamic'`.

| Policy | Like Optimizely | Quieter |
|---|---|---|
| None | Everything works | Everything works |
| `hash` | Vendor script blocked, nothing runs | Vendor script blocked, nothing runs |
| `nonce` | Payload blocked | Address swapped, nothing sent |
| `nonce` with `'strict-dynamic'` | Address swapped, nothing sent | Address swapped, nothing sent |
| `url` | Payload blocked | Address swapped, nothing sent |

Three things stand out:

- **Nothing left the page under any policy.** Policies start from `default-src 'none'` and list only what the page was seen to use, so the attacker's domain isn't in `connect-src` or `frame-src`.
- **Only `hash` stops the code from running.** The script's `integrity` attribute no longer matches, so the browser refuses it. The cost is that the experiment stops too, and the same happens every time the vendor makes a legitimate change.
- **`'strict-dynamic'` is the weak spot.** It lets a trusted script load others from anywhere, which is what the attack's first step did.

minimalcsp never emits `'unsafe-eval'`, so the fallback failed in every mode.

## What the affected sites look like today

`gencsp` also ran against the home pages of eleven affected sites on 18 November, after the cleanup, from a data center and without accepting any cookie banners. The attack itself wasn't there to observe.

| Site | Result |
|---|---|
| BBC | `nonce` policy verified. 6 `style` attributes to fix |
| GitLab | `nonce` policy verified. 16 `style` attributes and an event handler to fix |
| HSBC UK | `nonce` policy verified. 11 `style` attributes to fix |
| IKEA US | `nonce` policy verified. 3 uses of `eval` and 32 `style` attributes to fix |
| Vodafone Australia | 15 uses of `eval` to fix, and 2 violations when verifying |
| Zoom | 3 uses of `eval` to fix, and 17 violations when verifying |
| Fox News | 51 uses of `eval` to fix, and 10 violations when verifying |
| CNN | Sent headless Chrome a page of plain text |
| Salesforce, Scheels | Refused headless Chrome with status 403 |
| KLM | The connection failed |

- **Every policy needed `'strict-dynamic'`.** All seven sites that got a `hash` or `nonce` policy have scripts that load other scripts. Against this attack, those policies would have stopped the theft but not the payload.
- **Four of seven call `eval` on their home page.** Those calls have to go before the site can drop `'unsafe-eval'`, which is what let the fallback run at HSBC during the attack.
- **`hash` verified only on the BBC.** Elsewhere it found violations, such as scripts it couldn't hash, or ran out of time. Most large sites can't hash everything.
- **Only IKEA still loaded Optimizely**, from its own domain at `/ext/optimizelyjs/`. A snippet copied from Optimizely on every request is as exposed as the original, and a policy sees it as `'self'`.

The policies are short. HSBC's allows four sources in `connect-src`, and IKEA's allows seven. That list is what stood between the payload and a card number.

## Setting it up

**1. Generate a policy and send it in report-only mode.** [Rolling out a policy](../../README.md#rolling-out-a-policy) has the full steps.

```bash
gencsp -scripts nonce -pages 20 -report-to /csp-reports https://example.com
```

**2. Fix every `blocked: eval` line.** A policy that needs `'unsafe-eval'` lets a poisoned script run anything.

**3. Check whether the policy has `'strict-dynamic'`.** If it does, a poisoned script can load a second one. Find the scripts that need it, and ask whether each could load what it needs from your page instead.

**4. Keep vendor scripts off pages that take payments or passwords.** If one has to be there, serve a reviewed copy from your own site and use `hash`, so it changes only when you deploy:

```bash
gencsp -scripts hash https://example.com/checkout
```

**5. Read the `connect-src` list.** Every host on it is somewhere a poisoned script can send data. Remove what you don't need.

**6. Watch for changes.** Keep `report-uri` in the enforced policy. A sudden run of reports for a host you've never seen is what this attack looked like from the inside. You can also run `gencsp verify` against the live site on a schedule:

```bash
gencsp verify -pages 20 https://example.com
```

In the test, this failed as soon as the vendor script was poisoned, with lines such as:

```text
violation: http://127.0.0.1:8001/: script-src-elem blocked http://127.0.0.1:8003/track.js
violation: http://127.0.0.1:8001/: connect-src blocked http://127.0.0.1:8003/hit.php
```

## What a policy can't do

- **It can't stop changes inside the page.** Under `nonce`, a poisoned script can still rewrite what visitors see, such as a payment address.
- **It can't stop data going to a host you allow.** If `connect-src` lists an analytics service, a poisoned script can send data to the attacker's account there.
- **It can't stop navigation.** A script can send the visitor to another site with data in the URL.
- **It only covers pages that send it.** A crawl misses pages behind a login unless you add `Actions`.

A policy narrows what an attacker can do with a script you trusted. The scripts you trust still matter, and the fewest should run where the most is at stake.

## What minimalcsp gets wrong today

Running it against these sites turned up problems, all now on the [roadmap](../../TODO.md#phase-7-compromised-third-party-scripts):

- It adds `'strict-dynamic'` without saying which script needs it, or that a third-party one does.
- It can't mix modes, so you can't hash one vendor script and use nonces for the rest.
- `gencsp` has no timeout flag. Five of the eleven home pages needed more than the 30 second default, which only the library can change.
- `gencsp verify` doesn't report requests that Chrome itself blocks, so a page whose scripts never ran can pass.
- It warns about risky hosts in `script-src`, but not in `connect-src`.
