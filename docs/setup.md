# Setting up a policy

`gencsp` prints a policy. This page shows where to put it on common servers and static hosts. For the order to do things in, see [Rolling out a policy](../README.md#rolling-out-a-policy).

The examples send the policy in report-only mode, so nothing gets blocked. To enforce it, change the header's name to `Content-Security-Policy`. Replace `POLICY` with what `gencsp` printed.

| Host | How to send the header | Nonces | How it was tested |
|---|---|---|---|
| [nginx](#nginx) | `add_header` | From your application | Run on nginx 1.24 |
| [Apache](#apache) | `Header` | From your application | Run on Apache 2.4 |
| [Caddy](#caddy) | `header` | From your application | Run on Caddy 2.11 |
| [Netlify](#netlify) | `_headers` file | No | With Netlify's parser, not on Netlify |
| [Cloudflare Pages](#cloudflare-pages) | `_headers` file | No | With wrangler's local server, not on Cloudflare |
| [Vercel](#vercel) | `vercel.json` | No | With Vercel's config library, not on Vercel |
| [Amazon CloudFront](#amazon-cloudfront) | Response headers policy | No | Not tested, written from AWS's documentation |
| [GitHub Pages](#github-pages) | None, so use a `<meta>` tag | No | Tag checked in Chrome, not on GitHub Pages |
| [Node.js](#nodejs-with-nonces) | Your application | Yes | Run with Express in Chrome |

"Run" means the server sent the policy byte for byte, using a policy with hashes, keywords and an escaped URL.

A static host sends the same response to everyone, so a nonce can't change per response. Use `hash`, the default, on those hosts.

## Static sites

Under `hash`, the policy and the page have to match. Regenerate them together in your build, then deploy both at once. This step crawls a preview of the built site, adds the `integrity` attributes to each page, and writes the policy to a file for your host:

```go
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mikecb/minimalcsp"
	"github.com/mikecb/minimalcsp/browser"
)

func main() {
	const site, preview = "dist", "http://localhost:8000/"

	var collector browser.Collector
	pages, err := collector.Crawl(context.Background(), preview, 100)
	if err != nil {
		log.Fatal(err)
	}
	policy := minimalcsp.Build(minimalcsp.Merge(pages...), minimalcsp.Options{})

	// A page's path is the same in the preview and in the build.
	for _, page := range pages {
		file := filepath.Join(site, filepath.FromSlash(page.URL.Path))
		if strings.HasSuffix(page.URL.Path, "/") {
			file = filepath.Join(file, "index.html")
		}
		document, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(file, policy.Apply(document, page.URL), 0o644); err != nil {
			log.Fatal(err)
		}
	}

	headers := "/*\n  Content-Security-Policy-Report-Only: " + policy.String() + "\n"
	if err := os.WriteFile(filepath.Join(site, "_headers"), []byte(headers), 0o644); err != nil {
		log.Fatal(err)
	}
}
```

This writes a `_headers` file, for Netlify and Cloudflare Pages. For another host, write the policy wherever that host reads it from. The preview has to serve the build from its root, so that each page's path matches its file. This example ignores `policy.Warnings` and `policy.Blockers`, so log them in a real build, or fail it.

## nginx

```nginx
server {
    listen 80;
    root /var/www/site;

    add_header Content-Security-Policy-Report-Only "POLICY" always;
}
```

`always` sends the header on error pages too.

A `location` with an `add_header` of its own loses every `add_header` from the `server` block, so it has to repeat this one. Keep the line in a file and `include` it in both places.

Don't use `sub_filter` to add nonces to scripts. It would add one to every script in the page, including one an attacker managed to inject, which defeats the policy. If your application sets nonces, let it send the header too, and nginx passes it through.

## Apache

```apache
Header always set Content-Security-Policy-Report-Only "POLICY"
```

This needs `mod_headers`, which `a2enmod headers` turns on where that command exists.

Apache gives `%` a meaning in this line, so write any `%` in the policy as `%%`. A URL with an escaped character can put one there, and without the change Apache refuses to start, with `Unrecognized header format`.

## Caddy

```caddyfile
example.com {
    root * /var/www/site
    file_server

    header Content-Security-Policy-Report-Only "POLICY"
}
```

## Netlify

Put a file named `_headers` in the folder you deploy:

```text
/*
  Content-Security-Policy-Report-Only: POLICY
```

Netlify only adds these headers to files it serves itself, not to proxied content or anything from a function.

## Cloudflare Pages

Put a file named `_headers` in the folder you deploy:

```text
/*
  Content-Security-Policy-Report-Only: POLICY
```

Cloudflare limits each line of this file to 2,000 characters, including the header's name, so a long policy won't fit. The headers don't apply to responses from Pages Functions.

## Vercel

Add this to `vercel.json`:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Content-Security-Policy-Report-Only", "value": "POLICY" }
      ]
    }
  ]
}
```

A policy has no double quotes or backslashes, so it needs no escaping here.

## Amazon CloudFront

S3 can't set this header, so a site on S3 needs CloudFront in front of it, with a response headers policy. CloudFront limits the value to 1,783 characters.

To enforce a policy, set it in `SecurityHeadersConfig`:

```yaml
ResponseHeadersPolicyConfig:
  Name: content-security-policy
  SecurityHeadersConfig:
    ContentSecurityPolicy:
      ContentSecurityPolicy: "POLICY"
      Override: true
```

This is the input for `aws cloudfront create-response-headers-policy --cli-input-yaml`. Attach the policy it creates to the distribution's cache behavior.

CloudFront has no field for report-only mode, so that header would have to go in `CustomHeadersConfig`. The pages of AWS's documentation checked for this don't say whether that's allowed, and it hasn't been tried.

## GitHub Pages

GitHub Pages can't set response headers, so use a tag. See [Hosts that can't set headers](../README.md#hosts-that-cant-set-headers). A tag can't run in report-only mode, so check the site with `gencsp -meta` first.

## Node.js with nonces

Any application server works the same way. Make a new random nonce for each response, put it in the header in place of `{nonce}`, and give it to every script in your templates. Print the policy with `gencsp -scripts nonce`.

```js
import crypto from "node:crypto";
import express from "express";

const policy = process.env.CSP_POLICY;
const app = express();

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  res.set("Content-Security-Policy-Report-Only", policy.replaceAll("{nonce}", res.locals.nonce));
  res.set("Cache-Control", "no-store");
  next();
});

app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send(`<!doctype html><script nonce="${res.locals.nonce}" src="/app.js"></script>`);
});

app.listen(3000);
```

A cached page repeats its nonce, so an attacker could learn it. That's why these pages can't be cached. For Go, use [`NonceMiddleware`](../README.md#nonces-on-a-go-server).

## Collecting reports for a static site

A static host has nowhere to run a [`ReportHandler`](../README.md#collecting-reports), but the endpoint can be on another origin. This runs on any machine that can take a request, and keeps each report as a line of JSON:

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/mikecb/minimalcsp"
)

func main() {
	file, err := os.OpenFile("reports.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var mu sync.Mutex
	encoder := json.NewEncoder(file)
	handler := minimalcsp.ReportHandler{Receive: func(report minimalcsp.Report) {
		mu.Lock()
		defer mu.Unlock()
		if err := encoder.Encode(report); err != nil {
			log.Print(err)
		}
	}}
	log.Fatal(http.ListenAndServe(":8080", handler))
}
```

Put it behind HTTPS, and rate-limit it. Then print the policy with `gencsp -report-to https://reports.example.com/`.

To review the reports, decode each line into a `minimalcsp.Report`, pass it to `Tally.Add`, and call `Tally.Suggest`.
