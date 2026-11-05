// Package browser collects what a page needs by running it in headless Chrome,
// so it sees what static analysis can't: fonts from stylesheets, requests made
// by scripts, and anything added at runtime.
//
// It's a separate module so that users of the minimalcsp library don't depend
// on a browser. It needs Chrome or Chromium installed.
package browser

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"

	"github.com/mikecb/minimalcsp"
)

// denyAll makes the browser report everything a page does. 'report-sample'
// needs a source list that isn't 'none', and an empty list denies just the same.
const denyAll = "default-src 'none'; base-uri 'none'; form-action 'none'; " +
	"script-src 'report-sample'; style-src 'report-sample'"

const (
	world      = "minimalcsp"
	binding    = "__minimalcspReport"
	flushEvent = "__minimalcspFlush"
)

// recorderScript runs in an isolated world, so a page can't see it or stop it.
// The DOM misses scripts and styles that have been removed or that are in a
// shadow root, so it sends those when asked.
var recorderScript = fmt.Sprintf(`(() => {
	if (window !== window.top) return;
	const added = new Set();
	const send = (message) => window.%[1]s(JSON.stringify(message));
	const inline = 'script:not([src]), style';

	document.addEventListener('securitypolicyviolation', (e) => send({
		type: 'violation',
		directive: e.effectiveDirective,
		blocked: e.blockedURI,
		sample: e.sample,
		element: e.target && e.target.nodeType === Node.ELEMENT_NODE ? e.target.localName : '',
	}), true);

	document.addEventListener('error', (e) => {
		if (e.target.localName === 'script' && e.target.integrity) {
			send({type: 'violation', directive: 'integrity', blocked: e.target.src});
		}
	}, true);

	new MutationObserver((records) => {
		for (const record of records) {
			for (const node of record.addedNodes) {
				if (node.nodeType !== Node.ELEMENT_NODE) continue;
				if (node.matches(inline)) added.add(node);
				node.querySelectorAll(inline).forEach((n) => added.add(n));
			}
		}
	}).observe(document, {childList: true, subtree: true});

	const pierce = (root) => {
		for (const element of root.querySelectorAll('*')) {
			if (!element.shadowRoot) continue;
			element.shadowRoot.querySelectorAll(inline).forEach((n) => added.add(n));
			pierce(element.shadowRoot);
		}
	};

	document.addEventListener('%[2]s', () => {
		pierce(document);
		for (const node of added) {
			if (node.getRootNode() !== document) send({type: 'hidden', tag: node.localName, code: node.textContent});
		}
	});
})();`, binding, flushEvent)

// probe appends one timing line to the file named by PROBE_TRACE.
func probe(what string, since time.Time, detail string) {
	name := os.Getenv("PROBE_TRACE")
	if name == "" {
		return
	}
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s pid=%d %s %.3fs %s\n", time.Now().UTC().Format("15:04:05.000"), os.Getpid(), what, time.Since(since).Seconds(), detail)
}

var probeLogs atomic.Int64

// probeSlow marks that this process's current session had a slow navigation,
// so its net log is kept. Tests in a package run one at a time.
var probeSlow atomic.Bool

// Collector loads pages in headless Chrome. The zero value is ready to use.
type Collector struct {
	// Options adds to chromedp's default browser options, for example to set
	// the path to Chrome with chromedp.ExecPath. Chrome treats a rewritten page
	// as public, so to collect a site on a private network, turn off its
	// LocalNetworkAccessChecks feature. Otherwise the page's requests are blocked,
	// which shows up as warnings. Loopback addresses aren't affected.
	Options []chromedp.ExecAllocatorOption

	// Actions run on each page after it loads, to reach resources that need
	// interaction, such as a menu that loads content or a login form.
	Actions []chromedp.Action[chromedp.Void]

	// Timeout limits each page. It defaults to 30 seconds.
	Timeout time.Duration

	// Settle is how long a page must be idle to count as finished. It defaults
	// to 500 milliseconds.
	Settle time.Duration

	// MaxWait limits how long to wait for an idle page after it loads, since
	// some pages never stop making requests. It defaults to 5 seconds.
	MaxWait time.Duration
}

// Violation is something a page tried that a policy didn't allow.
type Violation struct {
	Directive  string // The directive that was violated, such as "img-src".
	BlockedURI string // A URL, or a keyword such as "inline" or "eval".
	Sample     string // The start of the blocked code, if the policy asks for one.
	Element    string // The element involved, if there is one.
	Page       string // The page it happened on.
}

func (v Violation) String() string {
	if v.Sample != "" {
		return fmt.Sprintf("%s blocked %s: %q", v.Directive, v.BlockedURI, v.Sample)
	}
	return fmt.Sprintf("%s blocked %s", v.Directive, v.BlockedURI)
}

// Collect loads pageURL and returns everything it needs.
func (c Collector) Collect(ctx context.Context, pageURL string) (*minimalcsp.Page, error) {
	browser, stop, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()
	return c.collect(browser, pageURL)
}

// Verify loads each page under policy and returns everything the policy would
// block. The policy is applied in report-only mode, so one blocked resource
// can't hide what would have depended on it.
//
// A policy containing minimalcsp.NoncePlaceholder uses the nonce from a page's
// own policy, so a page already serving nonces is checked as it is. On a page
// with no nonce, every script gets one, as if the templates had been updated.
func (c Collector) Verify(ctx context.Context, policy string, pageURLs ...string) ([]Violation, error) {
	return c.verify(ctx, policy, nil, pageURLs)
}

// VerifyPolicy is Verify for a policy from minimalcsp.Build. It also makes the
// changes the policy needs to the page, so it shows what will happen once those
// changes are made. A script that fails because of them has a Violation with
// the directive "integrity".
func (c Collector) VerifyPolicy(ctx context.Context, policy *minimalcsp.Policy, pageURLs ...string) ([]Violation, error) {
	return c.verify(ctx, policy.String(), policy.Apply, pageURLs)
}

// VerifyMeta loads each page with policy in a <meta> tag, as minimalcsp's
// ApplyMeta would leave it, and returns everything the policy blocked. <meta>
// has no report-only mode, so the policy is enforced: the page behaves as it
// will when deployed, but one blocked resource hides whatever depended on it.
// It doesn't suit a ByNonce policy.
func (c Collector) VerifyMeta(ctx context.Context, policy *minimalcsp.Policy, pageURLs ...string) ([]Violation, error) {
	sampled := withSamples(policy.String())
	return c.verify(ctx, "", func(document []byte, pageURL *url.URL) []byte {
		return minimalcsp.InsertMeta(policy.Apply(document, pageURL), sampled)
	}, pageURLs)
}

func (c Collector) verify(ctx context.Context, policy string, rewrite rewriter, pageURLs []string) ([]Violation, error) {
	browser, stop, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()
	var violations []Violation
	for _, pageURL := range pageURLs {
		loaded, err := c.load(browser, pageURL, withSamples(policy), rewrite)
		if err != nil {
			return nil, err
		}
		for _, v := range loaded.violations {
			v.Page = loaded.url
			violations = append(violations, v)
		}
	}
	return violations, nil
}

// Crawl collects startURL and the pages it links to on the same origin, up to
// maxPages in all. A page that fails after the first becomes a warning on the
// first page, so one broken link doesn't lose the rest of the crawl.
func (c Collector) Crawl(ctx context.Context, startURL string, maxPages int) ([]*minimalcsp.Page, error) {
	browser, stop, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()

	first, err := c.collect(browser, startURL)
	if err != nil {
		return nil, err
	}
	pages := []*minimalcsp.Page{first}
	visited := map[string]bool{withoutFragment(first.URL): true}
	queue := slices.Clone(first.Links)
	for len(queue) > 0 && len(pages) < maxPages {
		next := queue[0]
		queue = queue[1:]
		key := withoutFragment(next)
		if visited[key] || !sameOrigin(next, first.URL) {
			continue
		}
		visited[key] = true
		page, err := c.collect(browser, key)
		if err != nil {
			first.Warnings = append(first.Warnings, fmt.Sprintf("skipped %s: %v", key, err))
			continue
		}
		pages = append(pages, page)
		queue = append(queue, page.Links...)
	}
	return pages, nil
}

// withSamples adds 'report-sample' to what governs scripts and styles, so that
// violations show which code they're about. It doesn't change what's allowed.
func withSamples(policy string) string {
	directives := strings.Split(policy, ";")
	named := func(name string) int {
		return slices.IndexFunc(directives, func(d string) bool {
			fields := strings.Fields(d)
			return len(fields) > 0 && strings.EqualFold(fields[0], name)
		})
	}
	for _, name := range []string{"script-src", "style-src"} {
		i := named(name)
		if i < 0 {
			i = named("default-src")
		}
		if i >= 0 && !strings.Contains(directives[i], "'report-sample'") {
			directives[i] += " 'report-sample'"
		}
	}
	return strings.Join(directives, ";")
}

func withoutFragment(u *url.URL) string {
	stripped := *u
	stripped.Fragment = ""
	stripped.RawFragment = ""
	return stripped.String()
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

// start launches a browser, and returns a context for it and a way to stop it.
func (c Collector) start(ctx context.Context) (context.Context, context.CancelFunc, error) {
	opts := slices.Concat(chromedp.DefaultExecAllocatorOptions[:], c.Options)
	for _, flag := range strings.Fields(os.Getenv("PROBE_FLAGS")) {
		opts = append(opts, chromedp.Flag(flag, true))
	}
	var netLog string
	if dir := os.Getenv("PROBE_NETLOG"); dir != "" {
		netLog = fmt.Sprintf("%s/net-%d-%d.json", dir, os.Getpid(), probeLogs.Add(1))
		opts = append(opts, chromedp.Flag("log-net-log", netLog))
	}
	allocator, stopAllocator := chromedp.NewExecAllocator(ctx, opts...)
	browser, stopBrowser := chromedp.NewContext(allocator)
	stop := func() {
		began := time.Now()
		if netLog != "" {
			closing, cancel := context.WithTimeout(browser, 10*time.Second)
			chromedp.Cancel(closing)
			cancel()
		}
		stopBrowser()
		stopAllocator()
		probe("stop", began, "")
		if netLog != "" && !probeSlow.Swap(false) {
			os.Remove(netLog)
		}
	}
	began := time.Now()
	// The browser must start on a context with no per-page timeout, because
	// the context of the first run decides how long the browser lives.
	if err := chromedp.Do(browser); err != nil {
		stop()
		probe("start-failed", began, err.Error())
		return nil, nil, fmt.Errorf("starting Chrome: %w", err)
	}
	probe("start", began, "")
	return browser, stop, nil
}

// collect turns one page load into a Page.
func (c Collector) collect(browser context.Context, pageURL string) (*minimalcsp.Page, error) {
	loaded, err := c.load(browser, pageURL, denyAll, nil)
	if err != nil {
		return nil, err
	}
	final, err := url.Parse(loaded.url)
	if err != nil {
		return nil, err
	}
	// The DOM after running covers forms and inline code that static analysis
	// finds but that may never trigger a violation during a load.
	page, err := minimalcsp.Parse(strings.NewReader(loaded.html), final)
	if err != nil {
		return nil, err
	}
	page.Incomplete = false
	// The page as served holds the scripts it needs to trust directly. They
	// may have changed since, or a script may have removed them.
	served, err := servedScripts(loaded, final)
	if err != nil {
		return nil, err
	}
	page.Findings = append(page.Findings, served...)
	addViolations(page, loaded)
	markScripts(page, served, loaded.scripts)
	for _, blocked := range loaded.blocked {
		page.Warnings = append(page.Warnings,
			fmt.Sprintf("Chrome blocked %s, so anything that depends on it wasn't seen", blocked))
	}
	if loaded.busy {
		page.Warnings = append(page.Warnings,
			"this page was still making requests when collection stopped, so it may need more")
	}
	return page, nil
}

// servedScripts returns the scripts in the page as it was served.
func servedScripts(loaded *loadResult, final *url.URL) ([]minimalcsp.Finding, error) {
	body, err := charset.NewReader(bytes.NewReader(loaded.source), loaded.contentType)
	if err != nil {
		// An empty page is valid, but the reader has nothing to detect.
		return nil, nil
	}
	page, err := minimalcsp.Parse(body, final)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(page.Findings, func(f minimalcsp.Finding) bool {
		return f.Directive != "script-src"
	}), nil
}

// markScripts records which scripts other scripts added, and the hashes of the
// external scripts in the page as served.
func markScripts(page *minimalcsp.Page, served []minimalcsp.Finding, hashes map[string]string) {
	for i := range page.Findings {
		f := &page.Findings[i]
		if f.Directive != "script-src" {
			continue
		}
		match := slices.IndexFunc(served, func(s minimalcsp.Finding) bool {
			if f.URL == nil || s.URL == nil {
				return f.URL == nil && s.URL == nil && f.Code == s.Code
			}
			return withoutFragment(f.URL) == withoutFragment(s.URL)
		})
		f.Loaded = match < 0
		if f.Loaded || f.URL == nil {
			continue
		}
		// Violations don't carry an integrity attribute, so the page as served
		// decides. A page with its own hash needs that one in the policy.
		f.Hashes = served[match].Hashes
		if hash, ok := hashes[withoutFragment(f.URL)]; ok && len(f.Hashes) == 0 {
			f.Hashes = []string{hash}
		}
	}
}

// addViolations records what the browser saw that the DOM doesn't show.
func addViolations(page *minimalcsp.Page, loaded *loadResult) {
	var inline []Violation
	for _, v := range loaded.violations {
		switch {
		case v.Directive == "integrity":
			page.Warnings = append(page.Warnings,
				fmt.Sprintf("%s failed its integrity check or didn't load", v.BlockedURI))
		case v.Directive == "script-src-attr":
			addBlocker(page, minimalcsp.ReasonEventHandler, v)
		case v.Directive == "style-src-attr":
			addBlocker(page, minimalcsp.ReasonStyleAttribute, v)
		case v.BlockedURI == "eval" || v.BlockedURI == "wasm-eval":
			addBlocker(page, minimalcsp.ReasonEval, v)
		case v.BlockedURI == "inline" && strings.HasPrefix(v.Sample, "javascript:"):
			addBlocker(page, minimalcsp.ReasonJavaScriptURL, v)
		case v.BlockedURI == "inline":
			inline = append(inline, v)
		default:
			if finding, ok := findingFor(v); ok {
				page.Findings = append(page.Findings, finding)
			}
		}
	}

	// Hidden code counts only if the browser tried to run it, which rules out
	// data blocks and anything inert.
	for _, hidden := range loaded.hidden {
		directive := directiveFor(hidden.tag)
		if slices.ContainsFunc(inline, func(v Violation) bool {
			return baseDirective(v.Directive) == directive && matchesSample(hidden.code, v.Sample)
		}) {
			page.Findings = append(page.Findings, minimalcsp.Finding{Directive: directive, Code: hidden.code})
		}
	}

	for _, v := range inline {
		if !slices.ContainsFunc(page.Findings, func(f minimalcsp.Finding) bool {
			return f.URL == nil && f.Directive == baseDirective(v.Directive) && matchesSample(f.Code, v.Sample)
		}) {
			page.Warnings = append(page.Warnings,
				fmt.Sprintf("couldn't capture inline code starting %q, so the policy will block it", v.Sample))
		}
	}
}

// matchesSample reports whether code is what a violation's sample came from.
// Browsers trim the sample before cutting it to length.
func matchesSample(code, sample string) bool {
	return strings.HasPrefix(strings.TrimSpace(code), sample)
}

func directiveFor(tag string) string {
	if tag == "style" {
		return "style-src"
	}
	return "script-src"
}

// addBlocker records v unless the same code is already known. A sample is cut
// short, and it has no element if the page removed the element first.
func addBlocker(page *minimalcsp.Page, reason string, v Violation) {
	if slices.ContainsFunc(page.Blockers, func(b minimalcsp.Blocker) bool {
		return b.Reason == reason && strings.HasPrefix(b.Value, v.Sample)
	}) {
		return
	}
	page.Blockers = append(page.Blockers, minimalcsp.Blocker{Reason: reason, Element: v.Element, Value: v.Sample})
}

// baseDirective maps the browser's specific directives to the ones policies use.
func baseDirective(directive string) string {
	return strings.TrimSuffix(directive, "-elem")
}

// findingFor converts a violation for a resource into a Finding.
func findingFor(v Violation) (minimalcsp.Finding, bool) {
	directive := baseDirective(v.Directive)
	if !strings.HasSuffix(directive, "-src") && directive != "base-uri" && directive != "form-action" {
		return minimalcsp.Finding{}, false
	}
	// Browsers report some schemes as a bare word, such as "data".
	if !strings.Contains(v.BlockedURI, ":") {
		return minimalcsp.Finding{Directive: directive, URL: &url.URL{Scheme: v.BlockedURI}}, v.BlockedURI != ""
	}
	u, err := url.Parse(v.BlockedURI)
	if err != nil || !u.IsAbs() {
		return minimalcsp.Finding{}, false
	}
	return minimalcsp.Finding{Directive: directive, URL: u}, true
}

// loadResult is what one page load produced.
type loadResult struct {
	url        string
	html       string
	violations []Violation
	hidden     []hiddenNode
	blocked    []string // Requests Chrome refused, whatever the policy.
	busy       bool

	source      []byte            // The page as it was served.
	contentType string            // The page's Content-Type.
	scripts     map[string]string // Each script's hash expression, by URL.
}

// rewriter changes a page before the browser sees it.
type rewriter func(document []byte, pageURL *url.URL) []byte

// hiddenNode is a script or style outside the document's own tree.
type hiddenNode struct {
	tag, code string
}

// recorder collects events from one tab. Events arrive on chromedp's read
// loop, so anything that sends a command has to run in its own goroutine.
type recorder struct {
	ctx       context.Context
	mainFrame cdp.FrameID
	policy    string
	rewrite   rewriter

	mu       sync.Mutex
	status   int64
	pending  map[network.RequestID]string
	lastSeen time.Time
	result   loadResult

	navBegan time.Time
	sentOnce sync.Once
}

func (r *recorder) handle(ev any) {
	switch e := ev.(type) {
	case *fetch.EventRequestPaused:
		go r.intercept(e)
	case *runtime.EventBindingCalled:
		if e.Name == binding {
			r.message(e.Payload)
		}
	case *network.EventRequestWillBeSent:
		r.started(e.RequestID, e.Request.URL)
	case *network.EventLoadingFinished:
		r.finished(e.RequestID, "")
	case *network.EventLoadingFailed:
		r.finished(e.RequestID, blockedReason(e))
	}
}

// blockedReason returns why Chrome refused a request, if it did. Chrome reports
// local network blocks as CORS errors, but ordinary CORS errors say nothing
// about what a page needs.
func blockedReason(e *network.EventLoadingFailed) string {
	if e.BlockedReason != "" {
		return string(e.BlockedReason)
	}
	if e.CorsErrorStatus != nil && strings.Contains(string(e.CorsErrorStatus.CorsError), "LocalNetwork") {
		return string(e.CorsErrorStatus.CorsError)
	}
	return ""
}

func (r *recorder) started(id network.RequestID, url string) {
	r.sentOnce.Do(func() { probe("nav-request-sent", r.navBegan, "") })
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSeen = time.Now()
	r.pending[id] = url
}

func (r *recorder) finished(id network.RequestID, blocked string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSeen = time.Now()
	if blocked != "" {
		r.result.blocked = append(r.result.blocked, fmt.Sprintf("%s (%s)", r.pending[id], blocked))
	}
	delete(r.pending, id)
}

// idle reports whether nothing has happened on the page for d.
func (r *recorder) idle(d time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending) == 0 && time.Since(r.lastSeen) >= d
}

func (r *recorder) message(payload string) {
	var m struct {
		Type, Directive, Blocked, Sample, Element, Tag, Code string
	}
	if json.Unmarshal([]byte(payload), &m) != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSeen = time.Now()
	switch m.Type {
	case "violation":
		v := Violation{Directive: m.Directive, BlockedURI: m.Blocked, Sample: m.Sample, Element: m.Element}
		// Empty code loses nothing by being blocked, and clearing an element's
		// style counts as inline. Browsers can also repeat a report.
		empty := v.BlockedURI == "inline" && v.Sample == ""
		if !empty && !slices.Contains(r.result.violations, v) {
			r.result.violations = append(r.result.violations, v)
		}
	case "hidden":
		r.result.hidden = append(r.result.hidden, hiddenNode{m.Tag, m.Code})
	}
}

// intercept replaces the page's response with one carrying r.policy. Editing
// headers in place isn't enough, because Chrome reads a response's policy
// before DevTools can change it, so the page's own policy would stay in force.
// Responses with no body to rewrite, such as failures, carry on as they are.
// Scripts pass through here so that they can be hashed as the browser got them.
func (r *recorder) intercept(e *fetch.EventRequestPaused) {
	pass := func() {
		chromedp.Call(r.ctx, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: e.RequestID})
	}
	isPage := e.ResourceType == network.ResourceTypeDocument && e.FrameID == r.mainFrame
	if isPage {
		probe("nav-response-paused", r.navBegan, "")
	}
	if !isPage && e.ResourceType != network.ResourceTypeScript {
		pass()
		return
	}
	body, err := chromedp.Call(r.ctx, fetch.GetResponseBody, fetch.GetResponseBodyParams{RequestID: e.RequestID})
	if err != nil {
		pass()
		return
	}
	if !isPage {
		sum := sha256.Sum256(body.Body)
		r.mu.Lock()
		r.result.scripts[e.Request.URL] = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
		r.mu.Unlock()
		pass()
		return
	}
	r.mu.Lock()
	r.status = e.ResponseStatusCode
	r.result.source = body.Body
	r.result.contentType = headerValue(e.ResponseHeaders, "content-type")
	r.mu.Unlock()

	probe("nav-body", r.navBegan, "")
	document, policy := r.prepareResponse(e, body.Body)
	chromedp.Call(r.ctx, fetch.FulfillRequest, fetch.FulfillRequestParams{
		RequestID:       e.RequestID,
		ResponseCode:    e.ResponseStatusCode,
		ResponseHeaders: replaceHeaders(e.ResponseHeaders, policy),
		Body:            document,
	})
	probe("nav-fulfilled", r.navBegan, "")
}

// prepareResponse returns the page and policy to give the browser.
func (r *recorder) prepareResponse(e *fetch.EventRequestPaused, document []byte) ([]byte, string) {
	pageURL, err := url.Parse(e.Request.URL)
	if err != nil {
		return document, r.policy
	}
	if r.rewrite != nil {
		document = r.rewrite(document, pageURL)
	}
	if !strings.Contains(r.policy, minimalcsp.NoncePlaceholder) {
		return document, r.policy
	}
	nonce := pageNonce(e.ResponseHeaders)
	if nonce == "" {
		nonce = trialNonce
		document = minimalcsp.EditScriptTags(document, pageURL, func(*url.URL) []html.Attribute {
			return []html.Attribute{{Key: "nonce", Val: nonce}}
		})
	}
	return document, strings.ReplaceAll(r.policy, minimalcsp.NoncePlaceholder, nonce)
}

// trialNonce stands in for a real nonce when trying a page that has none.
const trialNonce = "bWluaW1hbGNzcC10cmlhbA"

var nonceSource = regexp.MustCompile(`'nonce-([^']+)'`)

// pageNonce returns the nonce in a page's own policy, if it has one.
func pageNonce(headers []*fetch.HeaderEntry) string {
	for _, name := range []string{"content-security-policy", "content-security-policy-report-only"} {
		if match := nonceSource.FindStringSubmatch(headerValue(headers, name)); match != nil {
			return match[1]
		}
	}
	return ""
}

func headerValue(headers []*fetch.HeaderEntry, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// replaceHeaders swaps the page's own policies for policy, in report-only mode.
func replaceHeaders(headers []*fetch.HeaderEntry, policy string) []*fetch.HeaderEntry {
	kept := []*fetch.HeaderEntry{{Name: "Content-Security-Policy-Report-Only", Value: policy}}
	for _, h := range headers {
		name := strings.ToLower(h.Name)
		if name != "content-security-policy" && name != "content-security-policy-report-only" {
			kept = append(kept, h)
		}
	}
	return kept
}

// load opens pageURL in a new tab under policy and records what happens.
func (c Collector) load(browser context.Context, pageURL, policy string, rewrite rewriter) (*loadResult, error) {
	timeout := cmp.Or(c.Timeout, 30*time.Second)
	if c.Timeout == 0 && os.Getenv("PROBE_TIMEOUT") != "" {
		timeout, _ = time.ParseDuration(os.Getenv("PROBE_TIMEOUT"))
	}
	limited, cancel := context.WithTimeout(browser, timeout)
	defer cancel()
	ctx, closeTab := chromedp.NewContext(limited)
	defer func() {
		began := time.Now()
		closeTab()
		probe("closetab", began, "")
	}()
	loadBegan, step := time.Now(), time.Now()
	lap := func(what string) {
		probe(what, step, "")
		step = time.Now()
	}
	defer func() { probe("load-total", loadBegan, pageURL) }()

	if err := chromedp.Do(ctx); err != nil {
		return nil, err
	}
	lap("newtab")
	tree, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil {
		return nil, err
	}
	r := &recorder{
		ctx:       ctx,
		mainFrame: tree.FrameTree.Frame.ID,
		policy:    policy,
		rewrite:   rewrite,
		pending:   map[network.RequestID]string{},
		lastSeen:  time.Now(),
		result:    loadResult{scripts: map[string]string{}},
	}
	if err := chromedp.Listen(ctx, r.handle); err != nil {
		return nil, err
	}
	if err := prepare(ctx); err != nil {
		return nil, err
	}
	lap("prepare")

	r.navBegan = time.Now()
	if err := chromedp.Do(ctx, chromedp.Navigate(pageURL)); err != nil {
		probeSlow.Store(true)
		lap("navigate-failed")
		return nil, fmt.Errorf("loading %s: %w", pageURL, err)
	}
	if time.Since(r.navBegan) > 5*time.Second {
		probeSlow.Store(true)
	}
	lap("navigate")
	r.mu.Lock()
	status := r.status
	r.mu.Unlock()
	if status >= 400 {
		return nil, fmt.Errorf("loading %s: status %d", pageURL, status)
	}
	if err := chromedp.Do(ctx, c.Actions...); err != nil {
		return nil, fmt.Errorf("running actions on %s: %w", pageURL, err)
	}
	busy := waitUntilIdle(ctx, r, cmp.Or(c.Settle, 500*time.Millisecond), cmp.Or(c.MaxWait, 5*time.Second))

	if _, err := chromedp.Run(ctx, chromedp.Evaluate[bool](fmt.Sprintf(`document.dispatchEvent(new Event(%q))`, flushEvent))); err != nil {
		return nil, err
	}
	final, err := chromedp.Run(ctx, chromedp.Evaluate[string](`location.href`))
	if err != nil {
		return nil, err
	}
	html, err := chromedp.Run(ctx, chromedp.Evaluate[string](`document.documentElement.outerHTML`))
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.result
	result.url, result.html, result.busy = final, html, busy
	return &result, nil
}

// prepare sets up a tab to record a page before it navigates.
func prepare(ctx context.Context) error {
	if _, err := chromedp.Call(ctx, network.Enable, network.EnableParams{}); err != nil {
		return err
	}
	if _, err := chromedp.Call(ctx, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{
		{ResourceType: network.ResourceTypeDocument, RequestStage: fetch.RequestStageResponse},
		{ResourceType: network.ResourceTypeScript, RequestStage: fetch.RequestStageResponse},
	}}); err != nil {
		return err
	}
	if _, err := chromedp.Call(ctx, runtime.AddBinding, runtime.AddBindingParams{
		Name:                 binding,
		ExecutionContextName: world,
	}); err != nil {
		return err
	}
	_, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{
		Source:    recorderScript,
		WorldName: world,
	})
	return err
}

// waitUntilIdle waits for in-flight requests to finish, which a fixed delay
// can't do: a slow stylesheet would hide the fonts it loads. It reports whether
// the page was still busy when maxWait ran out.
func waitUntilIdle(ctx context.Context, r *recorder, settle, maxWait time.Duration) (busy bool) {
	deadline := time.Now().Add(maxWait)
	for !r.idle(settle) {
		if time.Now().After(deadline) {
			return true
		}
		select {
		case <-ctx.Done():
			return true
		case <-time.After(20 * time.Millisecond):
		}
	}
	return false
}
