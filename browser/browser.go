// Package browser collects what a page needs by running it in headless Chrome,
// so it sees what static analysis can't: fonts from stylesheets, requests made
// by scripts, and anything added at runtime.
//
// It's a separate module so that users of the minimalcsp library don't depend
// on a browser. It needs Chrome or Chromium installed.
package browser

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

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
func (c Collector) Verify(ctx context.Context, policy string, pageURLs ...string) ([]Violation, error) {
	browser, stop, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()
	var violations []Violation
	for _, pageURL := range pageURLs {
		loaded, err := c.load(browser, pageURL, withSamples(policy))
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
	allocator, stopAllocator := chromedp.NewExecAllocator(ctx, opts...)
	browser, stopBrowser := chromedp.NewContext(allocator)
	stop := func() {
		stopBrowser()
		stopAllocator()
	}
	// The browser must start on a context with no per-page timeout, because
	// the context of the first run decides how long the browser lives.
	if err := chromedp.Do(browser); err != nil {
		stop()
		return nil, nil, fmt.Errorf("starting Chrome: %w", err)
	}
	return browser, stop, nil
}

// collect turns one page load into a Page.
func (c Collector) collect(browser context.Context, pageURL string) (*minimalcsp.Page, error) {
	loaded, err := c.load(browser, pageURL, denyAll)
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
	addViolations(page, loaded)
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

// addViolations records what the browser saw that the DOM doesn't show.
func addViolations(page *minimalcsp.Page, loaded *loadResult) {
	var inline []Violation
	for _, v := range loaded.violations {
		switch {
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
}

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

	mu       sync.Mutex
	status   int64
	pending  map[network.RequestID]string
	lastSeen time.Time
	result   loadResult
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
func (r *recorder) intercept(e *fetch.EventRequestPaused) {
	pass := func() {
		chromedp.Call(r.ctx, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: e.RequestID})
	}
	if e.FrameID != r.mainFrame {
		pass()
		return
	}
	body, err := chromedp.Call(r.ctx, fetch.GetResponseBody, fetch.GetResponseBodyParams{RequestID: e.RequestID})
	if err != nil {
		pass()
		return
	}
	r.mu.Lock()
	r.status = e.ResponseStatusCode
	r.mu.Unlock()
	chromedp.Call(r.ctx, fetch.FulfillRequest, fetch.FulfillRequestParams{
		RequestID:       e.RequestID,
		ResponseCode:    e.ResponseStatusCode,
		ResponseHeaders: replaceHeaders(e.ResponseHeaders, r.policy),
		Body:            body.Body,
	})
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
func (c Collector) load(browser context.Context, pageURL, policy string) (*loadResult, error) {
	timeout := cmp.Or(c.Timeout, 30*time.Second)
	limited, cancel := context.WithTimeout(browser, timeout)
	defer cancel()
	ctx, closeTab := chromedp.NewContext(limited)
	defer closeTab()

	if err := chromedp.Do(ctx); err != nil {
		return nil, err
	}
	tree, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil {
		return nil, err
	}
	r := &recorder{
		ctx:       ctx,
		mainFrame: tree.FrameTree.Frame.ID,
		policy:    policy,
		pending:   map[network.RequestID]string{},
		lastSeen:  time.Now(),
	}
	if err := chromedp.Listen(ctx, r.handle); err != nil {
		return nil, err
	}
	if err := prepare(ctx); err != nil {
		return nil, err
	}

	if err := chromedp.Do(ctx, chromedp.Navigate(pageURL)); err != nil {
		return nil, fmt.Errorf("loading %s: %w", pageURL, err)
	}
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
	if _, err := chromedp.Call(ctx, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{{
		ResourceType: network.ResourceTypeDocument,
		RequestStage: fetch.RequestStageResponse,
	}}}); err != nil {
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
