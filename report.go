package minimalcsp

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// ErrReportType means a body isn't in either format browsers report in.
var ErrReportType = errors.New("minimalcsp: unknown report format")

// sampleLimit is how much code browsers send, which also limits what a forged
// report can make anyone store or read.
const sampleLimit = 40

// maxReportBody limits one request. A Reporting API batch holds many reports.
const maxReportBody = 1 << 20

// Report is one violation a browser reported. Anyone can send a report, so
// treat every field as untrusted. Queries and fragments are removed from URLs,
// since they can hold session tokens and other private data.
type Report struct {
	Page      string // The page the violation happened on.
	Directive string // The directive that blocked it, such as "img-src".
	Blocked   string // The URL, or a keyword such as "inline" or "eval".
	Sample    string // The start of the blocked code, if the policy asks for one.
	Source    string // The file that caused the violation, if known.
	Client    string // Identifies who sent it, without revealing them.
}

// ParseReports reads a request body in either format browsers use:
// application/csp-report from report-uri, or application/reports+json from
// report-to.
func ParseReports(body []byte, contentType string) ([]Report, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReportType, err)
	}
	switch mediaType {
	case "application/csp-report", "application/json":
		var wrapper struct {
			Report struct {
				DocumentURI        string `json:"document-uri"`
				EffectiveDirective string `json:"effective-directive"`
				ViolatedDirective  string `json:"violated-directive"`
				BlockedURI         string `json:"blocked-uri"`
				ScriptSample       string `json:"script-sample"`
				SourceFile         string `json:"source-file"`
			} `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &wrapper); err != nil {
			return nil, err
		}
		r := wrapper.Report
		// Some browsers only send this one, with the sources after the name.
		directive, _, _ := strings.Cut(r.ViolatedDirective, " ")
		return []Report{newReport(r.DocumentURI, cmp.Or(r.EffectiveDirective, directive), r.BlockedURI, r.ScriptSample, r.SourceFile)}, nil
	case "application/reports+json":
		var batch []struct {
			Type string          `json:"type"`
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, err
		}
		var reports []Report
		for _, entry := range batch {
			// The same endpoint can receive other kinds, such as deprecations.
			if entry.Type != "csp-violation" {
				continue
			}
			var r struct {
				DocumentURL        string `json:"documentURL"`
				EffectiveDirective string `json:"effectiveDirective"`
				BlockedURL         string `json:"blockedURL"`
				Sample             string `json:"sample"`
				SourceFile         string `json:"sourceFile"`
			}
			if err := json.Unmarshal(entry.Body, &r); err != nil {
				return nil, err
			}
			reports = append(reports, newReport(r.DocumentURL, r.EffectiveDirective, r.BlockedURL, r.Sample, r.SourceFile))
		}
		return reports, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrReportType, mediaType)
}

func newReport(page, directive, blocked, sample, source string) Report {
	if code := []rune(sample); len(code) > sampleLimit {
		sample = string(code[:sampleLimit])
	}
	return Report{
		Page:      withoutQuery(page),
		Directive: directive,
		Blocked:   withoutQuery(blocked),
		Sample:    sample,
		Source:    withoutQuery(source),
	}
}

// withoutQuery returns a URL without anything private. Keywords pass through,
// and a URL with no host, such as a data: URL, becomes its scheme, which is what
// some browsers send anyway.
func withoutQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme == "" {
		return raw
	}
	if u.Opaque != "" {
		return u.Scheme
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
	return u.String()
}

// ReportHandler receives reports from browsers in either format. Use it as the
// endpoint for Policy.ReportingTo. It answers cross-origin preflights, so it can
// serve other origins, but it doesn't limit how fast clients send, which is left
// to the server in front of it.
type ReportHandler struct {
	// Receive is called with each report, such as with a Tally's Add. It can be
	// called from several requests at once.
	Receive func(Report)

	// ClientID identifies who sent a request, which is how a Tally tells many
	// clients from one client sending many reports. It defaults to the network
	// address, so set it behind a proxy, or every report seems to come from the
	// proxy and nothing ever repeats. The result is hashed before it's stored.
	ClientID func(*http.Request) string
}

func (h ReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "reports are sent by POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReportBody))
	if err != nil {
		http.Error(w, "couldn't read the report", http.StatusRequestEntityTooLarge)
		return
	}
	reports, err := ParseReports(body, r.Header.Get("Content-Type"))
	if errors.Is(err, ErrReportType) {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	if err != nil {
		http.Error(w, "couldn't parse the report", http.StatusBadRequest)
		return
	}
	identify := h.ClientID
	if identify == nil {
		identify = clientNetwork
	}
	client := hashClient(identify(r))
	for _, report := range reports {
		report.Client = client
		h.Receive(report)
	}
	w.WriteHeader(http.StatusNoContent)
}

// clientNetwork returns the address of r's sender. One IPv6 customer usually
// gets a whole /64, so anything smaller would let them count as many clients.
func clientNetwork(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if addr.Is6() {
		network, _ := addr.Prefix(64)
		return network.String()
	}
	return addr.String()
}

// clientKey changes when the process starts, so stored IDs can't be reversed by
// hashing every address.
var clientKey = func() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}()

func hashClient(client string) string {
	mac := hmac.New(sha256.New, clientKey)
	mac.Write([]byte(client))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil)[:12])
}

// tallyLimit and clientLimit bound what a flood of forged reports can use.
// Reaching clientLimit doesn't lose anything, since it's far past any threshold.
const (
	tallyLimit  = 10000
	clientLimit = 1000
)

// evidenceLimit is how many examples to keep for each thing reported.
const evidenceLimit = 5

// Tally counts reports for one site and works out which of them repeat. It
// filters out what real pages don't need: anything from a browser extension, on
// a page outside the site, or from too few clients.
//
// Reports aren't authenticated, so someone who controls enough clients can make
// anything repeat. A Tally never turns a report into a source that can run code.
// Those become warnings, because a script needs its hash, which reports don't
// have. Review anything else before deploying it. A source an attacker added
// could still let them send data out.
//
// A Tally is safe for concurrent use. It keeps everything in memory, so to keep
// reports past a restart, or to combine servers, store them from
// ReportHandler.Receive and pass them to Add later.
type Tally struct {
	// Site is the site's URL. Only reports from pages on its origin count.
	Site *url.URL

	// MinClients is how many clients have to report something for it to count.
	// It defaults to 3. Raise it for a busy site, where a few people with the
	// same extension could otherwise reach it.
	MinClients int

	// ExactPaths counts and lists resources by URL rather than by origin, as
	// Options.ExactPaths does.
	ExactPaths bool

	mu      sync.Mutex
	entries map[tallyKey]*tallyEntry
	dropped int
}

type tallyKey struct {
	directive string
	target    string // The source that would allow it, or the code's identity.
}

type tallyEntry struct {
	url     *url.URL // The first URL reported, or nil for inline code.
	blocked string
	sample  string
	reports int
	clients map[string]struct{}
	pages   []string
	urls    []string
}

// Add counts a report, unless it's noise.
func (t *Tally) Add(r Report) {
	key, entry, ok := t.classify(r)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	existing, found := t.entries[key]
	if !found {
		if len(t.entries) >= tallyLimit {
			t.dropped++
			return
		}
		if t.entries == nil {
			t.entries = map[tallyKey]*tallyEntry{}
		}
		entry.clients = map[string]struct{}{}
		t.entries[key] = entry
		existing = entry
	}
	existing.reports++
	if len(existing.clients) < clientLimit {
		existing.clients[r.Client] = struct{}{}
	}
	existing.pages = addEvidence(existing.pages, r.Page)
	existing.urls = addEvidence(existing.urls, r.Blocked)
}

func addEvidence(list []string, item string) []string {
	if len(list) >= evidenceLimit || slices.Contains(list, item) {
		return list
	}
	return append(list, item)
}

// extensionSchemes are what browsers use for code from extensions.
var extensionSchemes = []string{"chrome-extension", "moz-extension", "safari-extension", "safari-web-extension", "ms-browser-extension"}

func fromExtension(value string) bool {
	scheme, _, _ := strings.Cut(value, ":")
	return slices.Contains(extensionSchemes, scheme)
}

// resourceDirectives are the directives a report can add a source to.
var resourceDirectives = []string{"connect-src", "font-src", "form-action", "frame-src", "img-src", "manifest-src", "media-src", "style-src"}

// codeDirectives govern what runs code, so a forged report mustn't add to them.
var codeDirectives = []string{"base-uri", "object-src", "script-src", "worker-src"}

// reportedSource matches what's safe to put in a policy. Reports are forged
// easily and URL parsing is lenient, so without this a blocked URL could carry
// a semicolon and whole new directives with it.
var reportedSource = regexp.MustCompile(`^('self'|data:|blob:|(https?|wss?)://[a-z0-9.-]+(:[0-9]+)?(/[^\s;,]*)?)$`)

// classify returns where a report belongs, or false if it's noise.
func (t *Tally) classify(r Report) (tallyKey, *tallyEntry, bool) {
	none := tallyKey{}
	page, err := url.Parse(r.Page)
	if err != nil || t.Site == nil || origin(page) != origin(t.Site) || fromExtension(r.Source) {
		return none, nil, false
	}
	directive := strings.TrimSuffix(r.Directive, "-elem")
	entry := &tallyEntry{blocked: r.Blocked, sample: r.Sample}
	switch r.Blocked {
	case "inline", "eval", "wasm-eval":
		switch directive {
		case "script-src", "script-src-attr", "style-src", "style-src-attr":
			return tallyKey{directive, r.Blocked + " " + r.Sample}, entry, true
		}
		return none, nil, false
	}
	if !slices.Contains(resourceDirectives, directive) && !slices.Contains(codeDirectives, directive) {
		return none, nil, false
	}
	u, err := url.Parse(r.Blocked)
	if err != nil {
		return none, nil, false
	}
	// Browsers report some schemes as a bare word, such as "data".
	if u.Scheme == "" {
		u = &url.URL{Scheme: r.Blocked}
	}
	source := sourceFor(Finding{Directive: directive, URL: u}, t.Site, Options{ExactPaths: t.ExactPaths})
	if !reportedSource.MatchString(source) {
		return none, nil, false
	}
	entry.url = u
	return tallyKey{directive, source}, entry, true
}

// repeating calls visit for everything enough clients reported, most reported
// first, so that output is stable.
func (t *Tally) repeating(visit func(key tallyKey, e *tallyEntry)) {
	minimum := cmp.Or(t.MinClients, 3)
	var keys []tallyKey
	for key, e := range t.entries {
		if len(e.clients) >= minimum {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a, b tallyKey) int {
		return cmp.Or(
			cmp.Compare(len(t.entries[b].clients), len(t.entries[a].clients)),
			cmp.Compare(a.directive, b.directive),
			cmp.Compare(a.target, b.target),
		)
	})
	for _, key := range keys {
		visit(key, t.entries[key])
	}
}

// Page returns what repeated in the reports as a Page, so that it can go through
// Merge and Build along with what a collector found.
func (t *Tally) Page() *Page {
	t.mu.Lock()
	defer t.mu.Unlock()
	page := &Page{URL: t.Site}
	t.repeating(func(key tallyKey, e *tallyEntry) {
		clients := len(e.clients)
		switch {
		case key.directive == "script-src-attr":
			page.Blockers = append(page.Blockers, Blocker{Reason: ReasonEventHandler, Value: e.sample})
		case key.directive == "style-src-attr":
			page.Blockers = append(page.Blockers, Blocker{Reason: ReasonStyleAttribute, Value: e.sample})
		case e.blocked == "eval" || e.blocked == "wasm-eval":
			page.Blockers = append(page.Blockers, Blocker{Reason: ReasonEval, Value: e.sample})
		case e.url == nil && strings.HasPrefix(e.sample, "javascript:"):
			page.Blockers = append(page.Blockers, Blocker{Reason: ReasonJavaScriptURL, Value: e.sample})
		case e.url == nil:
			page.Warnings = append(page.Warnings, fmt.Sprintf(
				"%d clients reported inline code starting %q, but a report's sample can't be hashed, so collect the page again", clients, e.sample))
		case key.directive == "script-src":
			page.Warnings = append(page.Warnings, fmt.Sprintf(
				"%d clients reported %s, but a report can't give a script's hash, so collect the page again", clients, e.blocked))
		case slices.Contains(codeDirectives, key.directive):
			page.Warnings = append(page.Warnings, fmt.Sprintf(
				"%d clients reported %s under %s, which can run code, so add it by hand if it's real", clients, e.blocked, key.directive))
		default:
			page.Findings = append(page.Findings, Finding{Directive: key.directive, URL: e.url})
		}
	})
	if t.dropped > 0 {
		page.Warnings = append(page.Warnings, fmt.Sprintf("%d reports weren't counted, because too many different things were reported", t.dropped))
	}
	return page
}

// Addition is a source reports suggest adding to a policy, with the evidence
// for it.
type Addition struct {
	Directive string
	Source    string
	Reports   int      // How many reports asked for it.
	Clients   int      // How many clients sent them.
	Pages     []string // Some of the pages it happened on.
	Blocked   []string // Some of the URLs that were blocked.
}

func (a Addition) String() string {
	return fmt.Sprintf("%s %s: %d reports from %d clients, such as %s on %s", a.Directive, a.Source, a.Reports, a.Clients, a.Blocked[0], a.Pages[0])
}

// Suggestions are what reports say a policy is missing.
type Suggestions struct {
	Additions []Addition // Sources to review and add.
	Blockers  []Blocker  // Inline code that has to change.
	Warnings  []string   // Everything that needs a person, such as blocked scripts.
}

// Suggest compares what repeated in the reports with policy, and returns what
// the policy doesn't already allow.
func (t *Tally) Suggest(policy *Policy) *Suggestions {
	page := t.Page()
	suggestions := &Suggestions{Blockers: page.Blockers, Warnings: page.Warnings}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.repeating(func(key tallyKey, e *tallyEntry) {
		if e.url == nil || slices.Contains(codeDirectives, key.directive) || policy.allows(key.directive, key.target) {
			return
		}
		suggestions.Additions = append(suggestions.Additions, Addition{
			Directive: key.directive,
			Source:    key.target,
			Reports:   e.reports,
			Clients:   len(e.clients),
			Pages:     e.pages,
			Blocked:   e.urls,
		})
	})
	return suggestions
}

// allows reports whether source is already listed for directive. This only
// compares text. A report means a browser found it blocked, so all this needs to
// catch is a source added since.
func (p *Policy) allows(directive, source string) bool {
	fallback := -1
	for i, d := range p.Directives {
		if d.Name == directive {
			return slices.Contains(d.Sources, source)
		}
		if d.Name == "default-src" {
			fallback = i
		}
	}
	return fallback >= 0 && slices.Contains(p.Directives[fallback].Sources, source)
}

// ParsePolicy reads a Content-Security-Policy header value. As in browsers,
// only the first directive of each name counts, and names ignore case. Its
// Warnings list any sources that let an attacker get around the policy through
// a host known to allow it.
func ParsePolicy(header string) *Policy {
	policy := &Policy{}
	for part := range strings.SplitSeq(header, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if !slices.ContainsFunc(policy.Directives, func(d Directive) bool { return d.Name == name }) {
			policy.Directives = append(policy.Directives, Directive{name, fields[1:]})
		}
	}
	policy.Warnings = bypassWarnings(policy.Directives)
	return policy
}

// ReportingTo returns a copy of the policy that sends violations to endpoint, a
// ReportHandler. It adds 'report-sample' to script-src and style-src, which
// doesn't change what's allowed. Send the result in a
// Content-Security-Policy-Report-Only header to try the policy.
//
// It uses report-uri, even though the specification prefers report-to. Every
// browser supports report-uri, but Chrome ignores it when report-to is there,
// and report-to doesn't work on plain HTTP, so listing both would lose every
// report from those pages.
func (p *Policy) ReportingTo(endpoint string) *Policy {
	copied := *p
	copied.Directives = make([]Directive, 0, len(p.Directives)+1)
	for _, d := range p.Directives {
		if d.Name == "script-src" || d.Name == "style-src" {
			d.Sources = append(slices.Clone(d.Sources), "'report-sample'")
		}
		copied.Directives = append(copied.Directives, d)
	}
	copied.Directives = append(copied.Directives, Directive{"report-uri", []string{endpoint}})
	return &copied
}
