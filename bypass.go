package minimalcsp

import (
	"fmt"
	"slices"
	"strings"
)

// A bypass is a URL that defeats a policy allowing it, since an attacker who
// can inject markup can load it as a script. It's on https, as they all are.
type bypass struct {
	host string
	path string
	why  string // What the host does, with %s for the URL.
}

const (
	hasJSONP   = "has a JSONP endpoint at %s, so injected markup can choose a function to call"
	hasAngular = "serves AngularJS at %s, which runs code from injected markup without eval"
	isOpen     = "lets anyone publish files, such as %s, so an attacker can host a script there"
)

// bypasses is deliberately short. The JSONP and AngularJS entries were each
// run in Chrome under a policy listing only the host, starting from the lists
// in Google's CSP Evaluator, most of whose JSONP endpoints have since gone.
// raw.githubusercontent.com isn't here because it serves text/plain with
// nosniff, so browsers refuse to run what it serves. Hosts that need
// 'unsafe-eval', such as www.googletagmanager.com, aren't here either.
//
// Subdomains on attacker.* stand for anyone's site on a shared platform, so
// they match wildcards but not a source naming one particular site.
var bypasses = []bypass{
	{"www.google.com", "/complete/search", hasJSONP},
	{"clients1.google.com", "/complete/search", hasJSONP},
	{"suggestqueries.google.com", "/complete/search", hasJSONP},
	{"translate.google.com", "/translate_a/l", hasJSONP},
	{"translate.googleapis.com", "/translate_a/l", hasJSONP},
	{"www.googleapis.com", "/customsearch/v1", hasJSONP},
	{"maps.googleapis.com", "/maps/api/js/GeoPhotoService.GetMetadata", hasJSONP},
	{"books.google.com", "/books", hasJSONP},
	{"graph.facebook.com", "/", hasJSONP},
	{"api.flickr.com", "/services/feeds/photos_public.gne", hasJSONP},
	{"en.wikipedia.org", "/w/api.php", hasJSONP},
	{"nominatim.openstreetmap.org", "/search", hasJSONP},
	{"fast.wistia.com", "/embed/medias/o75jtw7654.json", hasJSONP},
	{"api.vk.com", "/method/wall.get", hasJSONP},
	{"widgets.pinterest.com", "/v3/pidgets/boards/x/y/pins/", hasJSONP},

	{"ajax.googleapis.com", "/ajax/libs/angularjs/1.8.3/angular.min.js", hasAngular},
	{"cdnjs.cloudflare.com", "/ajax/libs/angular.js/1.8.3/angular.min.js", hasAngular},
	{"cdn.bootcdn.net", "/ajax/libs/angular.js/1.8.3/angular.min.js", hasAngular},

	{"cdn.jsdelivr.net", "/npm/angular@1.8.3/angular.min.js", isOpen},
	{"unpkg.com", "/angular@1.8.3/angular.min.js", isOpen},
	{"esm.sh", "/angular@1.8.3/angular.min.js", isOpen},
	{"storage.googleapis.com", "/attacker/x.js", isOpen},
	{"s3.amazonaws.com", "/attacker/x.js", isOpen},

	{"attacker.s3.amazonaws.com", "/x.js", isOpen},
	{"attacker.cloudfront.net", "/x.js", isOpen},
	{"attacker.github.io", "/x.js", isOpen},
	{"attacker.vercel.app", "/x.js", isOpen},
	{"attacker.netlify.app", "/x.js", isOpen},
	{"attacker.pages.dev", "/x.js", isOpen},
	{"attacker.workers.dev", "/x.js", isOpen},
	{"attacker.web.app", "/x.js", isOpen},
	{"attacker.firebaseapp.com", "/x.js", isOpen},
	{"attacker.appspot.com", "/x.js", isOpen},
	{"attacker.herokuapp.com", "/x.js", isOpen},
	{"attacker.azurewebsites.net", "/x.js", isOpen},
	{"attacker.blob.core.windows.net", "/x.js", isOpen},
}

// bypassWarnings returns a warning for each source that lets injected markup
// run code through a known bypass. 'strict-dynamic' makes browsers ignore host
// sources, so a policy with it has nothing to warn about.
func bypassWarnings(directives []Directive) []string {
	name, sources := scriptElementSources(directives)
	if slices.ContainsFunc(sources, func(s string) bool { return strings.EqualFold(s, "'strict-dynamic'") }) {
		return nil
	}
	var warnings []string
	for _, source := range sources {
		// A source that matches a host nobody listed matches every host.
		if hostSourceAllows(source, "any-host.invalid", "/") {
			warnings = append(warnings, fmt.Sprintf("%s allows %s, so injected markup can load a script from any host", name, source))
			continue
		}
		for _, b := range bypasses {
			if hostSourceAllows(source, b.host, b.path) {
				why := fmt.Sprintf(b.why, "https://"+b.host+b.path)
				warnings = append(warnings, fmt.Sprintf("%s allows %s, which %s", name, source, why))
				break
			}
		}
	}
	return warnings
}

// scriptElementSources returns the directive that governs script elements.
func scriptElementSources(directives []Directive) (name string, sources []string) {
	for _, name := range []string{"script-src-elem", "script-src", "default-src"} {
		i := slices.IndexFunc(directives, func(d Directive) bool { return d.Name == name })
		if i >= 0 {
			return name, directives[i].Sources
		}
	}
	return "", nil
}

// hostSourceAllows reports whether a source expression matches the https URL
// made of host and path, which must be lowercase and absolute. Source paths
// aren't percent-decoded, so a source that encodes an ordinary character
// doesn't match.
func hostSourceAllows(source, host, path string) bool {
	switch strings.ToLower(source) {
	case "http:", "https:":
		return true
	}
	rest := source
	if scheme, after, found := strings.Cut(source, "://"); found {
		if s := strings.ToLower(scheme); s != "http" && s != "https" {
			return false
		}
		rest = after
	}
	sourceHost, sourcePath := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		sourceHost, sourcePath = rest[:i], rest[i:]
	}
	sourceHost, port, _ := strings.Cut(strings.ToLower(sourceHost), ":")
	if port != "" && port != "*" && port != "443" {
		return false
	}
	if suffix, ok := strings.CutPrefix(sourceHost, "*"); ok {
		if !strings.HasSuffix(host, suffix) {
			return false
		}
	} else if sourceHost != host {
		return false
	}
	if strings.HasSuffix(sourcePath, "/") {
		return strings.HasPrefix(path, sourcePath)
	}
	return sourcePath == "" || sourcePath == path
}
