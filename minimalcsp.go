package minimalcsp

import (
	"fmt"
	"log"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

// attr returns the value of n's attribute with the given key, and whether n has it.
func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// runsAsScript reports whether a script element with the given type attribute
// executes. Other types are data blocks, such as JSON-LD, which CSP doesn't
// restrict. Every JavaScript MIME type contains "script".
func runsAsScript(scriptType string) bool {
	t := strings.ToLower(strings.TrimSpace(scriptType))
	return t == "" || t == "module" || t == "importmap" || strings.Contains(t, "script")
}

// GetSources returns slices of the discovered src attributes for each of the CSP types.
func GetSources(s string) [][]string {

	// Tags to handle
	// 	canvas
	// 	figure

	var sources = [][]string{}

	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		log.Fatal(err)
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		switch {
		case n.Type != html.ElementNode:
			// Text and comments can have the same Data as a tag name.
		case n.Data == "link":
			href, ok := attr(n, "href")
			if !ok {
				break
			}
			rel, _ := attr(n, "rel")
			for _, token := range strings.Fields(strings.ToLower(rel)) {
				switch token {
				case "stylesheet":
					sources = append(sources, []string{"style-src", href})
				case "icon":
					sources = append(sources, []string{"img-src", href})
				}
			}
		case n.Data == "script":
			scriptType, _ := attr(n, "type")
			if src, ok := attr(n, "src"); ok {
				sources = append(sources, []string{"script-src", src})
			} else if n.FirstChild != nil && runsAsScript(scriptType) {
				sources = append(sources, []string{"script-src", "unsafe-inline"})
			}
		case n.Data == "style":
			styleType, _ := attr(n, "type")
			isCSS := styleType == "" || strings.EqualFold(styleType, "text/css")
			if n.FirstChild != nil && isCSS {
				sources = append(sources, []string{"style-src", "unsafe-inline"})
			}
		case n.Data == "img":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"img-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "embed":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"object-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "object":
			for _, a := range n.Attr {
				if a.Key == "data" {
					tuple := []string{"object-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "canvas":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"img-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "figure":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"img-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "form":
			for _, a := range n.Attr {
				if a.Key == "action" {
					tuple := []string{"form-action", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "iframe":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"child-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "source":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"media-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "audio":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"media-src", a.Val}
					sources = append(sources, tuple)
				}
			}
		case n.Data == "video":
			for _, a := range n.Attr {
				if a.Key == "src" {
					tuple := []string{"media-src", a.Val}
					sources = append(sources, tuple)
				}
			}

		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return sources
}

// MakePolicy groups the page's sources by directive, removes duplicates, and
// prints the policy to StdOut.
func MakePolicy(s string) {
	var directives []string
	sources := map[string][]string{}
	for _, a := range GetSources(s) {
		directive, source := a[0], a[1]
		if source == "unsafe-inline" {
			source = "'unsafe-inline'"
		}
		if _, seen := sources[directive]; !seen {
			directives = append(directives, directive)
		}
		if !slices.Contains(sources[directive], source) {
			sources[directive] = append(sources[directive], source)
		}
	}

	var policy []string
	for _, directive := range directives {
		policy = append(policy, directive+" "+strings.Join(sources[directive], " "))
	}
	fmt.Println(strings.Join(policy, "; "))

	// Directives to handle.
	// 	base-uri
	// 	child-src - iframe
	// 	connect-src - xmlhttprequest, websocket, eventsource
	// 	default-src
	// 	font-src - @font-face
	// 	form-action - form
	// 	img-src - img, link rel="icon or favicon"
	// 	manifest-src
	// 	media-src audio video
	// 	object-src object embed applet
	// 	plugin-types
	// 	referrer
	// 	reflected-xss
	// 	report-uri
	// 	sandbox
	// 	script-src
	// 	style-src style and style attributes
	// 	upgrade-insecure-requests

}
