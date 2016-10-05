package minimalcsp

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/net/html"
)

//GetSources returns slices of the discovered src attributes for each of the CSP types.
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
		case n.Data == "link":
			for _, a := range n.Attr {
				if a.Key == "rel" && a.Val == "stylesheet" {
					for _, b := range n.Attr {
						if b.Key == "href" {
							tuple := []string{"style-src", b.Val}
							sources = append(sources, tuple)
						}
					}
				} else if a.Key == "rel" && a.Val == "icon" {
					for _, b := range n.Attr {
						if b.Key == "href" {
							tuple := []string{"img-src", b.Val}
							sources = append(sources, tuple)
						}
					}
				} else if a.Key == "rel" && a.Val == "shortcut icon" {
					for _, b := range n.Attr {
						if b.Key == "href" {
							tuple := []string{"img-src", b.Val}
							sources = append(sources, tuple)
						}
					}
				}
			}
		case n.Data == "script":
			if n.Attr == nil {
				tuple := []string{n.Data, "unsafe-inline"}
				sources = append(sources, tuple)
			} else {
				for _, a := range n.Attr {
					if a.Key == "src" {
						tuple := []string{"script-src", a.Val}
						sources = append(sources, tuple)
					}
				}
			}
		case n.Data == "style":
			if n.Attr == nil {
				tuple := []string{"style-src", "unsafe-inline"}
				sources = append(sources, tuple)
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
				if a.Key == "src" {
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
				if a.Key == "src" {
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

// MakePolicy parses the slice of sources, deduplicates, matches with CSP rule, and prints the policy to StdOut.
func MakePolicy(s string) {
	sources := GetSources(s)
	var policy []string
	for _, a := range sources {
		policy = append(policy, strings.Join(a, " "))
	}
	fmt.Printf("%s", policy)

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
