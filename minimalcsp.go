package minimalcsp

import (
	"log"
	"strings"

	"golang.org/x/net/html"
)

//GetSources returns slices of the discovered src attributes for each of the CSP types.
//func GetSources(s string) {
func GetSources(s string) [][]string {
	// const (
	// 	script = iota
	// 	link
	// 	img
	// 	embed
	// 	object
	// 	canvas
	// 	figure
	// 	form
	// 	iframe
	// 	source
	// 	video
	// 	audio
	// )

	var sources = [][]string{}

	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		log.Fatal(err)
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		//Change to switch statement to accomodate all the different types of n.Data we will need to extract differently.
		switch {
		case n.Data == "link":
			for _, a := range n.Attr {
				if a.Key == "rel" && a.Val == "stylesheet" {
					for _, b := range n.Attr {
						if b.Key == "href" {
							css := []string{"style", b.Val}
							sources = append(sources, css)
						}
					}
				}
			}
		case n.Data == "script":
			if n.Attr == nil {
				script := []string{n.Data, "inline"}
				sources = append(sources, script)
			} else {
				for _, a := range n.Attr {
					if a.Key == "src" {
						script := []string{n.Data, a.Val}
						sources = append(sources, script)
					}
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
func MakePolicy(s [][]string) {

	// const (
	// 	base-uri = iota
	// 	child-src
	// 	connect-src
	// 	default-src
	// 	font-src
	// 	form-action
	// 	frame-ancestors
	// 	frame-src
	// 	img-src
	// 	manifest-src
	// 	media-src
	// 	object-src
	// 	plugin-types
	// 	referrer
	// 	reflected-xss
	// 	report-uri
	// 	sandbox
	// 	script-src
	// 	style-src
	// 	upgrade-insecure-requests
	// )

}
