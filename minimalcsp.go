package main

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/net/html"
)

//GetSources returns slices of the discovered src attributes for each of the CSP types.
//func GetSources(s string) {
func GetSources(string s) [][]string {
	items := [][]string{{"script", "src"}, {"link", "href"}, {"img", "src"}}

	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		log.Fatal(err)
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == items[1][0] {
			for _, a := range n.Attr {
				if a.Key == items[1][1] {
					fmt.Println(a.Val)
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
}

func MakePolicy(s [][]string) {

}
