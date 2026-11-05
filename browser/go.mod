module github.com/mikecb/minimalcsp/browser

go 1.27.3

require (
	github.com/chromedp/cdproto v0.159.1
	github.com/chromedp/chromedp v0.22.1
	github.com/mikecb/minimalcsp v0.0.0
)

require (
	github.com/go-json-experiment/json v0.0.0-20260213210345-44df1a37e875 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

// The browser module always builds against the library in this repository.
// Using it from elsewhere needs a tagged release of the library.
replace github.com/mikecb/minimalcsp => ../
