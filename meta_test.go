package minimalcsp

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestMetaTag(t *testing.T) {
	policy := &Policy{Directives: []Directive{
		{"default-src", []string{"'none'"}},
		{"img-src", []string{`https://a.example/x&y"z`}},
	}}
	want := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https://a.example/x&amp;y&quot;z">`
	if got := policy.MetaTag(); got != want {
		t.Errorf("MetaTag() =\n%s\nwant\n%s", got, want)
	}
}

// The escaping has to survive a real parser, so the browser sees the policy.
func TestMetaTagParses(t *testing.T) {
	policy := &Policy{Directives: []Directive{{"img-src", []string{`https://a.example/x&amp;y"z<>`}}}}
	doc, err := html.Parse(strings.NewReader(policy.MetaTag()))
	if err != nil {
		t.Fatal(err)
	}
	if got := policyIn(doc); len(got) != 1 || got[0] != policy.String() {
		t.Errorf("parsed %q, want %q", got, policy.String())
	}
}

func TestInsertMeta(t *testing.T) {
	const tag = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`
	tests := []struct{ name, document, want string }{
		{"empty", ``, tag},
		{"full page", `<!doctype html><html lang=en><head><title>t</title></head><body></body></html>`,
			`<!doctype html><html lang=en><head>` + tag + `<title>t</title></head><body></body></html>`},
		{"head first", `<head lang=en><title>t</title>`, `<head lang=en>` + tag + `<title>t</title>`},
		{"empty head", `<head></head><body>`, `<head>` + tag + `</head><body>`},
		{"no head", `<html><script>a</script>`, `<html>` + tag + `<script>a</script>`},
		{"no tags", `hello`, tag + `hello`},
		{"doctype only", `<!doctype html><p>text`, `<!doctype html>` + tag + `<p>text`},
		{"comments", `<!-- a --><!doctype html><!-- b --><head><!-- c --><script></script>`,
			`<!-- a --><!doctype html><!-- b --><head><!-- c -->` + tag + `<script></script>`},
		{"whitespace stays after the tag", "<!doctype html>\n<head>\n  <title>t</title>",
			"<!doctype html>\n<head>" + tag + "\n  <title>t</title>"},
		{"byte order mark", "\xef\xbb\xbf<!doctype html><head>", "\xef\xbb\xbf<!doctype html><head>" + tag},
		{"upper case", `<HTML><HEAD><TITLE>t</TITLE>`, `<HTML><HEAD>` + tag + `<TITLE>t</TITLE>`},

		{"charset", `<head><meta charset=utf-8><title>t</title>`, `<head><meta charset=utf-8>` + tag + `<title>t</title>`},
		{"charset in http-equiv", `<head><META HTTP-EQUIV="Content-Type" content="text/html; charset=utf-8"><title>t</title>`,
			`<head><META HTTP-EQUIV="Content-Type" content="text/html; charset=utf-8">` + tag + `<title>t</title>`},
		{"other meta", `<head><meta name=viewport content=a><meta charset=utf-8>`,
			`<head>` + tag + `<meta name=viewport content=a><meta charset=utf-8>`},
		{"charset after a script stays there", `<head><script></script><meta charset=utf-8>`,
			`<head>` + tag + `<script></script><meta charset=utf-8>`},

		{"ahead of base", `<head><base href=/a/><script src=b.js></script>`, `<head>` + tag + `<base href=/a/><script src=b.js></script>`},
		{"ahead of styles", `<head><style>a{}</style>`, `<head>` + tag + `<style>a{}</style>`},
		{"ahead of links", `<head><link rel=stylesheet href=a.css>`, `<head>` + tag + `<link rel=stylesheet href=a.css>`},

		{"replaces a tag", `<head><meta http-equiv=Content-Security-Policy content="script-src 'self'"><title>t</title>`,
			`<head>` + tag + `<title>t</title>`},
		{"replaces in any case", `<head><title>t</title><META HTTP-EQUIV=" content-security-policy " CONTENT=x>`,
			`<head>` + tag + `<title>t</title>`},
		{"replaces every tag", `<head><meta http-equiv=content-security-policy content=a><meta http-equiv=content-security-policy content=b>`,
			`<head>` + tag},
		{"keeps other elements", `<head><div http-equiv=content-security-policy>`, `<head>` + tag + `<div http-equiv=content-security-policy>`},
		{"keeps other http-equiv", `<head><meta http-equiv=refresh content=5>`, `<head>` + tag + `<meta http-equiv=refresh content=5>`},

		{"not fooled by comments", `<!-- <head> --><p>`, `<!-- <head> -->` + tag + `<p>`},
		{"not fooled by scripts", `<script>"<head>"</script>`, tag + `<script>"<head>"</script>`},
		{"not fooled by the policy in text", `<head><script>"<meta http-equiv=content-security-policy>"</script>`,
			`<head>` + tag + `<script>"<meta http-equiv=content-security-policy>"</script>`},
		{"unterminated tag", `<head><title>t</title><p`, `<head>` + tag + `<title>t</title><p`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(InsertMeta([]byte(tt.document), "default-src 'none'"))
			if got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
			// Running a build twice has to change nothing more.
			if again := string(InsertMeta([]byte(got), "default-src 'none'")); again != got {
				t.Errorf("second run gave\n%s\nwant\n%s", again, got)
			}
			checkPlacement(t, got)
		})
	}
}

// checkPlacement parses a document the way a browser does, since a tag that
// looks right in the source can still end up where the browser ignores it.
func checkPlacement(t *testing.T, document string) {
	t.Helper()
	// Browsers drop a byte order mark while decoding, before parsing starts.
	doc, err := html.Parse(strings.NewReader(strings.TrimPrefix(document, string(byteOrderMark))))
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	var walk func(n *html.Node, inHead bool)
	walk = func(n *html.Node, inHead bool) {
		if n.Type == html.ElementNode {
			inHead = inHead || n.Data == "head"
			if equiv, _ := attr(n, "http-equiv"); n.Data == "meta" && strings.EqualFold(equiv, metaName) {
				if !inHead {
					t.Errorf("tag is outside <head>: %s", document)
				}
				seen = append(seen, "policy")
			}
			switch n.Data {
			case "script", "style", "link", "base", "img":
				seen = append(seen, n.Data)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, inHead)
		}
	}
	walk(doc, false)
	if len(seen) == 0 || seen[0] != "policy" {
		t.Errorf("order = %v in %s", seen, document)
	}
}

func TestInsertMetaKeepsHeadAttributes(t *testing.T) {
	doc, err := html.Parse(bytes.NewReader(InsertMeta([]byte(`<!doctype html><head lang=en>`), "default-src 'none'")))
	if err != nil {
		t.Fatal(err)
	}
	var lang string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Data == "head" {
			lang, _ = attr(n, "lang")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if lang != "en" {
		t.Errorf("lang = %q", lang)
	}
}

func TestInsertMetaKeepsCharsetInReach(t *testing.T) {
	policy := "script-src " + strings.Repeat("'sha256-x' ", 200)
	got := InsertMeta([]byte(`<!doctype html><head><meta charset=utf-8><title>t</title>`), policy)
	if index := bytes.Index(got, []byte("charset=utf-8")); index < 0 || index > 1024 {
		t.Errorf("charset is at byte %d", index)
	}
}

func TestApplyMeta(t *testing.T) {
	pageURL, err := url.Parse("https://a.example/")
	if err != nil {
		t.Fatal(err)
	}
	script, err := url.Parse("https://a.example/a.js")
	if err != nil {
		t.Fatal(err)
	}
	policy := &Policy{
		Directives: []Directive{{"script-src", []string{"'sha256-x'"}}},
		Integrity:  []Integrity{{URL: script, Value: "sha256-x"}},
	}
	got := string(policy.ApplyMeta([]byte(`<head><script src=/a.js></script>`), pageURL))
	want := `<head>` + policy.MetaTag() + `<script src=/a.js integrity="sha256-x"></script>`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func policyIn(doc *html.Node) []string {
	var found []string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			content, _ := attr(n, "content")
			found = append(found, content)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return found
}
