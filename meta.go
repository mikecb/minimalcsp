package minimalcsp

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

const metaName = "Content-Security-Policy"

var byteOrderMark = []byte("\xef\xbb\xbf")

// metaEscaper leaves single quotes alone, since they're safe in a double-quoted
// attribute and every policy is full of them.
var metaEscaper = strings.NewReplacer("&", "&amp;", `"`, "&quot;")

// MetaTag returns the policy as a <meta> tag, for hosts that can't set response
// headers. Use a header where you can, since a tag does less: it has no
// report-only mode, can't report violations, and browsers ignore frame-ancestors,
// report-uri and sandbox in it. It doesn't suit a ByNonce policy, which needs a
// new value on every response.
//
// The tag only applies to what comes after it, and only in <head>. InsertMeta
// and ApplyMeta put it in the right place.
func (p *Policy) MetaTag() string {
	return metaTag(p.String())
}

func metaTag(policy string) string {
	return `<meta http-equiv="` + metaName + `" content="` + metaEscaper.Replace(policy) + `">`
}

// ApplyMeta is Apply for a page that carries its policy in a <meta> tag. It
// also adds the tag, using InsertMeta.
func (p *Policy) ApplyMeta(document []byte, pageURL *url.URL) []byte {
	return InsertMeta(p.Apply(document, pageURL), p.String())
}

// InsertMeta returns document with policy, a header value, in a <meta> tag at
// the start of its <head>. Any policy tag already there is removed, because
// browsers enforce every tag they find, so an old one would stay in force and
// repeated builds would add up. Everything else stays byte for byte.
//
// The tag goes ahead of anything the policy governs, but after a <meta> that
// declares the charset, which has to stay within the page's first 1024 bytes.
func InsertMeta(document []byte, policy string) []byte {
	var out bytes.Buffer
	position := 0 // Where in out the tag goes.
	leading := true
	z := html.NewTokenizer(bytes.NewReader(document))
	for {
		kind := z.Next()
		// Reading a token can change what Raw returned, so keep a copy.
		raw := bytes.Clone(z.Raw())
		if kind == html.ErrorToken {
			out.Write(raw)
			break
		}
		var tag html.Token
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken {
			tag = z.Token()
		}
		if isPolicyMeta(tag) {
			continue
		}
		leading = leading && comesBeforeThePolicy(kind, raw, tag)
		out.Write(raw)
		if leading && kind != html.TextToken {
			position = out.Len()
		}
	}
	return bytes.Join([][]byte{out.Bytes()[:position], []byte(metaTag(policy)), out.Bytes()[position:]}, nil)
}

// comesBeforeThePolicy reports whether a token at the start of a document can
// stay ahead of the policy's tag. A tag above <head> would make the parser open
// the head early and drop the <head> element's attributes.
func comesBeforeThePolicy(kind html.TokenType, raw []byte, tag html.Token) bool {
	switch kind {
	case html.DoctypeToken, html.CommentToken:
		return true
	case html.TextToken:
		return len(bytes.Trim(bytes.TrimPrefix(raw, byteOrderMark), " \t\r\n\f")) == 0
	}
	return tag.Data == "html" || tag.Data == "head" || declaresCharset(tag)
}

func declaresCharset(tag html.Token) bool {
	if tag.Data != "meta" {
		return false
	}
	equiv, _ := tokenAttr(tag, "http-equiv")
	_, charset := tokenAttr(tag, "charset")
	return charset || strings.EqualFold(equiv, "content-type")
}

func isPolicyMeta(tag html.Token) bool {
	equiv, _ := tokenAttr(tag, "http-equiv")
	return tag.Data == "meta" && strings.EqualFold(strings.TrimSpace(equiv), metaName)
}
