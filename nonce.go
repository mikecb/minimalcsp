package minimalcsp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// NonceMiddleware gives each response a new nonce and sends a ByNonce policy
// that allows it. Templates then put the nonce on every script element:
//
//	<script nonce="{{.Nonce}}" src="/app.js"></script>
//
// Pages using nonces mustn't be cached, since a nonce only protects a page if
// an attacker can't predict it.
type NonceMiddleware struct {
	Policy *Policy

	// ReportOnly sends the policy without enforcing it, for trying it out.
	ReportOnly bool

	// ReportTo is where browsers send violations, such as a ReportHandler's
	// path. Leave it empty to not collect them.
	ReportTo string
}

// Wrap returns a handler that adds the policy to next's responses.
func (m NonceMiddleware) Wrap(next http.Handler) http.Handler {
	header := "Content-Security-Policy"
	if m.ReportOnly {
		header += "-Report-Only"
	}
	policy := m.Policy
	if m.ReportTo != "" {
		policy = policy.ReportingTo(m.ReportTo)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 128 bits is the minimum the CSP specification recommends.
		var random [16]byte
		rand.Read(random[:])
		nonce := base64.StdEncoding.EncodeToString(random[:])
		w.Header().Set(header, policy.WithNonce(nonce))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey{}, nonce)))
	})
}

type nonceKey struct{}

// Nonce returns the nonce for the request ctx belongs to. It's empty outside
// NonceMiddleware.
func Nonce(ctx context.Context) string {
	nonce, _ := ctx.Value(nonceKey{}).(string)
	return nonce
}
