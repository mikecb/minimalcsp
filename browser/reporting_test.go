package browser

import "testing"

func TestWithoutReporting(t *testing.T) {
	tests := []struct{ policy, want string }{
		{"default-src 'none'", "default-src 'none'"},
		{"default-src 'none'; report-uri /r", "default-src 'none'"},
		{"report-to group; default-src 'none'", " default-src 'none'"},
		{"default-src 'none'; REPORT-URI /r; Report-To group; img-src *", "default-src 'none'; img-src *"},
		{"report-uri /r", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := withoutReporting(tt.policy); got != tt.want {
			t.Errorf("withoutReporting(%q) = %q, want %q", tt.policy, got, tt.want)
		}
	}
}
