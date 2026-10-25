package auth

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandler_ClientIP(t *testing.T) {
	proxies := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/8"),
	}

	tests := []struct {
		name    string
		trusted []netip.Prefix
		peer    string
		header  http.Header
		want    string
	}{
		{
			name:   "no trusted proxies ignores spoofed XFF",
			peer:   "203.0.113.7:51000",
			header: http.Header{"X-Forwarded-For": {"1.2.3.4"}, "X-Real-Ip": {"5.6.7.8"}},
			want:   "203.0.113.7",
		},
		{
			name:    "untrusted peer ignores XFF",
			trusted: proxies,
			peer:    "203.0.113.7:51000",
			header:  http.Header{"X-Forwarded-For": {"1.2.3.4"}},
			want:    "203.0.113.7",
		},
		{
			name:    "trusted peer: rightmost untrusted hop is the client",
			trusted: proxies,
			peer:    "10.0.0.2:443",
			header:  http.Header{"X-Forwarded-For": {"1.2.3.4, 198.51.100.9, 10.0.0.5"}},
			want:    "198.51.100.9",
		},
		{
			name:    "hops split across header lines",
			trusted: proxies,
			peer:    "10.0.0.2:443",
			header:  http.Header{"X-Forwarded-For": {"1.2.3.4, 198.51.100.9", "10.0.0.5"}},
			want:    "198.51.100.9",
		},
		{
			name:    "all hops trusted: leftmost",
			trusted: proxies,
			peer:    "10.0.0.2:443",
			header:  http.Header{"X-Forwarded-For": {"10.1.1.1, 10.0.0.5"}},
			want:    "10.1.1.1",
		},
		{
			name:    "garbage hop stops at the last vouched address",
			trusted: proxies,
			peer:    "10.0.0.2:443",
			header:  http.Header{"X-Forwarded-For": {"not-an-ip, 10.0.0.5"}},
			want:    "10.0.0.5",
		},
		{
			name:    "trusted peer without XFF falls back to X-Real-IP",
			trusted: proxies,
			peer:    "10.0.0.2:443",
			header:  http.Header{"X-Real-Ip": {"198.51.100.9"}},
			want:    "198.51.100.9",
		},
		{
			name:    "trusted peer without headers is the client",
			trusted: proxies,
			peer:    "10.0.0.2:443",
			header:  http.Header{},
			want:    "10.0.0.2",
		},
		{
			name:    "IPv6 peer and IPv4-mapped hop",
			trusted: proxies,
			peer:    "[fd00::1]:443",
			header:  http.Header{"X-Forwarded-For": {"::ffff:198.51.100.9"}},
			want:    "198.51.100.9",
		},
		{
			name:   "bare IP peer",
			peer:   "203.0.113.7",
			header: http.Header{},
			want:   "203.0.113.7",
		},
		{
			name:   "unparseable peer",
			peer:   "",
			header: http.Header{"X-Forwarded-For": {"1.2.3.4"}},
			want:   unknownClientIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(nil, WithTrustedProxies(tt.trusted))
			assert.Equal(t, tt.want, h.clientIP(tt.peer, tt.header))
		})
	}
}
