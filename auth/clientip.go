package auth

import (
	"net/http"
	"net/netip"
	"strings"
)

// unknownClientIP is reported when the peer address does not parse.
const unknownClientIP = "unknown"

// WithTrustedProxies sets the proxies whose X-Forwarded-For and X-Real-IP
// headers are believed. Without it the headers are ignored and the client is
// the connection's peer: any client can write those headers itself.
func WithTrustedProxies(prefixes []netip.Prefix) HandlerOption {
	return func(h *Handler) {
		h.trustedProxies = prefixes
	}
}

// clientIP resolves the client address for logging. peer is the connection's
// remote address ("host:port" or a bare IP). X-Forwarded-For is walked right to
// left: each trusted proxy appends the address it received from, so the first
// untrusted hop is the client. Entries left of it are the client's own claims.
func (h *Handler) clientIP(peer string, header http.Header) string {
	addr, ok := parseAddr(peer)
	if !ok {
		return unknownClientIP
	}
	if !h.trusted(addr) {
		return addr.String()
	}

	hops := forwardedFor(header)
	if len(hops) == 0 {
		if real, ok := parseAddr(header.Get("X-Real-IP")); ok {
			return real.String()
		}
		return addr.String()
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseAddr(hops[i])
		if !ok {
			// A trusted proxy would not append garbage, so the client wrote it;
			// the last address a trusted proxy vouched for is the best we have.
			return addr.String()
		}
		addr = hop
		if !h.trusted(addr) {
			return addr.String()
		}
	}
	// Every hop is a trusted proxy: the request started inside the trusted net.
	return addr.String()
}

func (h *Handler) trusted(addr netip.Addr) bool {
	for _, p := range h.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// forwardedFor flattens every X-Forwarded-For header line into one hop list:
// proxies may append a new line instead of extending the existing one.
func forwardedFor(header http.Header) []string {
	var hops []string
	for _, line := range header.Values("X-Forwarded-For") {
		for hop := range strings.SplitSeq(line, ",") {
			if hop = strings.TrimSpace(hop); hop != "" {
				hops = append(hops, hop)
			}
		}
	}
	return hops
}

// parseAddr accepts "host:port", "[v6]:port" or a bare IP and unmaps
// IPv4-in-IPv6, so 10.0.0.1 matches 10.0.0.0/8 however the socket reports it.
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}
