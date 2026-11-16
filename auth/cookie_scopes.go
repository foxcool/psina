package auth

// EvictedCookieScopes lists the cookie scopes the legacy-scope eviction
// expires on every login and logout for a configured cookie domain: the
// host-only scope (reported as "") and each parent domain above it. Callers
// use it to tell an operator what a configuration will clear; it shares
// parentDomains with the eviction so the two cannot drift apart.
func EvictedCookieScopes(domain string) []string {
	if domain == "" {
		return nil
	}
	return append([]string{""}, parentDomains(domain)...)
}
