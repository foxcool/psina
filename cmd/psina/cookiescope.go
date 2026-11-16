package main

import (
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/foxcool/psina/auth"
)

// warnBroadCookieDomain logs when cookie.domain is a strict parent of a host
// the service answers on. Such a cookie is sent to every sibling host under the
// domain, and the legacy-scope eviction (auth.EvictedCookieScopes) expires
// token cookies under the other scopes, so two deployments whose cookie
// domains disagree log each other out. It is a warning, not an error: a
// deliberate SSO across subdomains is legitimate.
//
// psina has no public-URL or issuer setting, so the hosts come from the
// settings that name a browser-facing host: wallet.domain, wallet.uri and the
// OAuth redirect URIs. When none is set the check cannot run, and that is
// logged once.
func warnBroadCookieDomain(log *slog.Logger, c *Config) {
	if !c.Cookie.Enabled || c.Cookie.Domain == "" {
		return
	}
	domain := strings.ToLower(strings.TrimPrefix(c.Cookie.Domain, "."))

	hosts := serviceHosts(c)
	if len(hosts) == 0 {
		log.Info("cookie.domain not checked against a service host: set wallet.domain or an OAuth redirect URI to enable the check",
			"cookie_domain", domain)
		return
	}

	var covered []string
	for _, h := range hosts {
		if strings.HasSuffix(h, "."+domain) {
			covered = append(covered, h)
		}
	}
	if len(covered) == 0 {
		return
	}

	evicted := make([]string, 0, 2)
	for _, s := range auth.EvictedCookieScopes(domain) {
		if s == "" {
			s = "host-only"
		}
		evicted = append(evicted, s)
	}
	log.Warn("cookie.domain is broader than the service host: its cookies are sent to every host under the domain, "+
		"and each login or logout expires token cookies under the evicted scopes",
		"cookie_domain", domain,
		"service_hosts", covered,
		"covered_scope", "*."+domain,
		"evicted_scopes", evicted,
	)
}

// serviceHosts returns the sorted, deduplicated lowercase hostnames named by
// the configuration. IP literals are skipped: a cookie domain cannot be their
// parent.
func serviceHosts(c *Config) []string {
	seen := map[string]struct{}{}
	add := func(raw string, hasScheme bool) {
		if raw == "" {
			return
		}
		if !hasScheme {
			raw = "//" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		h := strings.ToLower(u.Hostname())
		if h == "" || net.ParseIP(h) != nil {
			return
		}
		seen[h] = struct{}{}
	}
	add(c.Wallet.Domain, false)
	add(c.Wallet.URI, true)
	for _, uris := range [][]string{c.OAuth.Google.RedirectURIs, c.OAuth.GitHub.RedirectURIs} {
		for _, u := range uris {
			add(u, true)
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}
