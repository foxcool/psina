package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cookieScopeConfig(domain, walletDomain, walletURI string, redirects ...string) *Config {
	c := &Config{}
	c.Cookie.Enabled = true
	c.Cookie.Domain = domain
	c.Wallet.Domain = walletDomain
	c.Wallet.URI = walletURI
	c.OAuth.Google.RedirectURIs = redirects
	return c
}

func TestWarnBroadCookieDomain(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		wantWarn bool
		wantInfo bool
		contains []string
	}{
		{
			name:     "parent domain of wallet host warns",
			cfg:      cookieScopeConfig(".example.com", "dev.app.example.com", "https://dev.app.example.com"),
			wantWarn: true,
			contains: []string{"dev.app.example.com", "example.com"},
		},
		{
			name:     "parent domain of oauth redirect host warns",
			cfg:      cookieScopeConfig("example.com", "", "", "https://app.example.com/cb"),
			wantWarn: true,
			contains: []string{"app.example.com"},
		},
		{
			name:     "eviction scopes above the domain are named",
			cfg:      cookieScopeConfig("app.example.com", "", "", "https://x.app.example.com/cb"),
			wantWarn: true,
			contains: []string{"example.com", "host-only"},
		},
		{
			name: "exact match is quiet",
			cfg:  cookieScopeConfig("app.example.com", "app.example.com", "https://app.example.com"),
		},
		{
			name: "leading dot and case do not defeat an exact match",
			cfg:  cookieScopeConfig(".App.Example.com", "app.example.com", "https://app.example.com"),
		},
		{
			name: "wallet domain with a port is compared by host",
			cfg:  cookieScopeConfig("app.example.com", "app.example.com:8443", "https://app.example.com:8443"),
		},
		{
			name:     "no host to compare against says so",
			cfg:      cookieScopeConfig("example.com", "", ""),
			wantInfo: true,
		},
		{
			name: "cookies disabled is silent",
			cfg: func() *Config {
				c := cookieScopeConfig("example.com", "app.example.com", "https://app.example.com")
				c.Cookie.Enabled = false
				return c
			}(),
		},
		{
			name: "unrelated host is not covered",
			cfg:  cookieScopeConfig("example.com", "other.org", "https://other.org"),
		},
		{
			name: "one warning even with several hosts",
			cfg: cookieScopeConfig("example.com", "a.example.com", "https://a.example.com",
				"https://b.example.com/cb"),
			wantWarn: true,
			contains: []string{"a.example.com", "b.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			warnBroadCookieDomain(log, tt.cfg)

			var warns, infos int
			var all strings.Builder
			for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				if line == "" {
					continue
				}
				var rec map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &rec))
				switch rec["level"] {
				case "WARN":
					warns++
				case "INFO":
					infos++
				}
				all.WriteString(line)
			}
			if tt.wantWarn {
				assert.Equal(t, 1, warns)
			} else {
				assert.Zero(t, warns)
			}
			if tt.wantInfo {
				assert.Equal(t, 1, infos)
			} else {
				assert.Zero(t, infos)
			}
			for _, s := range tt.contains {
				assert.Contains(t, all.String(), s)
			}
		})
	}
}
