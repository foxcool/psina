//go:build e2e

package e2e_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestKrakenDJWKS verifies the JWKS contract: KrakenD validates the RS256 token
// itself against psina's /.well-known/jwks.json — psina is not called per
// request. The token is minted directly from psina (KrakenD does not proxy the
// auth routes).
func TestKrakenDJWKS(t *testing.T) {
	base := krakendURL()
	if base == "" {
		t.Skip("E2E_KRAKEND_URL not set")
	}

	protected := base + "/api/whoami"

	t.Run("no token is rejected", func(t *testing.T) {
		status, _ := get(t, protected, "")
		if status != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", status)
		}
	})

	t.Run("bad token is rejected", func(t *testing.T) {
		status, _ := get(t, protected, "not-a-real-token")
		if status != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", status)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		status, _ := get(t, protected, mintExpiredToken(t))
		if status != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", status)
		}
	})

	t.Run("valid token passes and claims are propagated", func(t *testing.T) {
		psina := psinaURL()
		if psina == "" {
			t.Skip("E2E_PSINA_URL not set (needed to mint a token for KrakenD)")
		}
		reg := registerRaw(t, psina)

		status, body := get(t, protected, reg.accessToken)
		if status != http.StatusOK {
			t.Fatalf("want 200, got %d, body %s", status, body)
		}
		// KrakenD propagate_claims maps the "sub" claim to X-User-Id for the backend.
		if !strings.Contains(body, reg.userID) {
			t.Fatalf("user id %q not propagated to backend, body:\n%s", reg.userID, body)
		}
	})
}
