//go:build e2e

package e2e_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestTraefikForwardAuth verifies the ForwardAuth contract: Traefik calls
// psina's /verify, and on success injects X-User-Id/X-User-Email into the
// backend request. The backend is traefik/whoami, which echoes request headers.
func TestTraefikForwardAuth(t *testing.T) {
	base := traefikURL()
	if base == "" {
		t.Skip("E2E_TRAEFIK_URL not set")
	}

	protected := base + "/api"

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

	t.Run("valid token passes and identity is propagated", func(t *testing.T) {
		token := register(t, base)

		status, body := get(t, protected, token)
		if status != http.StatusOK {
			t.Fatalf("want 200, got %d, body %s", status, body)
		}
		// whoami echoes inbound headers; ForwardAuth must have injected the user id.
		if !strings.Contains(body, "X-User-Id") {
			t.Fatalf("X-User-Id not propagated to backend, body:\n%s", body)
		}
	})
}
