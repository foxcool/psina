//go:build e2e

package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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

	t.Run("expired token is rejected", func(t *testing.T) {
		status, _ := get(t, protected, mintExpiredToken(t))
		if status != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", status)
		}
	})

	t.Run("valid token passes and identity is propagated", func(t *testing.T) {
		reg := registerRaw(t, base)

		status, body := get(t, protected, reg.accessToken)
		if status != http.StatusOK {
			t.Fatalf("want 200, got %d, body %s", status, body)
		}
		// whoami echoes inbound headers; ForwardAuth must have injected the user id.
		if !strings.Contains(body, reg.userID) {
			t.Fatalf("user id %q not propagated to backend, body:\n%s", reg.userID, body)
		}
	})

	t.Run("admin roles are propagated", func(t *testing.T) {
		// The stand sets PSINA_ADMIN_EMAILS="@admin.e2e"; registering on that
		// domain must yield a token whose Verify emits X-User-Roles: admin.
		email := fmt.Sprintf("e2e-admin-%d@admin.e2e", time.Now().UnixNano())
		reg := registerRawEmail(t, base, email)

		status, body := get(t, protected, reg.accessToken)
		if status != http.StatusOK {
			t.Fatalf("want 200, got %d, body %s", status, body)
		}
		// whoami /api echoes headers as JSON.
		if !strings.Contains(body, `"X-User-Roles":["admin"]`) {
			t.Fatalf("X-User-Roles not propagated to backend, body:\n%s", body)
		}
	})

	t.Run("cookie auth passes", func(t *testing.T) {
		reg := registerRaw(t, base)
		if len(reg.cookies) == 0 {
			t.Fatal("register returned no cookies (is PSINA_COOKIE_ENABLED set on the stand?)")
		}

		// No Authorization header — psina must authenticate from the psina_access cookie.
		status, body := getWithCookies(t, protected, reg.cookies)
		if status != http.StatusOK {
			t.Fatalf("want 200, got %d, body %s", status, body)
		}
		if !strings.Contains(body, reg.userID) {
			t.Fatalf("user id %q not propagated to backend, body:\n%s", reg.userID, body)
		}
	})
}
