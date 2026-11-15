package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// ForwardAuth returns the plain-HTTP twin of Verify for gateways that call an
// auth URL per request (Traefik ForwardAuth and the like). It answers 200 with
// the X-User-* headers for a valid access JWT or PAT, 401 for a missing or
// rejected token and 500 for an outage, so a gateway never logs a user out on a
// storage failure. Any method is accepted; mount it on the path the gateway calls.
func (h *Handler) ForwardAuth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var accessToken string

		if authHeader != "" {
			accessToken = strings.TrimPrefix(authHeader, "Bearer ")
			if accessToken == authHeader {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}
		}

		if accessToken == "" && h.cookieConfig.Enabled {
			if cookie, err := r.Cookie(AccessTokenCookie); err == nil {
				accessToken = cookie.Value
			}
		}

		if accessToken == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}

		claims, err := h.service.Verify(r.Context(), accessToken)
		if errors.Is(err, ErrInvalidCredentials) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if err != nil {
			slog.ErrorContext(r.Context(), "verify failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("X-User-Id", claims.UserID)
		w.Header().Set("X-User-Email", claims.Email)
		if len(claims.Roles) > 0 {
			w.Header().Set("X-User-Roles", strings.Join(claims.Roles, ","))
		}
		w.WriteHeader(http.StatusOK)
	})
}
