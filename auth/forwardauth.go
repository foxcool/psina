package auth

import (
	"net/http"

	"connectrpc.com/connect"
)

// ForwardAuth returns the plain-HTTP twin of Verify for gateways that call an
// auth URL per request (Traefik ForwardAuth and the like). It answers 200 with
// the X-User-* headers for a valid access JWT or PAT, 401 for a missing or
// rejected token and 500 for an outage, so a gateway never logs a user out on a
// storage failure. Bodies are short plain-text reasons. Any method is accepted;
// mount it on the path the gateway calls.
func (h *Handler) ForwardAuth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := h.accessToken(r.Header)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := h.service.Verify(r.Context(), accessToken)
		if err != nil {
			cerr := credentialErrorToConnect(r.Context(), err)
			status := http.StatusInternalServerError
			if cerr.Code() == connect.CodeUnauthenticated {
				status = http.StatusUnauthorized
			}
			http.Error(w, cerr.Message(), status)
			return
		}

		setIdentityHeaders(w.Header(), claims)
		w.WriteHeader(http.StatusOK)
	})
}
