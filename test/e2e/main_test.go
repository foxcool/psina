//go:build e2e

// Package e2e drives gateway integration tests against a running stand
// (deploy/e2e/compose.yaml). It exercises the two supported integration modes:
// Traefik ForwardAuth (traefik_test.go) and KrakenD JWKS (krakend_test.go).
//
// The driver speaks plain HTTP/JSON — psina's Connect RPC endpoints accept JSON
// over HTTP/1.1, so no generated client is needed. URLs come from env so the
// same tests run locally and in CI:
//
//	E2E_TRAEFIK_URL  gateway URL for the Traefik scenario (empty -> skip)
//	E2E_KRAKEND_URL  gateway URL for the KrakenD scenario (empty -> skip)
//	E2E_PSINA_URL    direct psina URL, used to mint tokens for KrakenD
package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func traefikURL() string { return os.Getenv("E2E_TRAEFIK_URL") }
func krakendURL() string { return os.Getenv("E2E_KRAKEND_URL") }
func psinaURL() string   { return os.Getenv("E2E_PSINA_URL") }

var httpClient = &http.Client{Timeout: 10 * time.Second}

// uniqueEmail returns a fresh email so reruns against a long-lived stand don't
// collide on "user already exists".
func uniqueEmail() string {
	return fmt.Sprintf("e2e-%d@example.com", time.Now().UnixNano())
}

// register creates a new account via psina's Connect RPC and returns the access
// token. baseURL must route /auth.v1.AuthService/* to psina.
func register(t *testing.T, baseURL string) string {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"email":    uniqueEmail(),
		"password": "securepass123",
	})
	if err != nil {
		t.Fatalf("marshal register body: %v", err)
	}

	url := baseURL + "/auth.v1.AuthService/Register"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new register request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status %d, body %s", resp.StatusCode, raw)
	}

	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode register response %q: %v", raw, err)
	}
	if out.AccessToken == "" {
		t.Fatalf("register: empty access token, body %s", raw)
	}
	return out.AccessToken
}

// get issues a GET with an optional bearer token and returns status + body.
func get(t *testing.T, url, token string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new GET %s: %v", url, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}
