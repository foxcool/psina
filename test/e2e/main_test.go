//go:build e2e

// Package e2e drives gateway integration tests against a running stand
// (deploy/e2e/compose.yaml). It exercises the two supported integration modes:
// Traefik ForwardAuth (traefik_test.go) and KrakenD JWKS (krakend_test.go).
//
// The driver speaks plain HTTP/JSON — psina's Connect RPC endpoints accept JSON
// over HTTP/1.1, so no generated client is needed. URLs come from env so the
// same tests run locally and in CI:
//
//	E2E_TRAEFIK_URL   gateway URL for the Traefik scenario (empty -> skip)
//	E2E_KRAKEND_URL   gateway URL for the KrakenD scenario (empty -> skip)
//	E2E_PSINA_URL     direct psina URL, used to mint tokens for KrakenD
//	E2E_JWT_KEY_PATH  RSA private key psina signs with; lets the driver forge an
//	                  expired-but-valid token (empty -> expiry subtests skip)
package e2e_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func traefikURL() string { return os.Getenv("E2E_TRAEFIK_URL") }
func krakendURL() string { return os.Getenv("E2E_KRAKEND_URL") }
func psinaURL() string   { return os.Getenv("E2E_PSINA_URL") }
func jwtKeyPath() string { return os.Getenv("E2E_JWT_KEY_PATH") }

// jwtKeyID must match psina's token.KeyID so forged tokens carry a kid the
// gateway/psina can resolve in the JWKS.
const jwtKeyID = "psina-key-1"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// uniqueEmail returns a fresh email so reruns against a long-lived stand don't
// collide on "user already exists".
func uniqueEmail() string {
	return fmt.Sprintf("e2e-%d@example.com", time.Now().UnixNano())
}

// registerResult holds what the driver needs from a Register call.
type registerResult struct {
	accessToken string
	userID      string
	cookies     []*http.Cookie
}

// registerRaw creates a new account via psina's Connect RPC. baseURL must route
// /auth.v1.AuthService/* to psina.
func registerRaw(t *testing.T, baseURL string) registerResult {
	t.Helper()
	return registerRawEmail(t, baseURL, uniqueEmail())
}

// registerRawEmail is registerRaw with a caller-chosen email (e.g. one matching
// the stand's PSINA_ADMIN_EMAILS domain).
func registerRawEmail(t *testing.T, baseURL, email string) registerResult {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"email":    email,
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
		UserID      string `json:"userId"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode register response %q: %v", raw, err)
	}
	if out.AccessToken == "" {
		t.Fatalf("register: empty access token, body %s", raw)
	}
	return registerResult{accessToken: out.AccessToken, userID: out.UserID, cookies: resp.Cookies()}
}

// mintExpiredToken signs a token with psina's key whose exp is in the past. The
// signature is valid, so this isolates the "expired" rejection path from the
// "bad signature / garbage" path. Skips if no key is mounted.
func mintExpiredToken(t *testing.T) string {
	t.Helper()

	path := jwtKeyPath()
	if path == "" {
		t.Skip("E2E_JWT_KEY_PATH not set (cannot forge an expired token)")
	}

	keyData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read jwt key %s: %v", path, err)
	}
	key := parseRSAKey(t, keyData)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwtKeyID),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	now := time.Now()
	claims := struct {
		jwt.Claims
		Email string `json:"email"`
	}{
		Claims: jwt.Claims{
			Subject:   "00000000-0000-0000-0000-000000000001",
			Issuer:    "psina",
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			Expiry:    jwt.NewNumericDate(now.Add(-1 * time.Hour)), // expired
		},
		Email: "expired@example.com",
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}
	return token
}

func parseRSAKey(t *testing.T, keyData []byte) *rsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode(keyData)
	if block == nil {
		t.Fatal("no PEM block in jwt key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse jwt key: %v", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("jwt key is not RSA")
	}
	return key
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
	return do(t, req)
}

// getWithCookies issues a GET carrying the given cookies and no Authorization.
func getWithCookies(t *testing.T, url string, cookies []*http.Cookie) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new GET %s: %v", url, err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return do(t, req)
}

func do(t *testing.T, req *http.Request) (int, string) {
	t.Helper()

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}
