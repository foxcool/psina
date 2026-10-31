package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/foxcool/psina/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/provider/local"
	"github.com/foxcool/psina/provider/oauth"
	"github.com/foxcool/psina/provider/oauth/github"
	"github.com/foxcool/psina/provider/oauth/google"
	"github.com/foxcool/psina/provider/wallet"
	"github.com/foxcool/psina/provider/wallet/evm"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/store/postgres"
	"github.com/foxcool/psina/token"
)

// Build information (set by goreleaser via ldflags).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Handle --version flag
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("psina %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// Load config
	config, err := loadConfig(os.Args[1:])
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Setup logger
	logger := setupLogger(config)
	slog.SetDefault(logger)

	slog.Info("starting psina",
		"version", version,
		"port", config.Server.Port,
		"jwt_algorithm", config.JWT.Algorithm,
		"cookies_enabled", config.Cookie.Enabled,
		"pat_enabled", config.PAT.Enabled,
	)

	// Initialize stores based on config
	var userStore auth.UserStore
	var tokenStore auth.TokenStore
	var credStore auth.CredentialStore
	var patStore auth.PATStore
	var oauthIdentityStore auth.OAuthIdentityStore
	var challengeStore auth.ChallengeStore
	var walletIdentityStore auth.WalletIdentityStore
	var cleanup func()
	var dbPing func(context.Context) error

	if config.DB.URL != "" {
		// Production: use PostgreSQL
		slog.Info("using postgresql store", "table_prefix", config.DB.TablePrefix)

		pgStore, err := postgres.NewWithDSN(ctx, config.DB.URL,
			postgres.WithTablePrefix(config.DB.TablePrefix),
		)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
		cleanup = func() { pgStore.Close() }
		dbPing = pgStore.Ping

		userStore = pgStore
		tokenStore = pgStore
		credStore = pgStore
		patStore = pgStore
		oauthIdentityStore = pgStore
		challengeStore = pgStore
		walletIdentityStore = pgStore
	} else {
		// Development: use in-memory store
		slog.Warn("using in-memory store (data will not persist)")

		memStore := memory.New()
		cleanup = func() {}
		dbPing = nil

		userStore = memStore
		tokenStore = memStore
		credStore = memStore
		patStore = memStore
		oauthIdentityStore = memStore
		challengeStore = memStore
		walletIdentityStore = memStore
	}
	defer cleanup()

	// Initialize token issuer
	issuer, err := createTokenIssuer(config)
	if err != nil {
		return fmt.Errorf("create token issuer: %w", err)
	}
	slog.Info("token issuer initialized", "algorithm", issuer.Algorithm())

	// Initialize provider
	provider := local.New(userStore, credStore)

	// Initialize service
	serviceOpts := []auth.ServiceOption{auth.WithRefreshReuseLeeway(config.Token.RefreshReuseLeeway)}
	if config.PAT.Enabled {
		serviceOpts = append(serviceOpts, auth.WithPAT(patStore, auth.PATConfig{
			MaxPerUser:    config.PAT.MaxPerUser,
			MaxTTL:        config.PAT.MaxTTL,
			TouchInterval: config.PAT.TouchInterval,
		}))
	}
	oauthProviders, err := createOAuthProviders(config)
	if err != nil {
		return fmt.Errorf("create oauth providers: %w", err)
	}
	if len(oauthProviders) > 0 {
		serviceOpts = append(serviceOpts, auth.WithOAuth(oauthProviders, oauthIdentityStore, challengeStore, credStore,
			auth.OAuthConfig{DisableAutoLinkEmail: !config.OAuth.AutoLinkEmail}))
		slog.Info("oauth sign-in enabled", "providers", len(oauthProviders), "auto_link_email", config.OAuth.AutoLinkEmail)
	}
	walletProviders, err := createWalletDispatcher(config)
	if err != nil {
		return fmt.Errorf("create wallet providers: %w", err)
	}
	if walletProviders != nil {
		w := config.Wallet
		serviceOpts = append(serviceOpts, auth.WithWallet(walletProviders, walletIdentityStore, challengeStore,
			auth.WalletConfig{Domain: w.Domain, URI: w.URI, Statement: w.Statement, ChallengeTTL: w.ChallengeTTL}))
		slog.Info("wallet sign-in enabled", "domain", w.Domain, "chains", walletProviders.Chains())
	}
	service := auth.NewService(tokenStore, userStore, issuer, []auth.Provider{provider}, serviceOpts...)

	// Initialize handler with cookie config
	cookieConfig := &auth.CookieConfig{
		Enabled:  config.Cookie.Enabled,
		Domain:   config.Cookie.Domain,
		Path:     config.Cookie.Path,
		Secure:   config.Cookie.Secure,
		SameSite: parseSameSite(config.Cookie.SameSite),
	}
	trustedProxies, err := parseTrustedProxies(config.Server.TrustedProxies)
	if err != nil {
		return err
	}
	if len(trustedProxies) == 0 {
		slog.Info("no trusted proxies: client IP is the connection peer, X-Forwarded-For is ignored")
	}
	handler := auth.NewHandler(service,
		auth.WithCookieConfig(cookieConfig),
		auth.WithTrustedProxies(trustedProxies),
		auth.WithAuditLogger(setupAuditLogger(config, os.Stdout)),
	)

	// Setup HTTP mux
	mux := http.NewServeMux()

	// Mount Connect RPC handler
	path, rpcHandler := authv1connect.NewAuthServiceHandler(
		handler,
		connect.WithInterceptors(),
	)
	mux.Handle(path, rpcHandler)

	// JWKS endpoint
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if err := json.NewEncoder(w).Encode(service.JWKS()); err != nil {
			slog.Error("encode jwks", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})

	// Health endpoints
	// /healthz - liveness probe (always returns 200 if service is running)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// /readyz - readiness probe (checks DB connection)
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if dbPing != nil {
			if err := dbPing(r.Context()); err != nil {
				slog.Warn("readiness check failed", "error", err)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"not_ready","reason":"database_unavailable"}`))
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	// /health - backward compatible health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		status := "ok"
		dbStatus := "not_configured"
		httpStatus := http.StatusOK

		if dbPing != nil {
			if err := dbPing(r.Context()); err != nil {
				status = "degraded"
				dbStatus = "error"
				httpStatus = http.StatusServiceUnavailable
				slog.Warn("health check: db ping failed", "error", err)
			} else {
				dbStatus = "connected"
			}
		}

		w.WriteHeader(httpStatus)
		resp := fmt.Sprintf(`{"status":"%s","service":"psina","version":"%s","db":"%s"}`, status, version, dbStatus)
		_, _ = w.Write([]byte(resp))
	})

	// /verify - HTTP endpoint for Traefik ForwardAuth
	// This is separate from the Connect RPC Verify method to provide a simple HTTP interface
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		var accessToken string

		if authHeader != "" {
			accessToken = strings.TrimPrefix(authHeader, "Bearer ")
			if accessToken == authHeader {
				// No "Bearer " prefix, invalid format
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}
		}

		// Also check cookie if cookies are enabled
		if accessToken == "" && config.Cookie.Enabled {
			if cookie, err := r.Cookie("psina_access"); err == nil {
				accessToken = cookie.Value
			}
		}

		if accessToken == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}

		// Verify token
		claims, err := service.Verify(r.Context(), accessToken)
		if errors.Is(err, auth.ErrInvalidCredentials) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if err != nil {
			// Not 401: the gateway would read an outage as "log the user out".
			slog.ErrorContext(r.Context(), "verify failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Set response headers for the gateway
		w.Header().Set("X-User-Id", claims.UserID)
		w.Header().Set("X-User-Email", claims.Email)
		if len(claims.Roles) > 0 {
			w.Header().Set("X-User-Roles", strings.Join(claims.Roles, ","))
		}
		w.WriteHeader(http.StatusOK)
	})

	// HTTP/1.1 for JSON clients and ForwardAuth, HTTP/2 cleartext (prior knowledge) for gRPC.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Server.Port),
		Handler:      mux,
		Protocols:    protocols,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The first signal starts the drain; unregistering then lets a second one
	// kill the process as usual instead of waiting out the drain.
	context.AfterFunc(ctx, stop)

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	slog.Info("server listening", "addr", server.Addr)
	if err := serve(ctx, server, ln, shutdownTimeout); err != nil {
		return err
	}

	slog.Info("server stopped")
	return nil
}

// shutdownTimeout bounds the drain of in-flight requests after a signal.
const shutdownTimeout = 30 * time.Second

// serve runs server on ln until ctx is done, then drains in-flight requests.
// It returns only after the drain: Serve itself returns ErrServerClosed as soon
// as Shutdown starts, and run() closes the DB pool once serve returns, so a
// request still running then (a refresh rotated, its successor not yet saved)
// would fail half-done.
func serve(ctx context.Context, server *http.Server, ln net.Listener, drainTimeout time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(ln) }()

	var serveErr error
	select {
	case err := <-served:
		// Handlers already running still need the DB: drain them too.
		serveErr = fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		slog.Info("shutting down", "cause", context.Cause(ctx))
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return errors.Join(serveErr, fmt.Errorf("shutdown: %w", err))
	}
	return serveErr
}

func createTokenIssuer(config *Config) (*token.Issuer, error) {
	// Determine key source
	var keyData []byte
	var err error

	switch {
	case config.JWT.PrivateKey != "":
		// Key provided directly in config
		keyData = []byte(config.JWT.PrivateKey)
		slog.Info("using jwt key from environment/config")
	case config.JWT.PrivateKeyPath != "":
		// Load key from file
		keyData, err = os.ReadFile(config.JWT.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read jwt key file: %w", err)
		}
		slog.Info("using jwt key from file", "path", config.JWT.PrivateKeyPath)
	default:
		// Development: generate ephemeral key
		slog.Warn("no JWT key configured, generating ephemeral key (tokens will invalidate on restart)")
		return token.NewWithAlgorithm(token.Algorithm(config.JWT.Algorithm))
	}

	// Parse key based on algorithm
	switch config.JWT.Algorithm {
	case "ES256":
		privateKey, err := parseECDSAPrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse ecdsa key: %w", err)
		}
		return token.NewWithECDSAKey(privateKey)

	case "RS256":
		fallthrough
	default:
		privateKey, err := parseRSAPrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse rsa key: %w", err)
		}
		return token.NewWithRSAKey(privateKey)
	}
}

func parseRSAPrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS#1 first
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	return rsaKey, nil
}

func parseECDSAPrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try EC private key format first
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	ecKey, ok := keyInterface.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}

	return ecKey, nil
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

func setupLogger(config *Config) *slog.Logger {
	level, _ := parseLogLevel(config.Logger.Level) // validateConfig rejected an unknown level
	return slog.New(newLogHandler(config, os.Stdout, level))
}

// setupAuditLogger builds the logger for audit events: same output and format
// as the diagnostic log, but its own level, so logger.level never drops a
// security event.
func setupAuditLogger(config *Config, w io.Writer) *slog.Logger {
	return slog.New(newLogHandler(config, w, slog.LevelInfo))
}

func newLogHandler(config *Config, w io.Writer, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(config.Logger.Format, "text") {
		return slog.NewTextHandler(w, opts)
	}
	return slog.NewJSONHandler(w, opts)
}

// createOAuthProviders builds the OAuth providers that have credentials configured.
func createOAuthProviders(config *Config) ([]oauth.Provider, error) {
	var providers []oauth.Provider
	if g := config.OAuth.Google; g.ClientID != "" {
		p, err := google.New(google.Config{
			ClientID:     g.ClientID,
			ClientSecret: g.ClientSecret,
			RedirectURIs: g.RedirectURIs,
		})
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	if g := config.OAuth.GitHub; g.ClientID != "" {
		p, err := github.New(github.Config{
			ClientID:     g.ClientID,
			ClientSecret: g.ClientSecret,
			RedirectURIs: g.RedirectURIs,
		})
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// createWalletDispatcher builds one EVM provider per configured chain, or
// returns nil when wallet sign-in is disabled (no domain).
func createWalletDispatcher(config *Config) (*wallet.Dispatcher, error) {
	if config.Wallet.Domain == "" {
		return nil, nil
	}
	chains, err := parseEVMChains(config.Wallet.EVMChains)
	if err != nil {
		return nil, err
	}
	providers := make([]wallet.WalletProvider, 0, len(chains))
	for _, c := range chains {
		providers = append(providers, evm.New(c.Name, c.ID))
	}
	return wallet.NewDispatcher(providers...), nil
}
