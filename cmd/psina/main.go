package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/foxcool/psina/pkg/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/pkg/auth"
	"github.com/foxcool/psina/pkg/provider/local"
	"github.com/foxcool/psina/pkg/store/memory"
	"github.com/foxcool/psina/pkg/store/postgres"
	"github.com/foxcool/psina/pkg/token"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
	config, err := loadConfig()
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
	)

	// Initialize stores based on config
	var userStore auth.UserStore
	var tokenStore auth.TokenStore
	var credStore auth.CredentialStore
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
	} else {
		// Development: use in-memory store
		slog.Warn("using in-memory store (data will not persist)")

		memStore := memory.New()
		cleanup = func() {}
		dbPing = nil

		userStore = memStore
		tokenStore = memStore
		credStore = memStore
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
	service := auth.NewService(provider, tokenStore, userStore, issuer)

	// Initialize handler with cookie config
	cookieConfig := &auth.CookieConfig{
		Enabled:  config.Cookie.Enabled,
		Domain:   config.Cookie.Domain,
		Path:     config.Cookie.Path,
		Secure:   config.Cookie.Secure,
		SameSite: parseSameSite(config.Cookie.SameSite),
	}
	handler := auth.NewHandler(service, auth.WithCookieConfig(cookieConfig))

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
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Set response headers for the gateway
		w.Header().Set("X-User-Id", claims.UserID)
		w.Header().Set("X-User-Email", claims.Email)
		w.WriteHeader(http.StatusOK)
	})

	// Create server with h2c (HTTP/2 cleartext for gRPC)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Server.Port),
		Handler:      h2c.NewHandler(mux, &http2.Server{}),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		slog.Info("received shutdown signal", "signal", sig.String())

		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "error", err)
		}
		cancel()
	}()

	// Start server
	slog.Info("server listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("listen: %w", err)
	}

	slog.Info("server stopped")
	return nil
}

func createTokenIssuer(config *Config) (*token.Issuer, error) {
	// Determine key source
	var keyData []byte
	var err error

	if config.JWT.PrivateKey != "" {
		// Key provided directly in config
		keyData = []byte(config.JWT.PrivateKey)
		slog.Info("using jwt key from environment/config")
	} else if config.JWT.PrivateKeyPath != "" {
		// Load key from file
		keyData, err = os.ReadFile(config.JWT.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read jwt key file: %w", err)
		}
		slog.Info("using jwt key from file", "path", config.JWT.PrivateKeyPath)
	} else {
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
	var level slog.Level
	switch config.Logger.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if config.Logger.Format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
