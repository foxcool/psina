package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

func main() {
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

	slog.Info("starting psina", "port", config.Server.Port)

	// Initialize stores based on config
	var userStore auth.UserStore
	var tokenStore auth.TokenStore
	var credStore auth.CredentialStore
	var cleanup func()

	if config.DB.URL != "" {
		// Production: use PostgreSQL
		slog.Info("using postgresql store")

		pgStore, err := postgres.NewWithDSN(ctx, config.DB.URL)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
		cleanup = func() { pgStore.Close() }

		userStore = pgStore
		tokenStore = pgStore
		credStore = pgStore
	} else {
		// Development: use in-memory store
		slog.Warn("using in-memory store (data will not persist)")

		memStore := memory.New()
		cleanup = func() {}

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

	// Initialize provider
	provider := local.New(userStore, credStore)

	// Initialize service
	service := auth.NewService(provider, tokenStore, userStore, issuer)

	// Initialize handler
	handler := auth.NewHandler(service)

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

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"psina"}`))
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
	if config.JWT.PrivateKeyPath != "" {
		// Production: load key from file
		privateKey, err := loadPrivateKey(config.JWT.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load jwt key: %w", err)
		}

		slog.Info("using jwt key from file", "path", config.JWT.PrivateKeyPath)
		return token.NewWithKey(privateKey)
	}

	// Development: generate ephemeral key
	slog.Warn("no JWT key configured, generating ephemeral key (tokens will invalidate on restart)")
	return token.New()
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

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
