package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/foxcool/psina/pkg/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/pkg/provider/local"
	"github.com/foxcool/psina/pkg/psina"
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
	logger := setupLogger(config.Logger)
	slog.SetDefault(logger)

	slog.Info("starting psina", "port", config.Server.Port)

	// Initialize stores based on config
	var userStore psina.UserStore
	var tokenStore psina.TokenStore
	var credStore psina.CredentialStore
	var cleanup func()

	if config.DB.URL != "" {
		// Production: use PostgreSQL
		slog.Info("using postgresql store", "url", maskDSN(config.DB.URL))

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
	tokenIssuer, err := token.New(tokenStore, userStore)
	if err != nil {
		return fmt.Errorf("create token issuer: %w", err)
	}

	// Initialize provider
	provider := local.New(userStore, credStore)

	// Initialize service
	service := psina.NewService(provider, tokenStore, tokenIssuer)

	// Initialize handler
	handler := psina.NewHandler(service)

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

// maskDSN hides password in DSN for logging.
func maskDSN(dsn string) string {
	// Simple masking: replace password in postgres://user:pass@host format
	if idx := len("postgres://"); len(dsn) > idx {
		if atIdx := findChar(dsn[idx:], '@'); atIdx > 0 {
			if colonIdx := findChar(dsn[idx:idx+atIdx], ':'); colonIdx > 0 {
				return dsn[:idx+colonIdx+1] + "****" + dsn[idx+atIdx:]
			}
		}
	}
	return dsn
}

func findChar(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func setupLogger(config LoggerConfig) *slog.Logger {
	var level slog.Level
	switch config.Level {
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
	if config.Format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
