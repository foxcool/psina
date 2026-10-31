package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/foxcool/psina/api/auth/v1"
	"github.com/foxcool/psina/api/auth/v1/authv1connect"
	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/provider/local"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lockedBuffer is written by the server goroutine and read by the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A quiet diagnostic log (logger.level=warn or error) must not drop audit
// events, which are written at info level.
func TestAuditLogger_IgnoresLogLevel(t *testing.T) {
	tests := []struct {
		level, format, want string
	}{
		{"warn", "json", `"event":"login","result":"success"`},
		{"error", "text", `event=login result=success`},
	}
	for _, tt := range tests {
		t.Run(tt.level+"/"+tt.format, func(t *testing.T) {
			cfg := &Config{}
			cfg.Logger.Level = tt.level
			cfg.Logger.Format = tt.format
			require.False(t, setupLogger(cfg).Enabled(context.Background(), slog.LevelInfo),
				"the diagnostic log drops info records")

			var out lockedBuffer
			mem := memory.New()
			issuer, err := token.New()
			require.NoError(t, err)
			svc := auth.NewService(mem, mem, issuer, []auth.Provider{local.New(mem, mem)})
			path, rpc := authv1connect.NewAuthServiceHandler(auth.NewHandler(svc, auth.WithAuditLogger(setupAuditLogger(cfg, &out))))
			mux := http.NewServeMux()
			mux.Handle(path, rpc)
			srv := httptest.NewServer(mux)
			defer srv.Close()
			client := authv1connect.NewAuthServiceClient(srv.Client(), srv.URL)

			ctx := context.Background()
			_, err = client.Register(ctx, connect.NewRequest(&authv1.RegisterRequest{Email: "user@example.com", Password: "SecurePassword123!"}))
			require.NoError(t, err)
			_, err = client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: "user@example.com", Password: "SecurePassword123!"}))
			require.NoError(t, err)

			assert.Contains(t, out.String(), tt.want)
		})
	}
}

// SIGTERM must let an in-flight request finish before serve returns: run()
// closes the DB pool right after, and a request cut short there may have
// rotated a refresh token without saving its successor.
func TestServe_SIGTERMDrainsInFlightRequest(t *testing.T) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			<-release
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- serve(ctx, srv, ln, 10*time.Second) }()

	status := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			status <- 0
			return
		}
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()

	<-entered
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	<-ctx.Done()

	select {
	case err := <-served:
		t.Fatalf("serve returned while a request was in flight: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	assert.Equal(t, http.StatusOK, <-status)
	assert.NoError(t, <-served)
}

// A drain that outlives its timeout is reported: run() exits non-zero rather
// than claiming a clean stop while a request may have been cut off.
func TestServe_DrainTimeout(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			close(entered)
			<-release
		}),
		ReadHeaderTimeout: time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serve(ctx, srv, ln, 50*time.Millisecond) }()
	go func() {
		if resp, err := http.Get("http://" + ln.Addr().String()); err == nil {
			_ = resp.Body.Close()
		}
	}()

	<-entered
	cancel()
	err = <-served
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.ErrorContains(t, err, "shutdown")
}

func TestServe_ListenerFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	err = serve(context.Background(), &http.Server{ReadHeaderTimeout: time.Second}, ln, time.Second)
	assert.ErrorContains(t, err, "serve")
}
