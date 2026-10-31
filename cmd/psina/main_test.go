package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

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
