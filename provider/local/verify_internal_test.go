package local

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store/memory"
)

// countVerifies replaces the password check with a counting wrapper for the
// duration of the test.
func countVerifies(t *testing.T) *int {
	t.Helper()
	orig := verifyPassword
	n := 0
	verifyPassword = func(password, encodedHash string) bool {
		n++
		return orig(password, encodedHash)
	}
	t.Cleanup(func() { verifyPassword = orig })
	return &n
}

// Every rejection after a lookup must cost one Argon2id verification, so the
// answer time does not reveal whether the account or its password exists.
func TestAuthenticate_RunsOneVerifyOnEveryRejection(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	p := New(st, st)

	_, err := p.Register(ctx, &entity.RegisterRequest{Email: "pw@example.com", Password: "right-password"})
	if err != nil {
		t.Fatal(err)
	}
	// An account without a password, as OAuth or wallet sign-in creates.
	if err := st.Create(ctx, &entity.User{ID: generateUserID(), Email: "nopw@example.com"}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		email  string
		reason string
	}{
		{"unknown user", "ghost@example.com", auth.ReasonUnknownUser},
		{"no password", "nopw@example.com", auth.ReasonNoPassword},
		{"bad password", "pw@example.com", auth.ReasonBadPassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := countVerifies(t)

			_, err := p.Authenticate(ctx, &entity.AuthRequest{Email: tt.email, Password: "wrong-password"})

			var ce *auth.CredentialsError
			if !errors.As(err, &ce) {
				t.Fatalf("want *auth.CredentialsError, got %v", err)
			}
			if ce.Reason != tt.reason {
				t.Errorf("reason = %q, want %q", ce.Reason, tt.reason)
			}
			if *n != 1 {
				t.Errorf("verify ran %d times, want 1", *n)
			}
		})
	}
}

// The dummy hash must parse, or verify would return before Argon2id runs.
func TestDummyHashIsWellFormed(t *testing.T) {
	parts := strings.Split(dummyPasswordHash, "$")
	if len(parts) != 6 {
		t.Fatalf("dummyPasswordHash has %d parts, want 6", len(parts))
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != argon2SaltLength {
		t.Fatalf("salt: len %d, err %v", len(salt), err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) != argon2KeyLength {
		t.Fatalf("key: len %d, err %v", len(key), err)
	}
}
