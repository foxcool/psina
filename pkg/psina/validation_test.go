package psina_test

import (
	"testing"

	"github.com/foxcool/psina/pkg/psina"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "valid password",
			password: "securepassword123",
			wantErr:  nil,
		},
		{
			name:     "minimum length",
			password: "12345678",
			wantErr:  nil,
		},
		{
			name:     "too short",
			password: "1234567",
			wantErr:  psina.ErrPasswordTooShort,
		},
		{
			name:     "empty",
			password: "",
			wantErr:  psina.ErrPasswordTooShort,
		},
		{
			name:     "max length",
			password: string(make([]byte, 128)),
			wantErr:  nil,
		},
		{
			name:     "too long",
			password: string(make([]byte, 129)),
			wantErr:  psina.ErrPasswordTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := psina.ValidatePassword(tt.password)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		want    string
		wantErr error
	}{
		{
			name:    "valid email",
			email:   "user@example.com",
			want:    "user@example.com",
			wantErr: nil,
		},
		{
			name:    "uppercase",
			email:   "User@Example.COM",
			want:    "user@example.com",
			wantErr: nil,
		},
		{
			name:    "with spaces",
			email:   "  user@example.com  ",
			want:    "user@example.com",
			wantErr: nil,
		},
		{
			name:    "subdomain",
			email:   "user@mail.example.com",
			want:    "user@mail.example.com",
			wantErr: nil,
		},
		{
			name:    "no at sign",
			email:   "userexample.com",
			want:    "",
			wantErr: psina.ErrInvalidEmail,
		},
		{
			name:    "no domain dot",
			email:   "user@examplecom",
			want:    "",
			wantErr: psina.ErrInvalidEmail,
		},
		{
			name:    "too short",
			email:   "a@b",
			want:    "",
			wantErr: psina.ErrInvalidEmail,
		},
		{
			name:    "empty",
			email:   "",
			want:    "",
			wantErr: psina.ErrInvalidEmail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := psina.NormalizeEmail(tt.email)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
