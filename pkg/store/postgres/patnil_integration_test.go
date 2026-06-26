//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/foxcool/psina/pkg/entity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: a PAT created without scopes must persist. pgx encodes a nil
// slice as SQL NULL, which previously violated the NOT NULL scopes column.
func TestStore_PATNilScopes(t *testing.T) {
	s := getTestStore(t)
	ctx := context.Background()

	user := &entity.User{ID: uuid.New().String(), Email: "patnil@example.com"}
	require.NoError(t, s.Create(ctx, user))

	pat := &entity.PersonalAccessToken{
		ID:     uuid.New().String(),
		Hash:   "pat-nil-scopes",
		UserID: user.ID,
		Name:   "no-scopes",
		Scopes: nil, // client omitted scopes
	}
	require.NoError(t, s.SavePAT(ctx, pat))

	got, err := s.GetPAT(ctx, "pat-nil-scopes")
	require.NoError(t, err)
	assert.Empty(t, got.Scopes)
}
