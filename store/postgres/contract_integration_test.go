//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestContract_RefreshRotation(t *testing.T) {
	storetest.RefreshRotation(t, func(t *testing.T) (auth.TokenStore, string) {
		s := getTestStore(t)
		user := &entity.User{ID: uuid.New().String(), Email: "contract@example.com"}
		require.NoError(t, s.Create(context.Background(), user))
		return s, user.ID
	})
}

func TestContract_Challenges(t *testing.T) {
	storetest.Challenges(t, func(t *testing.T) auth.ChallengeStore { return getTestStore(t) })
}

func TestContract_Users(t *testing.T) {
	storetest.Users(t, func(t *testing.T) auth.UserStore { return getTestStore(t) })
}

func TestContract_WalletIdentities(t *testing.T) {
	storetest.WalletIdentities(t, func(t *testing.T) storetest.WalletStore { return getTestStore(t) })
}
