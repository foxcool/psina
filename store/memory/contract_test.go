package memory_test

import (
	"context"
	"testing"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/store/storetest"
	"github.com/stretchr/testify/require"
)

func TestContract_RefreshRotation(t *testing.T) {
	storetest.RefreshRotation(t, func(t *testing.T) (auth.TokenStore, string) {
		s := memory.New()
		user := &entity.User{ID: "user-123"}
		require.NoError(t, s.Create(context.Background(), user))
		return s, user.ID
	})
}

func TestContract_Challenges(t *testing.T) {
	storetest.Challenges(t, func(t *testing.T) auth.ChallengeStore { return memory.New() })
}

func TestContract_Users(t *testing.T) {
	storetest.Users(t, func(t *testing.T) auth.UserStore { return memory.New() })
}

func TestContract_WalletIdentities(t *testing.T) {
	storetest.WalletIdentities(t, func(t *testing.T) storetest.WalletStore { return memory.New() })
}

func newBackend(t *testing.T) storetest.Backend { return memory.New() }

func TestContract_Credentials(t *testing.T)     { storetest.Credentials(t, newBackend) }
func TestContract_PATs(t *testing.T)            { storetest.PATs(t, newBackend) }
func TestContract_OAuthIdentities(t *testing.T) { storetest.OAuthIdentities(t, newBackend) }
func TestContract_UserOwnership(t *testing.T)   { storetest.UserOwnership(t, newBackend) }
