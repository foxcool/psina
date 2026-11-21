package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AccountClaims checks OAuthIdentityStore.ClaimAccountWithOAuthIdentity: a
// password account with no identity is handed to the provider account in one
// step (password, sessions and PATs gone, credential epoch set, link saved),
// and an account that already has an identity, or a claim that cannot link,
// changes nothing.
func AccountClaims(t *testing.T, newStore NewBackend) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	// The epoch comes from the store's clock (the database's, for postgres),
	// which may drift a little from the test's.
	const clockSlack = 2 * time.Second

	newIdentity := func(userID, externalID string) *entity.OAuthIdentity {
		return &entity.OAuthIdentity{
			ID: uuid.New().String(), UserID: userID, Provider: entity.ProviderTypeGoogle, ExternalID: externalID,
		}
	}

	// seed gives the user a password, a refresh family (root and successor)
	// and a PAT, and returns the PAT hash.
	seed := func(t *testing.T, s Backend, userID string) string {
		t.Helper()
		require.NoError(t, s.SavePasswordHash(ctx, userID, "hash"))
		root := "root-" + userID
		require.NoError(t, s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: root, UserID: userID, ExpiresAt: now.Add(time.Hour),
		}))
		require.NoError(t, s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "child-" + userID, UserID: userID, Parent: root, ExpiresAt: now.Add(time.Hour),
		}))
		patHash := "pat-" + userID
		require.NoError(t, s.SavePAT(ctx, &entity.PersonalAccessToken{
			ID: uuid.New().String(), Hash: patHash, UserID: userID, Name: "ci",
		}))
		return patHash
	}

	// assertUntouched checks that seed's rows are all still live and the
	// credential epoch is unset.
	assertUntouched := func(t *testing.T, s Backend, userID, patHash string) {
		t.Helper()
		_, err := s.GetPasswordHash(ctx, userID)
		require.NoError(t, err, "password kept")
		for _, hash := range []string{"root-" + userID, "child-" + userID} {
			rt, err := s.GetRefreshToken(ctx, hash)
			require.NoError(t, err)
			assert.False(t, rt.Revoked, "session kept: %s", hash)
			assert.Nil(t, rt.EndedAt, "session kept: %s", hash)
		}
		_, err = s.GetPAT(ctx, patHash)
		require.NoError(t, err, "PAT kept")
		user, err := s.GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Nil(t, user.CredentialsChangedAt, "credential epoch unset")
	}

	t.Run("password account without identity is taken over", func(t *testing.T) {
		s := newStore(t)
		userID, other := createUser(t, s), createUser(t, s)
		patHash := seed(t, s, userID)
		otherPAT := seed(t, s, other)

		before := time.Now()
		epoch, err := s.ClaimAccountWithOAuthIdentity(ctx, newIdentity(userID, "sub-1"))
		require.NoError(t, err)
		require.NotNil(t, epoch, "password dropped")
		assert.WithinRange(t, *epoch, before.Add(-clockSlack), time.Now().Add(clockSlack))

		_, err = s.GetPasswordHash(ctx, userID)
		assert.ErrorIs(t, err, store.ErrCredentialNotFound, "password dropped")
		for _, hash := range []string{"root-" + userID, "child-" + userID} {
			rt, err := s.GetRefreshToken(ctx, hash)
			require.NoError(t, err)
			assert.True(t, rt.Revoked, "token revoked: %s", hash)
			assert.NotNil(t, rt.EndedAt, "session ended: %s", hash)
		}
		family, err := s.GetRefreshFamily(ctx, "root-"+userID)
		require.NoError(t, err)
		assert.True(t, family.SessionEnded)
		// A successor of an ended family is refused, as after a logout.
		err = s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "late-" + userID, UserID: userID, Parent: "root-" + userID, ExpiresAt: now.Add(time.Hour),
		})
		assert.ErrorIs(t, err, store.ErrTokenRevoked)
		_, err = s.GetPAT(ctx, patHash)
		assert.ErrorIs(t, err, store.ErrTokenNotFound, "PAT deleted")

		user, err := s.GetByID(ctx, userID)
		require.NoError(t, err)
		require.NotNil(t, user.CredentialsChangedAt, "credential epoch set")
		assert.True(t, epoch.Equal(*user.CredentialsChangedAt), "stored epoch is the returned one, got %v", user.CredentialsChangedAt)

		identity, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-1")
		require.NoError(t, err)
		assert.Equal(t, userID, identity.UserID)

		assertUntouched(t, s, other, otherPAT)
	})

	t.Run("account without password is linked only", func(t *testing.T) {
		s := newStore(t)
		userID := createUser(t, s)
		require.NoError(t, s.SaveRefreshToken(ctx, &entity.RefreshToken{
			Hash: "root-" + userID, UserID: userID, ExpiresAt: now.Add(time.Hour),
		}))
		require.NoError(t, s.SavePAT(ctx, &entity.PersonalAccessToken{
			ID: uuid.New().String(), Hash: "pat-" + userID, UserID: userID, Name: "ci",
		}))
		// An existing identity does not matter without a password.
		require.NoError(t, s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
			ID: uuid.New().String(), UserID: userID, Provider: entity.ProviderTypeGitHub, ExternalID: "42",
		}))

		epoch, err := s.ClaimAccountWithOAuthIdentity(ctx, newIdentity(userID, "sub-1"))
		require.NoError(t, err)
		assert.Nil(t, epoch, "no password dropped")

		rt, err := s.GetRefreshToken(ctx, "root-"+userID)
		require.NoError(t, err)
		assert.False(t, rt.Revoked, "session kept")
		_, err = s.GetPAT(ctx, "pat-"+userID)
		require.NoError(t, err, "PAT kept")
		user, err := s.GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Nil(t, user.CredentialsChangedAt, "credential epoch unset")
		identity, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-1")
		require.NoError(t, err)
		assert.Equal(t, userID, identity.UserID, "linked")
	})

	refusals := []struct {
		name string
		// stage prepares the conflict for userID; other is a second user.
		stage   func(t *testing.T, s Backend, userID, other string)
		wantErr error
		// linkedToOther: afterwards sub-1 belongs to other; otherwise it is
		// linked to nobody.
		linkedToOther bool
	}{
		{
			name: "account with an oauth identity",
			stage: func(t *testing.T, s Backend, userID, _ string) {
				require.NoError(t, s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
					ID: uuid.New().String(), UserID: userID, Provider: entity.ProviderTypeGitHub, ExternalID: "42",
				}))
			},
			wantErr:       store.ErrUserHasIdentity,
			linkedToOther: false,
		},
		{
			name: "account with a wallet identity",
			stage: func(t *testing.T, s Backend, userID, _ string) {
				require.NoError(t, s.SaveWalletIdentity(ctx, &entity.WalletIdentity{
					ID: uuid.New().String(), UserID: userID, Chain: "ethereum", Address: "addr-" + userID,
				}))
			},
			wantErr:       store.ErrUserHasIdentity,
			linkedToOther: false,
		},
		{
			name: "provider account linked to another user",
			stage: func(t *testing.T, s Backend, _, other string) {
				require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(other, "sub-1")))
			},
			wantErr:       store.ErrOAuthIdentityExists,
			linkedToOther: true,
		},
		{
			// Both conflicts hold: the provider-account conflict is reported.
			name: "provider account taken and account with an identity",
			stage: func(t *testing.T, s Backend, userID, other string) {
				require.NoError(t, s.SaveOAuthIdentity(ctx, newIdentity(other, "sub-1")))
				require.NoError(t, s.SaveOAuthIdentity(ctx, &entity.OAuthIdentity{
					ID: uuid.New().String(), UserID: userID, Provider: entity.ProviderTypeGitHub, ExternalID: "42",
				}))
			},
			wantErr:       store.ErrOAuthIdentityExists,
			linkedToOther: true,
		},
	}
	for _, tt := range refusals {
		t.Run(tt.name+" changes nothing", func(t *testing.T) {
			s := newStore(t)
			userID, other := createUser(t, s), createUser(t, s)
			patHash := seed(t, s, userID)
			tt.stage(t, s, userID, other)

			_, err := s.ClaimAccountWithOAuthIdentity(ctx, newIdentity(userID, "sub-1"))
			require.ErrorIs(t, err, tt.wantErr)

			assertUntouched(t, s, userID, patHash)
			got, err := s.GetOAuthIdentity(ctx, entity.ProviderTypeGoogle, "sub-1")
			if tt.linkedToOther {
				require.NoError(t, err)
				assert.Equal(t, other, got.UserID)
			} else {
				assert.ErrorIs(t, err, store.ErrOAuthIdentityNotFound)
			}
		})
	}

	t.Run("missing user", func(t *testing.T) {
		s := newStore(t)
		_, err := s.ClaimAccountWithOAuthIdentity(ctx, newIdentity(uuid.New().String(), "sub-1"))
		assert.ErrorIs(t, err, store.ErrUserNotFound)
	})
}
