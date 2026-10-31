package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/token"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PATLimit drives auth.Service.CreatePAT over the backend: the per-user cap
// must hold under parallel creates, and expired tokens must not take slots.
func PATLimit(t *testing.T, newStore NewBackend) {
	ctx := context.Background()
	const limit = 5

	newService := func(t *testing.T) (*auth.Service, Backend, string) {
		t.Helper()
		s := newStore(t)
		issuer, err := token.New()
		require.NoError(t, err)
		svc := auth.NewService(s, s, issuer, nil, auth.WithPAT(s, auth.PATConfig{MaxPerUser: limit}))
		return svc, s, createUser(t, s)
	}

	t.Run("parallel creates at limit-1 end exactly at the limit", func(t *testing.T) {
		svc, s, userID := newService(t)
		for i := 0; i < limit-1; i++ {
			_, err := svc.CreatePAT(ctx, userID, "seed", nil, nil)
			require.NoError(t, err)
		}

		const workers = 20
		var (
			start sync.WaitGroup
			done  sync.WaitGroup
			mu    sync.Mutex
			ok    int
		)
		start.Add(1)
		for i := 0; i < workers; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				_, err := svc.CreatePAT(ctx, userID, "race", nil, nil)
				if err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
					return
				}
				assert.ErrorIs(t, err, auth.ErrPATLimitReached)
			}()
		}
		start.Done()
		done.Wait()

		assert.Equal(t, 1, ok, "exactly one create fits under the limit")
		list, err := s.ListPATs(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, list, limit)
	})

	t.Run("expired tokens do not occupy slots", func(t *testing.T) {
		svc, s, userID := newService(t)
		past := time.Now().Add(-time.Hour)
		for i := 0; i < limit; i++ {
			require.NoError(t, s.SavePAT(ctx, &entity.PersonalAccessToken{
				ID: uuid.NewString(), Hash: uuid.NewString(), UserID: userID, Name: "old", ExpiresAt: &past,
			}))
		}

		_, err := svc.CreatePAT(ctx, userID, "fresh", nil, nil)
		require.NoError(t, err)
	})

	t.Run("limit is per user", func(t *testing.T) {
		svc, s, userID := newService(t)
		other := createUser(t, s)
		for i := 0; i < limit; i++ {
			_, err := svc.CreatePAT(ctx, userID, "mine", nil, nil)
			require.NoError(t, err)
		}
		_, err := svc.CreatePAT(ctx, userID, "over", nil, nil)
		require.ErrorIs(t, err, auth.ErrPATLimitReached)

		_, err = svc.CreatePAT(ctx, other, "theirs", nil, nil)
		require.NoError(t, err)
	})
}
