package memory_test

import (
	"testing"

	"github.com/foxcool/psina/auth"
	"github.com/foxcool/psina/store/memory"
	"github.com/foxcool/psina/store/storetest"
)

func TestContract_RefreshRotation(t *testing.T) {
	storetest.RefreshRotation(t, func(t *testing.T) (auth.TokenStore, string) {
		// The memory store has no foreign keys; any user ID will do.
		return memory.New(), "user-123"
	})
}

func TestContract_Challenges(t *testing.T) {
	storetest.Challenges(t, func(t *testing.T) auth.ChallengeStore { return memory.New() })
}

func TestContract_Users(t *testing.T) {
	storetest.Users(t, func(t *testing.T) auth.UserStore { return memory.New() })
}
