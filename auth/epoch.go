package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/foxcool/psina/entity"
	"github.com/foxcool/psina/store"
	"github.com/foxcool/psina/token"
)

// A takeover (OAuthIdentityStore.ClaimAccountWithOAuthIdentity) drops an
// unproven password and sets the account's credential epoch. Whatever the
// password holder obtained before the epoch is stale and refused: access
// tokens for account actions, refresh sessions, and a login that raced the
// takeover. The epoch comes from the store's clock (the database's, for
// postgres) and is read after the claim's locks; access tokens and session
// starts come from the service clock. The two must agree to well under a
// second (NTP); a skew of d lets things issued within d of the takeover pass
// the time comparisons. The login check compares epoch reads, not times.

// errSessionEnded refuses a session or access token that the account's
// credential epoch, or a logout racing a refresh, has ended.
var errSessionEnded = fmt.Errorf("%w: %w", ErrInvalidCredentials, ErrSessionEnded)

// iatResolution is the precision of a JWT iat claim (whole seconds).
const iatResolution = time.Second

// credentialEpoch is an account's CredentialsChangedAt; the zero value means
// the account was never taken over.
type credentialEpoch struct{ at *time.Time }

func epochOf(user *entity.User) credentialEpoch {
	return credentialEpoch{at: user.CredentialsChangedAt}
}

// tokenStale reports whether an access token with this iat may predate the
// epoch. A token of the epoch's own second counts as before: it cannot be told
// apart from one issued a moment before the takeover. OAuthCallback waits that
// second out before issuing the owner's tokens.
func (e credentialEpoch) tokenStale(iat int64) bool {
	return e.at != nil && iat <= e.at.Unix()
}

// sessionStale reports whether a session whose credential was checked at
// start began before the epoch. A tie counts as before.
func (e credentialEpoch) sessionStale(start time.Time) bool {
	return e.at != nil && !start.After(*e.at)
}

// sleepTimer waits d of real time.
func sleepTimer(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitPastSecond waits until the service clock has left epoch's iat second,
// so a token issued afterwards is not tokenStale. It re-reads the clock after
// every sleep; a clock that does not move is an error, never a false "done".
func (s *Service) waitPastSecond(ctx context.Context, epoch time.Time) error {
	next := epoch.Truncate(iatResolution).Add(iatResolution)
	for {
		now := s.now()
		wait := next.Sub(now)
		if wait <= 0 {
			return nil
		}
		if err := s.sleep(ctx, wait); err != nil {
			return err
		}
		if !s.now().After(now) {
			return errors.New("wait past credential epoch: clock does not advance")
		}
	}
}

// verifySession is Verify for account actions (PAT management): it also
// refuses an access token issued before the account was taken over. Verify
// itself (ForwardAuth, every proxied request) stays stateless; such a token
// keeps passing there until it expires.
func (s *Service) verifySession(ctx context.Context, accessToken string) (*entity.Claims, error) {
	claims, err := s.Verify(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if err := s.checkSessionEpoch(ctx, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkSessionEpoch refuses claims issued before the account's credential
// epoch, or for an account that no longer exists.
func (s *Service) checkSessionEpoch(ctx context.Context, claims *entity.Claims) error {
	user, err := s.userStore.GetByID(ctx, claims.UserID)
	if errors.Is(err, store.ErrUserNotFound) {
		return fmt.Errorf("%w: %w", ErrInvalidCredentials, err)
	}
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if epochOf(user).tokenStale(claims.Iat) {
		return errSessionEnded
	}
	return nil
}

// sameAs reports whether two reads saw the same epoch.
func (e credentialEpoch) sameAs(o credentialEpoch) bool {
	if e.at == nil || o.at == nil {
		return e.at == o.at
	}
	return e.at.Equal(*o.at)
}

// loginEpoch reads the epoch of the account behind email before its password
// is checked; no such account reads as never taken over.
func (s *Service) loginEpoch(ctx context.Context, email string) (credentialEpoch, error) {
	user, err := s.userStore.GetByEmail(ctx, email)
	switch {
	case err == nil:
		return epochOf(user), nil
	case errors.Is(err, store.ErrUserNotFound):
		return credentialEpoch{}, nil
	default:
		return credentialEpoch{}, fmt.Errorf("get user by email: %w", err)
	}
}

// refuseLoginAfterTakeover ends the session just issued if the account was
// taken over while the login ran: its epoch differs from the one read before
// the password check. No clocks are compared. A takeover committed before
// the password read leaves no password to check; one committed before the
// session was saved is seen here; one committed after the save ends the
// session itself (the postgres claim makes the save wait for it otherwise).
func (s *Service) refuseLoginAfterTakeover(ctx context.Context, userID string, pair *entity.TokenPair, before credentialEpoch) error {
	user, err := s.userStore.GetByID(ctx, userID)
	if err != nil {
		return &accountError{accountChange{userID: userID}, fmt.Errorf("get user: %w", err)}
	}
	if epochOf(user).sameAs(before) {
		return nil
	}
	if err := s.tokenStore.RevokeTokens(ctx, token.HashToken(pair.RefreshToken)); err != nil {
		return &accountError{accountChange{userID: userID}, fmt.Errorf("revoke session after takeover: %w", err)}
	}
	return &CredentialsError{Reason: ReasonNoPassword, UserID: userID}
}

// createSessionPAT is CreatePAT for a caller authenticated by claims. A
// takeover committed between the session check and the save may have missed
// the new token (the postgres claim blocks the save until it commits), so the
// check runs again; the token is deleted unless it passes.
func (s *Service) createSessionPAT(ctx context.Context, claims *entity.Claims, name string, scopes []string, expiresAt *time.Time) (*PATResult, error) {
	result, err := s.CreatePAT(ctx, claims.UserID, name, scopes, expiresAt)
	if err != nil {
		return nil, err
	}
	if err := s.checkSessionEpoch(ctx, claims); err != nil {
		if _, delErr := s.patStore.DeletePAT(ctx, claims.UserID, result.Token.ID); delErr != nil {
			return nil, fmt.Errorf("delete pat after takeover: %w", delErr)
		}
		return nil, err
	}
	return result, nil
}
