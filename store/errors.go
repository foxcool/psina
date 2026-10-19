package store

import "errors"

// Store errors for use with errors.Is().
var (
	// ErrUserNotFound indicates the requested user does not exist.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates a user with the given email already exists.
	ErrUserExists = errors.New("user already exists")

	// ErrTokenNotFound indicates the requested refresh token does not exist.
	ErrTokenNotFound = errors.New("refresh token not found")

	// ErrTokenRevoked indicates the refresh token was already revoked or rotated.
	ErrTokenRevoked = errors.New("refresh token revoked")

	// ErrTokenExpired indicates the refresh token exists but has expired.
	ErrTokenExpired = errors.New("refresh token expired")

	// ErrCredentialNotFound indicates no credentials exist for the user.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrOAuthIdentityNotFound indicates no OAuth identity matches the lookup.
	ErrOAuthIdentityNotFound = errors.New("oauth identity not found")

	// ErrOAuthIdentityExists indicates the (provider, external id) pair is
	// already linked to a user.
	ErrOAuthIdentityExists = errors.New("oauth identity already exists")

	// ErrWalletIdentityNotFound indicates no wallet identity matches the lookup.
	ErrWalletIdentityNotFound = errors.New("wallet identity not found")

	// ErrChallengeNotFound indicates no challenge exists for the given nonce.
	ErrChallengeNotFound = errors.New("challenge not found")

	// ErrChallengeExpired indicates the challenge exists but has expired.
	ErrChallengeExpired = errors.New("challenge expired")
)
