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

	// ErrCredentialNotFound indicates no credentials exist for the user.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrOAuthIdentityNotFound indicates no OAuth identity matches the lookup.
	ErrOAuthIdentityNotFound = errors.New("oauth identity not found")

	// ErrWalletIdentityNotFound indicates no wallet identity matches the lookup.
	ErrWalletIdentityNotFound = errors.New("wallet identity not found")

	// ErrChallengeNotFound indicates no challenge exists for the given nonce.
	ErrChallengeNotFound = errors.New("challenge not found")

	// ErrChallengeExpired indicates the challenge exists but has expired.
	ErrChallengeExpired = errors.New("challenge expired")
)
