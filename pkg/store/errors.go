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
)
