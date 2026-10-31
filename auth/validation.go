package auth

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Password constraints
const (
	MinPasswordLength = 8
	MaxPasswordLength = 128

	// MaxEmailLength is the RFC 5321 path limit (254 octets), which also fits
	// the varchar(255) email columns; a longer value would fail the insert
	// as a storage error instead of a rejected input.
	MaxEmailLength = 254
)

// ErrPasswordTooShort is returned when password is shorter than MinPasswordLength.
var ErrPasswordTooShort = errors.New("password must be at least 8 characters")

// ErrPasswordTooLong is returned when password is longer than MaxPasswordLength.
var ErrPasswordTooLong = errors.New("password must be at most 128 characters")

// ErrInvalidEmail is returned when email format is invalid.
var ErrInvalidEmail = errors.New("invalid email format")

// ValidatePassword checks password meets requirements.
// OWASP/NIST: length matters, complexity doesn't.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if utf8.RuneCountInString(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}

// NormalizeEmail normalizes and validates email address.
// Applies: trim whitespace, lowercase.
// Validates: contains @ and ., length bounds, no control characters.
func NormalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)

	if len(email) < 5 || len(email) > MaxEmailLength {
		return "", ErrInvalidEmail
	}
	// No legitimate address carries control characters. NUL in particular
	// would reach Postgres, which rejects it in text: a storage failure
	// (500 + ERROR log) instead of a rejected credential.
	if strings.IndexFunc(email, unicode.IsControl) >= 0 {
		return "", ErrInvalidEmail
	}
	if !strings.Contains(email, "@") {
		return "", ErrInvalidEmail
	}
	// Check for domain part with dot
	atIndex := strings.LastIndex(email, "@")
	domain := email[atIndex+1:]
	if !strings.Contains(domain, ".") {
		return "", ErrInvalidEmail
	}

	return email, nil
}
