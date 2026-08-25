package auth

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Password constraints
const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
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
// Validates: contains @ and ., minimum length.
func NormalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)

	if len(email) < 5 {
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
