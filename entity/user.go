package entity

import "time"

// User represents an authenticated user in the system.
type User struct {
	ID    string
	Email string
	// Roles are opaque strings emitted in JWT claims and Verify responses.
	// psina never interprets them; authorization is the application's job.
	Roles     []string
	CreatedAt time.Time
	UpdatedAt time.Time
	// CredentialsChangedAt is when the account was last taken from the holder
	// of its credentials (a provider-verified sign-in dropped its unproven
	// password). Access tokens issued and sessions started before it are
	// refused for account actions. nil: never.
	CredentialsChangedAt *time.Time
}
