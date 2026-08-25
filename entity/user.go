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
}
