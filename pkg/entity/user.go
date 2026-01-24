package entity

import "time"

// User represents an authenticated user in the system.
type User struct {
	ID        string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}
