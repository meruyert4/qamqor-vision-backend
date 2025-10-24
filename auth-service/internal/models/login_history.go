package models

import "time"

// LoginStatus represents the status of a login attempt
type LoginStatus string

const (
	LoginStatusSuccess LoginStatus = "success"
	LoginStatusFailed  LoginStatus = "failed"
	LoginStatusBlocked LoginStatus = "blocked"
)

// UserLoginHistory represents a user login attempt record
type UserLoginHistory struct {
	ID            string      `json:"id" db:"id"`
	UserID        string      `json:"user_id" db:"user_id"`
	IPAddress     string      `json:"ip_address" db:"ip_address"`
	UserAgent     *string     `json:"user_agent,omitempty" db:"user_agent"`
	LoginStatus   LoginStatus `json:"login_status" db:"login_status"`
	FailureReason *string     `json:"failure_reason,omitempty" db:"failure_reason"`
	CreatedAt     time.Time   `json:"created_at" db:"created_at"`
}

// CreateLoginHistoryRequest represents the request to create a login history record
type CreateLoginHistoryRequest struct {
	UserID        string      `json:"user_id"`
	IPAddress     string      `json:"ip_address"`
	UserAgent     *string     `json:"user_agent,omitempty"`
	LoginStatus   LoginStatus `json:"login_status"`
	FailureReason *string     `json:"failure_reason,omitempty"`
}
