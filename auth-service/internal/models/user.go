package models

import (
	"time"
)

type User struct {
	ID                         string    `json:"id" db:"id"`
	Email                      string    `json:"email" db:"email"`
	PasswordHash               string    `json:"-" db:"password_hash"`
	FirstName                  string    `json:"first_name" db:"first_name"`
	LastName                   string    `json:"last_name" db:"last_name"`
	PhoneNumber                *string   `json:"phone_number" db:"phone_number"`
	PushNotificationPermission bool      `json:"push_notification_permission" db:"push_notification_permission"`
	Role                       string    `json:"role" db:"role"`
	IsVerified                 bool      `json:"is_verified" db:"is_verified"`
	CreatedAt                  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at" db:"updated_at"`
}

type CreateUserRequest struct {
	Email                      string  `json:"email" validate:"required,email"`
	Password                   string  `json:"password" validate:"required,password"`
	FirstName                  string  `json:"first_name" validate:"required,name"`
	LastName                   string  `json:"last_name" validate:"required,name"`
	PhoneNumber                *string `json:"phone_number,omitempty" validate:"omitempty,min=10,max=15"`
	PushNotificationPermission bool    `json:"push_notification_permission"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	User        *User  `json:"user"`
}

// UpdateUserRequest represents the request to update user information
type UpdateUserRequest struct {
	Email                      *string `json:"email,omitempty" validate:"omitempty,email"`
	FirstName                  *string `json:"first_name,omitempty" validate:"omitempty,name"`
	LastName                   *string `json:"last_name,omitempty" validate:"omitempty,name"`
	PhoneNumber                *string `json:"phone_number,omitempty" validate:"omitempty,min=10,max=15"`
	PushNotificationPermission *bool   `json:"push_notification_permission,omitempty"`
}

// ChangePasswordRequest represents the request to change password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,password"`
}

// VerifyUserRequest represents the request to verify user email
type VerifyUserRequest struct {
	Token string `json:"token" validate:"required,min=10"`
}

// ForgotPasswordRequest represents the request to initiate password reset
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest represents the request to reset password
type ResetPasswordRequest struct {
	Email       string `json:"email" validate:"required,email"`
	NewPassword string `json:"new_password" validate:"required,password"`
	Token       string `json:"token" validate:"required,min=10"`
}

// GetUserRequest represents the request to get user by ID
type GetUserRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

// DeleteUserRequest represents the request to delete user
type DeleteUserRequest struct {
	ID string `json:"id" validate:"required,uuid"`
}

// GetUserLoginHistoryRequest represents the request to get user login history
type GetUserLoginHistoryRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Limit  int32  `json:"limit" validate:"min=1,max=100"`
	Offset int32  `json:"offset" validate:"min=0"`
}

// GetRecentLoginHistoryRequest represents the request to get recent login history
type GetRecentLoginHistoryRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

// GetFailedLoginAttemptsRequest represents the request to get failed login attempts
type GetFailedLoginAttemptsRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Since  string `json:"since" validate:"required"`
}
