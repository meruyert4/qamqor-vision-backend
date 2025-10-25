package models

// User represents a user in the system
type User struct {
	ID                         string  `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Email                      string  `json:"email" example:"user@example.com"`
	FirstName                  string  `json:"first_name" example:"John"`
	LastName                   string  `json:"last_name" example:"Doe"`
	PhoneNumber                *string `json:"phone_number,omitempty" example:"+1234567890"`
	PushNotificationPermission bool    `json:"push_notification_permission" example:"true"`
	Role                       string  `json:"role" example:"user"`
	CreatedAt                  string  `json:"created_at" example:"2023-01-01T00:00:00Z"`
}

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Email                      string  `json:"email" binding:"required,email" example:"user@example.com"`
	Password                   string  `json:"password" binding:"required" example:"Password123!"`
	FirstName                  string  `json:"first_name" binding:"required" example:"John"`
	LastName                   string  `json:"last_name" binding:"required" example:"Doe"`
	PhoneNumber                *string `json:"phone_number,omitempty" example:"+1234567890"`
	PushNotificationPermission bool    `json:"push_notification_permission" example:"true"`
	Role                       string  `json:"role,omitempty" example:"user"`
}

// RegisterResponse represents the response for user registration
type RegisterResponse struct {
	Message string `json:"message" example:"User created successfully"`
	User    *User  `json:"user"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"Password123!"`
}

// LoginResponse represents the response for user login
type LoginResponse struct {
	Message      string `json:"message" example:"Login successful"`
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	User         *User  `json:"user"`
}

// ForgotPasswordRequest represents the request body for forgot password
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
}

// ResetPasswordRequest represents the request body for password reset
type ResetPasswordRequest struct {
	Email       string `json:"email" binding:"required,email" example:"user@example.com"`
	NewPassword string `json:"new_password" binding:"required,min=6" example:"newpassword123"`
	Token       string `json:"token" binding:"required" example:"reset_token_here"`
}

// UpdateUserRequest represents the request body for updating user information
type UpdateUserRequest struct {
	Email                      *string `json:"email,omitempty" example:"newemail@example.com"`
	FirstName                  *string `json:"first_name,omitempty" example:"Jane"`
	LastName                   *string `json:"last_name,omitempty" example:"Smith"`
	PhoneNumber                *string `json:"phone_number,omitempty" example:"+1234567890"`
	PushNotificationPermission *bool   `json:"push_notification_permission,omitempty" example:"true"`
	Role                       *string `json:"role,omitempty" example:"manager"`
}

// ChangePasswordRequest represents the request body for changing password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required" example:"oldpassword123"`
	NewPassword string `json:"new_password" binding:"required,min=6" example:"newpassword123"`
}

// UserResponse represents the response for user operations
type UserResponse struct {
	Message string `json:"message" example:"User retrieved successfully"`
	User    *User  `json:"user"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Message string `json:"message" example:"Operation successful"`
	Success bool   `json:"success" example:"true"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"Error message"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string `json:"status" example:"ok"`
}
