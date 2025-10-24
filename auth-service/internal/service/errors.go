package service

import (
	"errors"
)

// Custom error types for better error handling
var (
	ErrUserAlreadyExists  = errors.New("user with this email already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token has expired")
	ErrPasswordMismatch   = errors.New("password mismatch")
	ErrValidationFailed   = errors.New("validation failed")
	ErrDatabaseError      = errors.New("database error")
	ErrEmailSendFailed    = errors.New("failed to send email")
)

// ErrorType represents the type of error
type ErrorType int

const (
	ErrorTypeValidation ErrorType = iota
	ErrorTypeAlreadyExists
	ErrorTypeNotFound
	ErrorTypeUnauthorized
	ErrorTypeInternal
	ErrorTypeBadRequest
)

// ServiceError wraps errors with additional context
type ServiceError struct {
	Type    ErrorType
	Message string
	Err     error
}

func (e *ServiceError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

// NewServiceError creates a new service error
func NewServiceError(errorType ErrorType, message string, err error) *ServiceError {
	return &ServiceError{
		Type:    errorType,
		Message: message,
		Err:     err,
	}
}

// IsUserAlreadyExists checks if the error is a user already exists error
func IsUserAlreadyExists(err error) bool {
	return errors.Is(err, ErrUserAlreadyExists)
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	return errors.Is(err, ErrValidationFailed)
}

// IsUserNotFound checks if the error is a user not found error
func IsUserNotFound(err error) bool {
	return errors.Is(err, ErrUserNotFound)
}

// IsInvalidCredentials checks if the error is an invalid credentials error
func IsInvalidCredentials(err error) bool {
	return errors.Is(err, ErrInvalidCredentials)
}
