package routes

import (
	"net/http"
	"strings"
)

// HandleAuthError extracts pretty error messages from gRPC errors and returns appropriate HTTP status code and message
func HandleAuthError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	// Default values
	statusCode := http.StatusInternalServerError
	errorMessage := "Internal server error"

	// Extract the actual error message from gRPC error format
	// Format: "rpc error: code = Internal desc = user with this email already exists"
	if strings.Contains(err.Error(), "desc = ") {
		parts := strings.Split(err.Error(), "desc = ")
		if len(parts) > 1 {
			errorMessage = parts[1]
		}
	}

	// Map specific error messages to appropriate HTTP status codes
	switch {
	case strings.Contains(err.Error(), "user with this email already exists"):
		statusCode = http.StatusConflict
		errorMessage = "User with this email already exists"
	case strings.Contains(err.Error(), "validation failed"):
		statusCode = http.StatusBadRequest
		// Keep the original validation error message
	case strings.Contains(err.Error(), "invalid argument"):
		statusCode = http.StatusBadRequest
		// Keep the original error message
	case strings.Contains(err.Error(), "user not found"):
		statusCode = http.StatusNotFound
		errorMessage = "User not found"
	case strings.Contains(err.Error(), "invalid credentials"):
		statusCode = http.StatusUnauthorized
		errorMessage = "Invalid credentials"
	case strings.Contains(err.Error(), "invalid or expired token"):
		statusCode = http.StatusUnauthorized
		errorMessage = "Invalid or expired token"
	case strings.Contains(err.Error(), "unauthorized"):
		statusCode = http.StatusUnauthorized
		// Keep the original error message
	case strings.Contains(err.Error(), "not found"):
		statusCode = http.StatusNotFound
		// Keep the original error message
	}

	return statusCode, errorMessage
}
