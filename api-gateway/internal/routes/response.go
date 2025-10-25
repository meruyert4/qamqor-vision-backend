package routes

import (
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// HandleAuthError extracts error messages from gRPC errors and returns appropriate HTTP status code and structured error
func HandleAuthError(err error) (int, ErrorResponse) {
	if err == nil {
		return http.StatusOK, ErrorResponse{}
	}

	// Check if this is a gRPC status error
	if st, ok := status.FromError(err); ok {
		// Extract the error message
		message := st.Message()

		// Map gRPC status codes to HTTP status codes
		switch st.Code() {
		case codes.InvalidArgument:
			return http.StatusBadRequest, ErrorResponse{
				Error:   "Invalid request",
				Message: message,
			}
		case codes.NotFound:
			return http.StatusNotFound, ErrorResponse{
				Error:   "Not found",
				Message: message,
			}
		case codes.AlreadyExists:
			return http.StatusConflict, ErrorResponse{
				Error:   "User already exists",
				Message: "A user with this email address already exists",
			}
		case codes.Unauthenticated:
			return http.StatusUnauthorized, ErrorResponse{
				Error:   "Authentication required",
				Message: message,
			}
		case codes.PermissionDenied:
			return http.StatusForbidden, ErrorResponse{
				Error:   "Permission denied",
				Message: message,
			}
		case codes.Unavailable:
			return http.StatusServiceUnavailable, ErrorResponse{
				Error:   "Service unavailable",
				Message: "The authentication service is temporarily unavailable",
			}
		case codes.DeadlineExceeded:
			return http.StatusRequestTimeout, ErrorResponse{
				Error:   "Request timeout",
				Message: "The request timed out",
			}
		default:
			return http.StatusInternalServerError, ErrorResponse{
				Error:   "Internal server error",
				Message: message,
			}
		}
	}

	// Fallback for non-gRPC errors - extract message from error string
	rawError := err.Error()
	if strings.Contains(rawError, "desc = ") {
		parts := strings.Split(rawError, "desc = ")
		if len(parts) > 1 {
			rawError = parts[1]
		}
	}

	// Handle legacy string-based error detection for backward compatibility
	switch {
	case strings.Contains(rawError, "user with this email already exists"):
		return http.StatusConflict, ErrorResponse{
			Error:   "User already exists",
			Message: "A user with this email address already exists",
		}
	case strings.Contains(rawError, "validation failed"):
		return http.StatusBadRequest, ErrorResponse{
			Error:   "Validation failed",
			Message: rawError,
		}
	case strings.Contains(rawError, "invalid argument"):
		return http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid request",
			Message: rawError,
		}
	case strings.Contains(rawError, "user not found"):
		return http.StatusNotFound, ErrorResponse{
			Error:   "User not found",
			Message: "The requested user does not exist",
		}
	case strings.Contains(rawError, "invalid credentials"):
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "Invalid credentials",
			Message: "The provided email or password is incorrect",
		}
	case strings.Contains(rawError, "invalid or expired token"):
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "Invalid token",
			Message: "The provided token is invalid or has expired",
		}
	case strings.Contains(rawError, "unauthorized"):
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "Unauthorized",
			Message: rawError,
		}
	case strings.Contains(rawError, "not found"):
		return http.StatusNotFound, ErrorResponse{
			Error:   "Not found",
			Message: rawError,
		}
	default:
		return http.StatusInternalServerError, ErrorResponse{
			Error:   "Internal server error",
			Message: rawError,
		}
	}
}
