package validation

import (
	"fmt"
	"strings"

	"auth-service/internal/models"

	"github.com/go-playground/validator/v10"
)

type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

func buildValidationError(err validator.FieldError) ValidationError {
	var message string

	switch err.Tag() {
	case "required":
		message = fmt.Sprintf("%s is required", err.Field())
	case "email":
		message = "Please provide a valid email address"
	case "password":
		message = "Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character"
	case "name":
		message = "Name must contain only letters, spaces, hyphens, and apostrophes (2-50 characters)"
	case "uuid":
		message = "Please provide a valid ID"
	case "role":
		message = fmt.Sprintf("Invalid role. Available roles are: %s", strings.Join(models.GetAllRoles(), ", "))
	case "min":
		message = fmt.Sprintf("%s must be at least %s characters long", err.Field(), err.Param())
	case "max":
		message = fmt.Sprintf("%s must be at most %s characters long", err.Field(), err.Param())
	default:
		message = fmt.Sprintf("%s is invalid", err.Field())
	}

	return ValidationError{
		Field:   err.Field(),
		Tag:     err.Tag(),
		Value:   fmt.Sprintf("%v", err.Value()),
		Message: message,
	}
}
