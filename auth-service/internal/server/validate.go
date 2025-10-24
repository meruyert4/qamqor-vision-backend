package server

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

// Custom password validator
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Check minimum length
	if len(password) < 8 {
		return false
	}

	// Must contain at least one uppercase letter
	hasUpper, _ := regexp.MatchString(`[A-Z]`, password)
	if !hasUpper {
		return false
	}

	// Must contain at least one lowercase letter
	hasLower, _ := regexp.MatchString(`[a-z]`, password)
	if !hasLower {
		return false
	}

	// Must contain at least one number
	hasNumber, _ := regexp.MatchString(`[0-9]`, password)
	if !hasNumber {
		return false
	}

	// Must contain at least one special character
	hasSpecial, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password)
	if !hasSpecial {
		return false
	}

	return true
}

// Custom name validator
func validateName(fl validator.FieldLevel) bool {
	name := strings.TrimSpace(fl.Field().String())

	// Check for emptiness
	if name == "" {
		return false
	}

	// Check for allowed characters (letters, spaces, hyphens, apostrophes)
	matched, _ := regexp.MatchString(`^[a-zA-Z\s\-']+$`, name)
	if !matched {
		return false
	}

	// Check minimum length
	if len(name) < 2 {
		return false
	}

	// Check maximum length
	if len(name) > 50 {
		return false
	}

	return true
}

// Custom UUID validator
func validateUUID(fl validator.FieldLevel) bool {
	uuid := fl.Field().String()

	// Basic UUID format check (8-4-4-4-12 pattern)
	if len(uuid) != 36 {
		return false
	}

	// Check for hyphens at correct positions
	expectedHyphens := []int{8, 13, 18, 23}
	for _, pos := range expectedHyphens {
		if uuid[pos] != '-' {
			return false
		}
	}

	// Check that all other characters are hexadecimal
	for i, char := range uuid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue // Skip hyphen positions
		}
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f') ||
			(char >= 'A' && char <= 'F')) {
			return false
		}
	}

	return true
}

func init() {
	validate = validator.New()

	// Register custom validators
	validate.RegisterValidation("password", validatePassword)
	validate.RegisterValidation("name", validateName)
	validate.RegisterValidation("uuid", validateUUID)
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidateStruct validates a struct and returns formatted errors
func ValidateStruct(s interface{}) []ValidationError {
	var errors []ValidationError

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var message string

			switch err.Tag() {
			case "required":
				message = fmt.Sprintf("%s is required", err.Field())
			case "email":
				message = fmt.Sprintf("%s must be a valid email address", err.Field())
			case "password":
				message = fmt.Sprintf("%s must be at least 8 characters long and contain uppercase, lowercase, number, and special character", err.Field())
			case "name":
				message = fmt.Sprintf("%s must contain only letters, spaces, hyphens, and apostrophes (2-50 characters)", err.Field())
			case "uuid":
				message = fmt.Sprintf("%s must be a valid UUID", err.Field())
			case "min":
				message = fmt.Sprintf("%s must be at least %s characters long", err.Field(), err.Param())
			case "max":
				message = fmt.Sprintf("%s must be at most %s characters long", err.Field(), err.Param())
			default:
				message = fmt.Sprintf("%s is invalid", err.Field())
			}

			errors = append(errors, ValidationError{
				Field:   err.Field(),
				Tag:     err.Tag(),
				Value:   fmt.Sprintf("%v", err.Value()),
				Message: message,
			})
		}
	}

	return errors
}
