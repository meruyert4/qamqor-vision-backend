package validation

import (
	"regexp"
	"strings"

	"auth-service/internal/models"

	"github.com/go-playground/validator/v10"
)

func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	if len(password) < 8 {
		return false
	}

	hasUpper, _ := regexp.MatchString(`[A-Z]`, password)
	hasLower, _ := regexp.MatchString(`[a-z]`, password)
	hasNumber, _ := regexp.MatchString(`[0-9]`, password)
	hasSpecial, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password)

	return hasUpper && hasLower && hasNumber && hasSpecial
}

func validateName(fl validator.FieldLevel) bool {
	name := strings.TrimSpace(fl.Field().String())
	if name == "" || len(name) < 2 || len(name) > 50 {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z\s\-']+$`, name)
	return matched
}

func validateUUID(fl validator.FieldLevel) bool {
	uuid := fl.Field().String()
	if len(uuid) != 36 {
		return false
	}

	expectedHyphens := []int{8, 13, 18, 23}
	for _, pos := range expectedHyphens {
		if uuid[pos] != '-' {
			return false
		}
	}

	for i, char := range uuid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f') ||
			(char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func validateEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	if email == "" {
		return false
	}
	regex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return regex.MatchString(email)
}

func validateRole(fl validator.FieldLevel) bool {
	role := fl.Field().String()
	if role == "" {
		return true
	}
	return models.IsValidRole(role)
}
