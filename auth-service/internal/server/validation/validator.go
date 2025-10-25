package validation

import (
	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validators
	validate.RegisterValidation("password", validatePassword)
	validate.RegisterValidation("name", validateName)
	validate.RegisterValidation("uuid", validateUUID)
	validate.RegisterValidation("email", validateEmail)
	validate.RegisterValidation("role", validateRole)
}

func ValidateStruct(s interface{}) []ValidationError {
	var errors []ValidationError
	if err := validate.Struct(s); err != nil {
		for _, e := range err.(validator.ValidationErrors) {
			errors = append(errors, buildValidationError(e))
		}
	}
	return errors
}
