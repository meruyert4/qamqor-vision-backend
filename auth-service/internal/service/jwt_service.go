package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles JWT token operations
type JWTService struct {
	secretKey []byte
}

// JWTClaims represents the claims in the JWT token
type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// NewJWTService creates a new JWT service instance
func NewJWTService(secretKey string) *JWTService {
	return &JWTService{
		secretKey: []byte(secretKey),
	}
}

// GenerateAccessToken creates a new JWT access token for the user
// Token expires in 15 minutes and contains user_id and email claims
func (j *JWTService) GenerateAccessToken(userID, email string) (string, error) {
	// Set token expiration to 15 minutes from now
	expirationTime := time.Now().Add(15 * time.Minute)

	// Create claims with user information
	claims := &JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "qamqor-vision-auth",
			Subject:   userID,
		},
	}

	// Create token with HMAC SHA256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims
// Returns error if token is invalid, expired, or malformed
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method is HMAC SHA256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if token is valid
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Additional validation: check if token is not expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// ExtractUserID extracts the user ID from a valid JWT token
// This is a convenience method that validates and extracts user ID in one call
func (j *JWTService) ExtractUserID(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	if claims.UserID == "" {
		return "", errors.New("user ID not found in token claims")
	}

	return claims.UserID, nil
}

// ExtractEmail extracts the email from a valid JWT token
// This is a convenience method that validates and extracts email in one call
func (j *JWTService) ExtractEmail(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	if claims.Email == "" {
		return "", errors.New("email not found in token claims")
	}

	return claims.Email, nil
}

// IsTokenExpired checks if a token is expired without full validation
// Useful for quick expiration checks
func (j *JWTService) IsTokenExpired(tokenString string) bool {
	// Parse without validation to check expiration
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secretKey, nil
	})

	if err != nil {
		return true // Consider invalid tokens as expired
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return true
	}

	// Check if token is expired
	return claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now())
}
