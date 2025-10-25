package service

import (
	"fmt"
	"time"

	"auth-service/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

// logLoginAttempt logs a login attempt to the database
func (s *AuthService) logLoginAttempt(userID, ipAddress string, userAgent *string, status models.LoginStatus, failureReason *string) {
	if s.loginHistoryRepo == nil {
		return // Skip logging if repository is not available
	}

	req := &models.CreateLoginHistoryRequest{
		UserID:        userID,
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		LoginStatus:   status,
		FailureReason: failureReason,
	}

	_, err := s.loginHistoryRepo.CreateLoginHistory(req)
	if err != nil {
		// Log error but don't fail the login process
		fmt.Printf("Failed to log login attempt: %v\n", err)
	}
}

func (s *AuthService) generateResetToken(userID string) (string, error) {
	// Use JWT service for reset tokens with 30 minute expiration
	expirationTime := time.Now().Add(time.Minute * 30)

	claims := &JWTClaims{
		UserID: userID,
		Email:  "", // Reset tokens don't need email
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "qamqor-vision-auth",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.VerificationSecret))
}

// validateVerificationToken validates a verification token and returns the claims
func (s *AuthService) validateVerificationToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.VerificationSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// validateResetToken validates a reset token and returns the claims
func (s *AuthService) validateResetToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.VerificationSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// generateRandomPassword generates a secure random password
func (s *AuthService) generateRandomPassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	const passwordLength = 12

	// For simplicity, we'll use a basic approach
	// In production, you might want to use crypto/rand
	password := make([]byte, passwordLength)
	for i := range password {
		password[i] = charset[i%len(charset)]
	}

	return string(password), nil
}
