package service

import (
	"fmt"
	"time"

	"auth-service/config"
	"auth-service/internal/models"
	"auth-service/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo         *repository.UserRepository
	loginHistoryRepo *repository.LoginHistoryRepository
	jwtService       *JWTService
	config           *config.Config
}

func NewAuthService(userRepo *repository.UserRepository, loginHistoryRepo *repository.LoginHistoryRepository, config *config.Config) *AuthService {
	jwtService := NewJWTService(config.JWTSecret)
	return &AuthService{
		userRepo:         userRepo,
		loginHistoryRepo: loginHistoryRepo,
		jwtService:       jwtService,
		config:           config,
	}
}

func (s *AuthService) CreateUser(req *models.CreateUserRequest) (*models.User, error) {
	// Check if user already exists
	existingUser, _ := s.userRepo.GetUserByEmail(req.Email)
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}
	// Set default role if not provided
	if req.Role == "" {
		req.Role = models.GetDefaultRole()
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user, err := s.userRepo.CreateUser(req, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Send verification email
	if err := s.sendVerificationEmail(user); err != nil {
		fmt.Printf("Failed to send verification email: %v\n", err)
		// Don't fail user creation if email fails
	}

	return user, nil
}

func (s *AuthService) Login(req *models.LoginRequest) (*models.LoginResponse, error) {
	return s.LoginWithHistory(req, "", nil)
}

// LoginWithHistory performs login with IP address and user agent logging
func (s *AuthService) LoginWithHistory(req *models.LoginRequest, ipAddress string, userAgent *string) (*models.LoginResponse, error) {
	// Get user by email
	user, err := s.userRepo.GetUserByEmail(req.Email)
	if err != nil {
		// Log failed login attempt
		if user != nil {
			reason := "user not found"
			s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		}
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if email is verified
	if !user.IsVerified {
		// Log failed login attempt
		reason := "email not verified"
		s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		return nil, fmt.Errorf("please verify your email first")
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// Log failed login attempt
		reason := "invalid password"
		s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate JWT access token
	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		// Log failed login attempt
		reason := "token generation failed"
		s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Log successful login
	s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusSuccess, nil)

	return &models.LoginResponse{
		AccessToken: accessToken,
		User:        user,
	}, nil
}

func (s *AuthService) GetUser(id string) (*models.User, error) {
	return s.userRepo.GetUserByID(id)
}

// GetUserLoginHistory retrieves login history for a user
func (s *AuthService) GetUserLoginHistory(userID string, limit, offset int) ([]*models.UserLoginHistory, error) {
	if s.loginHistoryRepo == nil {
		return nil, fmt.Errorf("login history repository not available")
	}
	return s.loginHistoryRepo.GetUserLoginHistory(userID, limit, offset)
}

// GetRecentLoginHistory gets recent login history for a user
func (s *AuthService) GetRecentLoginHistory(userID string) ([]*models.UserLoginHistory, error) {
	if s.loginHistoryRepo == nil {
		return nil, fmt.Errorf("login history repository not available")
	}
	return s.loginHistoryRepo.GetRecentLoginHistory(userID)
}

// GetFailedLoginAttempts gets failed login attempts for a user within a time window
func (s *AuthService) GetFailedLoginAttempts(userID string, since time.Time) ([]*models.UserLoginHistory, error) {
	if s.loginHistoryRepo == nil {
		return nil, fmt.Errorf("login history repository not available")
	}
	return s.loginHistoryRepo.GetFailedLoginAttempts(userID, since)
}

func (s *AuthService) UpdateUser(id string, req *models.UpdateUserRequest) (*models.User, error) {
	updates := map[string]interface{}{
		"email":                        req.Email,
		"first_name":                   req.FirstName,
		"last_name":                    req.LastName,
		"phone_number":                 req.PhoneNumber,
		"push_notification_permission": req.PushNotificationPermission,
	}

	// Add role if provided
	if req.Role != nil {
		updates["role"] = *req.Role
	}

	return s.userRepo.UpdateUser(id, updates)
}

func (s *AuthService) ChangePassword(id, oldPassword, newPassword string) error {
	user, err := s.userRepo.GetUserByID(id)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify old password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		return fmt.Errorf("invalid old password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password
	updates := map[string]interface{}{
		"password_hash": string(hashedPassword),
	}
	_, err = s.userRepo.UpdateUser(id, updates)
	return err
}

func (s *AuthService) DeleteUser(id string) error {
	user, err := s.userRepo.GetUserByID(id)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	// Send account deletion email
	if err := s.sendAccountDeletionEail(user); err != nil {
		fmt.Printf("Failed to send account deletion info email: %v\n", err)
	}
	return s.userRepo.DeleteUser(id)
}

func (s *AuthService) VerifyUser(token string) error {
	// Validate the verification token
	claims, err := s.validateVerificationToken(token)
	if err != nil {
		return fmt.Errorf("invalid or expired verification token: %w", err)
	}

	// Verify the user
	return s.userRepo.VerifyUser(claims.UserID)
}

func (s *AuthService) ForgotPassword(email string) error {
	user, err := s.userRepo.GetUserByEmail(email)
	if err != nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate reset token
	resetToken, err := s.generateResetToken(user.ID)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Send reset email
	if err := s.sendResetPasswordEmail(user, resetToken); err != nil {
		fmt.Printf("Failed to send reset password email: %v\n", err)
		// Don't fail the request if email fails
	}

	return nil
}

func (s *AuthService) ResetPassword(token string) (string, error) {
	// Validate the reset token
	claims, err := s.validateResetToken(token)
	if err != nil {
		return "", fmt.Errorf("invalid or expired reset token: %w", err)
	}

	// Get user by ID
	user, err := s.userRepo.GetUserByID(claims.UserID)
	if err != nil {
		return "", fmt.Errorf("user not found")
	}

	// Generate a new random password
	newPassword, err := s.generateRandomPassword()
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	updates := map[string]interface{}{
		"password_hash": string(hashedPassword),
	}
	_, err = s.userRepo.UpdateUser(user.ID, updates)
	if err != nil {
		return "", fmt.Errorf("failed to update password: %w", err)
	}

	return newPassword, nil
}

// GetUserFromToken extracts user information from a JWT token
// Returns user ID and email from token claims
func (s *AuthService) GetUserFromToken(tokenString string) (userID, email string, err error) {
	claims, err := s.jwtService.ValidateToken(tokenString)
	if err != nil {
		return "", "", err
	}
	return claims.UserID, claims.Email, nil
}
