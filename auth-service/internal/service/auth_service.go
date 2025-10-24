package service

import (
	"fmt"
	"net/smtp"
	"time"

	"auth-service/config"
	"auth-service/internal/models"
	"auth-service/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo         *repository.UserRepository
	loginHistoryRepo *repository.LoginHistoryRepository
	config           *config.Config
}

func NewAuthService(userRepo *repository.UserRepository, loginHistoryRepo *repository.LoginHistoryRepository, config *config.Config) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		loginHistoryRepo: loginHistoryRepo,
		config:           config,
	}
}

func (s *AuthService) CreateUser(req *models.CreateUserRequest) (*models.User, error) {
	// Check if user already exists
	existingUser, _ := s.userRepo.GetUserByEmail(req.Email)
	if existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user, err := s.userRepo.CreateUser(req, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Send verification email
	go s.sendVerificationEmail(user)

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

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// Log failed login attempt
		reason := "invalid password"
		s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		// Log failed login attempt
		reason := "token generation failed"
		s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		// Log failed login attempt
		reason := "refresh token generation failed"
		s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusFailed, &reason)
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Log successful login
	s.logLoginAttempt(user.ID, ipAddress, userAgent, models.LoginStatusSuccess, nil)

	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

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

func (s *AuthService) UpdateUser(id string, updates map[string]interface{}) (*models.User, error) {
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
	return s.userRepo.DeleteUser(id)
}

func (s *AuthService) VerifyUser(id, token string) error {
	// In a real implementation, you would verify the JWT token
	// For simplicity, we'll just verify the user
	return s.userRepo.VerifyUser(id)
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
	go s.sendResetPasswordEmail(user, resetToken)

	return nil
}

func (s *AuthService) ResetPassword(email, newPassword, token string) error {
	// In a real implementation, you would verify the reset token
	// For simplicity, we'll just update the password
	user, err := s.userRepo.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	updates := map[string]interface{}{
		"password_hash": string(hashedPassword),
	}
	_, err = s.userRepo.UpdateUser(user.ID, updates)
	return err
}

func (s *AuthService) generateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
		"type":    "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *AuthService) generateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(),
		"type":    "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *AuthService) generateResetToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
		"type":    "reset",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.VerificationSecret))
}

func (s *AuthService) sendVerificationEmail(user *models.User) error {
	if s.config.SMTPUsername == "" || s.config.SMTPPassword == "" {
		return nil // Skip email if SMTP not configured
	}

	// Generate verification token
	verificationToken, err := s.generateVerificationToken(user.ID)
	if err != nil {
		return err
	}

	verificationURL := fmt.Sprintf("%s/verify?token=%s", s.config.FrontendURL, verificationToken)

	subject := "QAMQOR-VISION: Email Verification Link"
	body := fmt.Sprintf(`
		Hello %s %s,
		
		Please click the link below to verify your email address:
		%s
		
		If you didn't create an account, please ignore this email.
	`, user.FirstName, user.LastName, verificationURL)

	return s.sendEmail(user.Email, subject, body)
}

func (s *AuthService) sendResetPasswordEmail(user *models.User, resetToken string) error {
	if s.config.SMTPUsername == "" || s.config.SMTPPassword == "" {
		return nil // Skip email if SMTP not configured
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.config.FrontendURL, resetToken)

	subject := "QAMQOR-VISION: Password Reset Link"
	body := fmt.Sprintf(`
		Hello %s %s,
		
		Please click the link below to reset your password:
		%s
		
		This link will expire in 1 hour.
		
		If you didn't request this, please ignore this email.
	`, user.FirstName, user.LastName, resetURL)

	return s.sendEmail(user.Email, subject, body)
}

func (s *AuthService) generateVerificationToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
		"type":    "verification",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.VerificationSecret))
}

func (s *AuthService) sendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, subject, body))

	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)
	return smtp.SendMail(addr, auth, s.config.SMTPFrom, []string{to}, msg)
}
