package service

import (
	"auth-service/internal/models"
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type EmailTemplateData struct {
	FirstName       string
	LastName        string
	VerificationURL string
	ResetURL        string
}

func (s *AuthService) sendVerificationEmail(user *models.User) error {
	// Generate verification token
	verificationToken, err := s.generateVerificationToken(user.ID)
	if err != nil {
		return err
	}

	verificationURL := fmt.Sprintf("%s/verify?token=%s", s.config.FrontendURL, verificationToken)
	subject := "QAMQOR VISION: Email Verification Required"

	// Load and parse HTML template
	tmpl, err := template.ParseFiles(filepath.Join("internal/service/email_templates", "email_verification.html"))
	if err != nil {
		return fmt.Errorf("failed to load email template: %w", err)
	}

	// Prepare template data
	data := EmailTemplateData{
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		VerificationURL: verificationURL,
	}

	// Execute template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	fmt.Printf("=== EMAIL VERIFICATION ===\n")
	fmt.Printf("From: %s\n", s.config.SMTPFrom)
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("Verification URL: %s\n", verificationURL)
	fmt.Printf("Body:\n%s\n", body.String())
	fmt.Printf("========================\n")

	if s.config.SMTPUsername == "" || s.config.SMTPPassword == "" {
		fmt.Printf("SMTP not configured, email not sent (test mode)\n")
		return nil // Skip email if SMTP not configured
	}

	return s.sendHTMLEmail(user.Email, subject, body.String())
}

func (s *AuthService) sendResetPasswordEmail(user *models.User, resetToken string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.config.FrontendURL, resetToken)
	subject := "QAMQOR VISION: Password Reset Request"

	// Load and parse HTML template
	tmpl, err := template.ParseFiles(filepath.Join("internal/service/email_templates", "reset_password.html"))
	if err != nil {
		return fmt.Errorf("failed to load email template: %w", err)
	}

	// Prepare template data
	data := EmailTemplateData{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		ResetURL:  resetURL,
	}

	// Execute template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	fmt.Printf("=== PASSWORD RESET EMAIL ===\n")
	fmt.Printf("From: %s\n", s.config.SMTPFrom)
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("Reset URL: %s\n", resetURL)
	fmt.Printf("Body:\n%s\n", body.String())
	fmt.Printf("===========================\n")

	if s.config.SMTPUsername == "" || s.config.SMTPPassword == "" {
		fmt.Printf("SMTP not configured, email not sent (test mode)\n")
		return nil // Skip email if SMTP not configured
	}

	return s.sendHTMLEmail(user.Email, subject, body.String())
}

func (s *AuthService) sendAccountDeletionEail(user *models.User) error {
	subject := "Your QAMQOR VISION Account Has Been Deleted"
	// Load and parse HTML template
	tmpl, err := template.ParseFiles(filepath.Join("internal/service/email_templates", "account_deletion.html"))
	if err != nil {
		return fmt.Errorf("failed to load email template: %w", err)
	}

	// Prepare template data
	data := EmailTemplateData{
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	// Execute template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	if s.config.SMTPUsername == "" || s.config.SMTPPassword == "" {
		fmt.Printf("SMTP not configured, email not sent (test mode)\n")
		return nil // Skip email if SMTP not configured
	}

	return s.sendHTMLEmail(user.Email, subject, body.String())
}

func (s *AuthService) generateVerificationToken(userID string) (string, error) {
	// Use JWT service for verification tokens with 5 minute expiration
	expirationTime := time.Now().Add(time.Minute * 5)

	claims := &JWTClaims{
		UserID: userID,
		Email:  "", // Verification tokens don't need email
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

func (s *AuthService) sendHTMLEmail(to, subject, htmlBody string) error {
	auth := smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)

	// Create MIME message
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		s.config.SMTPFrom, to, subject, htmlBody))

	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)

	fmt.Printf("SMTP Config - Host: %s, Port: %d, Username: %s, From: %s\n",
		s.config.SMTPHost, s.config.SMTPPort, s.config.SMTPUsername, s.config.SMTPFrom)
	fmt.Printf("Sending email from: %s to: %s via %s\n", s.config.SMTPFrom, to, addr)

	err := smtp.SendMail(addr, auth, s.config.SMTPFrom, []string{to}, msg)
	if err != nil {
		fmt.Printf("Failed to send email: %v\n", err)
		return err
	}

	fmt.Printf("Email sent successfully from: %s to: %s\n", s.config.SMTPFrom, to)
	return nil
}
