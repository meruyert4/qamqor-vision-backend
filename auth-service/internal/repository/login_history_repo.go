package repository

import (
	"auth-service/internal/models"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type LoginHistoryRepository struct {
	db *sql.DB
}

func NewLoginHistoryRepository(db *sql.DB) *LoginHistoryRepository {
	return &LoginHistoryRepository{db: db}
}

// CreateLoginHistory creates a new login history record
func (r *LoginHistoryRepository) CreateLoginHistory(req *models.CreateLoginHistoryRequest) (*models.UserLoginHistory, error) {
	id := uuid.New().String()

	query := `
		INSERT INTO user_login_history (id, user_id, ip_address, user_agent, login_status, failure_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, ip_address, user_agent, login_status, failure_reason, created_at
	`

	var history models.UserLoginHistory
	err := r.db.QueryRow(query, id, req.UserID, req.IPAddress, req.UserAgent, req.LoginStatus, req.FailureReason, time.Now()).Scan(
		&history.ID, &history.UserID, &history.IPAddress, &history.UserAgent,
		&history.LoginStatus, &history.FailureReason, &history.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create login history: %w", err)
	}

	return &history, nil
}

// GetUserLoginHistory retrieves login history for a specific user
func (r *LoginHistoryRepository) GetUserLoginHistory(userID string, limit int, offset int) ([]*models.UserLoginHistory, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, login_status, failure_reason, created_at
		FROM user_login_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Query(query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get user login history: %w", err)
	}
	defer rows.Close()

	var histories []*models.UserLoginHistory
	for rows.Next() {
		var history models.UserLoginHistory
		err := rows.Scan(
			&history.ID, &history.UserID, &history.IPAddress, &history.UserAgent,
			&history.LoginStatus, &history.FailureReason, &history.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan login history: %w", err)
		}
		histories = append(histories, &history)
	}

	return histories, nil
}

// GetFailedLoginAttempts gets failed login attempts for a user within a time window
func (r *LoginHistoryRepository) GetFailedLoginAttempts(userID string, since time.Time) ([]*models.UserLoginHistory, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, login_status, failure_reason, created_at
		FROM user_login_history
		WHERE user_id = $1 AND login_status = 'failed' AND created_at >= $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, userID, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get failed login attempts: %w", err)
	}
	defer rows.Close()

	var histories []*models.UserLoginHistory
	for rows.Next() {
		var history models.UserLoginHistory
		err := rows.Scan(
			&history.ID, &history.UserID, &history.IPAddress, &history.UserAgent,
			&history.LoginStatus, &history.FailureReason, &history.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan failed login attempt: %w", err)
		}
		histories = append(histories, &history)
	}

	return histories, nil
}

// GetFailedLoginAttemptsByIP gets failed login attempts from a specific IP within a time window
func (r *LoginHistoryRepository) GetFailedLoginAttemptsByIP(ipAddress string, since time.Time) ([]*models.UserLoginHistory, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, login_status, failure_reason, created_at
		FROM user_login_history
		WHERE ip_address = $1 AND login_status = 'failed' AND created_at >= $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, ipAddress, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get failed login attempts by IP: %w", err)
	}
	defer rows.Close()

	var histories []*models.UserLoginHistory
	for rows.Next() {
		var history models.UserLoginHistory
		err := rows.Scan(
			&history.ID, &history.UserID, &history.IPAddress, &history.UserAgent,
			&history.LoginStatus, &history.FailureReason, &history.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan failed login attempt: %w", err)
		}
		histories = append(histories, &history)
	}

	return histories, nil
}

// GetRecentLoginHistory gets recent login history for a user (last 10 logins)
func (r *LoginHistoryRepository) GetRecentLoginHistory(userID string) ([]*models.UserLoginHistory, error) {
	return r.GetUserLoginHistory(userID, 10, 0)
}
