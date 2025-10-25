package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/models"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(user *models.CreateUserRequest, passwordHash string) (*models.User, error) {
	id := uuid.New().String()
	now := time.Now()

	query := `
		INSERT INTO users (id, email, password_hash, first_name, last_name, phone_number, 
		                  push_notification_permission, role, is_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, email, first_name, last_name, phone_number, 
		          push_notification_permission, role, is_verified, created_at, updated_at`

	var createdUser models.User
	err := r.db.QueryRow(query, id, user.Email, passwordHash, user.FirstName, user.LastName,
		user.PhoneNumber, user.PushNotificationPermission, user.Role, false, now, now).Scan(
		&createdUser.ID, &createdUser.Email, &createdUser.FirstName, &createdUser.LastName,
		&createdUser.PhoneNumber, &createdUser.PushNotificationPermission, &createdUser.Role,
		&createdUser.IsVerified, &createdUser.CreatedAt, &createdUser.UpdatedAt)

	fmt.Println("createdUser", createdUser)
	fmt.Println("err", err)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &createdUser, nil
}

func (r *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, phone_number,
		       push_notification_permission, role, is_verified, created_at, updated_at
		FROM users WHERE email = $1`

	var user models.User
	err := r.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.PhoneNumber, &user.PushNotificationPermission, &user.Role,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) GetUserByID(id string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, phone_number,
		       push_notification_permission, role, is_verified, created_at, updated_at
		FROM users WHERE id = $1`

	var user models.User
	err := r.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.PhoneNumber, &user.PushNotificationPermission, &user.Role,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) UpdateUser(id string, updates map[string]interface{}) (*models.User, error) {
	if len(updates) == 0 {
		return r.GetUserByID(id)
	}

	setParts := []string{}
	args := []interface{}{}
	argIndex := 1

	for key, value := range updates {
		if value != nil {
			setParts = append(setParts, fmt.Sprintf("%s = $%d", key, argIndex))
			args = append(args, value)
			argIndex++
		}
	}

	// Add updated_at
	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIndex))
	args = append(args, time.Now())
	argIndex++

	// Add WHERE clause
	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE users SET %s
		WHERE id = $%d
		RETURNING id, email, first_name, last_name, phone_number,
		          push_notification_permission, role, is_verified, created_at, updated_at`,
		strings.Join(setParts, ", "), argIndex)

	var user models.User
	err := r.db.QueryRow(query, args...).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName,
		&user.PhoneNumber, &user.PushNotificationPermission, &user.Role,
		&user.IsVerified, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) DeleteUser(id string) error {
	query := "DELETE FROM users WHERE id = $1"
	_, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (r *UserRepository) VerifyUser(id string) error {
	query := "UPDATE users SET is_verified = true, updated_at = $1 WHERE id = $2"
	_, err := r.db.Exec(query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to verify user: %w", err)
	}
	return nil
}
