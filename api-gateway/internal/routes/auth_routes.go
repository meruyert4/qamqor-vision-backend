package routes

import (
	"net/http"
	"strconv"

	"api-gateway/internal/client"
	"api-gateway/internal/models"

	pb "github.com/meruyert4/qamqor-vision-backend/proto/auth"

	"github.com/gin-gonic/gin"
)

// Register godoc
// @Summary User Registration
// @Description Register a new user with email, password, and personal information
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "User registration data"
// @Success 201 {object} models.RegisterResponse
// @Failure 400 {object} models.ErrorResponse
// @Router /api/v1/register [post]

type AuthRoutes struct {
	authClient *client.AuthClient
}

func NewAuthRoutes(authClient *client.AuthClient) *AuthRoutes {
	return &AuthRoutes{
		authClient: authClient,
	}
}

func (r *AuthRoutes) Register(c *gin.Context) {
	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grpcReq := &pb.CreateUserRequest{
		Email:                      req.Email,
		Password:                   req.Password,
		FirstName:                  req.FirstName,
		LastName:                   req.LastName,
		PhoneNumber:                req.PhoneNumber,
		PushNotificationPermission: req.PushNotificationPermission,
	}

	resp, err := r.authClient.CreateUser(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user":    resp.User,
	})
}

// Login godoc
// @Summary User Login
// @Description Login user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Router /api/v1/login [post]
func (r *AuthRoutes) Login(c *gin.Context) {
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grpcReq := &pb.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := r.authClient.Login(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"access_token": resp.AccessToken,
		"user":         resp.User,
	})
}

// GetUser godoc
// @Summary Get User
// @Description Get user by ID
// @Tags Users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Router /api/v1/users/{id} [get]
func (r *AuthRoutes) GetUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	grpcReq := &pb.GetUserRequest{
		Id: userID,
	}

	resp, err := r.authClient.GetUser(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": resp.User,
	})
}

func (r *AuthRoutes) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	var req struct {
		Email                      *string `json:"email,omitempty"`
		FirstName                  *string `json:"first_name,omitempty"`
		LastName                   *string `json:"last_name,omitempty"`
		PhoneNumber                *string `json:"phone_number,omitempty"`
		PushNotificationPermission *bool   `json:"push_notification_permission,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grpcReq := &pb.UpdateUserRequest{
		Id:                         userID,
		Email:                      req.Email,
		FirstName:                  req.FirstName,
		LastName:                   req.LastName,
		PhoneNumber:                req.PhoneNumber,
		PushNotificationPermission: req.PushNotificationPermission,
	}

	resp, err := r.authClient.UpdateUser(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
		"user":    resp.User,
	})
}

func (r *AuthRoutes) ChangePassword(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grpcReq := &pb.ChangePasswordRequest{
		Id:          userID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}

	resp, err := r.authClient.ChangePassword(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
		"success": resp.Success,
	})
}

func (r *AuthRoutes) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	grpcReq := &pb.DeleteUserRequest{
		Id: userID,
	}

	resp, err := r.authClient.DeleteUser(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
		"success": resp.Success,
	})
}

func (r *AuthRoutes) VerifyUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Verification token is required"})
		return
	}

	grpcReq := &pb.VerifyUserRequest{
		Id:    userID,
		Token: token,
	}

	resp, err := r.authClient.VerifyUser(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User verified successfully",
		"success": resp.Success,
	})
}

func (r *AuthRoutes) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grpcReq := &pb.ForgotPasswordRequest{
		Email: req.Email,
	}

	resp, err := r.authClient.ForgotPassword(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset email sent",
		"success": resp.Success,
	})
}

func (r *AuthRoutes) ResetPassword(c *gin.Context) {
	var req struct {
		Email       string `json:"email" binding:"required,email"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
		Token       string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	grpcReq := &pb.ResetPasswordRequest{
		Email:       req.Email,
		NewPassword: req.NewPassword,
		Token:       req.Token,
	}

	resp, err := r.authClient.ResetPassword(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successfully",
		"success": resp.Success,
	})
}

// GetUserLoginHistory godoc
// @Summary Get User Login History
// @Description Get paginated login history for a specific user
// @Tags Users
// @Produce json
// @Param id path string true "User ID"
// @Param limit query int false "Number of records to return" default(10)
// @Param offset query int false "Number of records to skip" default(0)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/users/{id}/login-history [get]
func (r *AuthRoutes) GetUserLoginHistory(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Parse query parameters
	limit := 10
	offset := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	grpcReq := &pb.GetUserLoginHistoryRequest{
		UserId: userID,
		Limit:  int32(limit),
		Offset: int32(offset),
	}

	resp, err := r.authClient.GetUserLoginHistory(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"login_history": resp.LoginHistory,
		"success":       true,
		"limit":         limit,
		"offset":        offset,
	})
}

// GetRecentLoginHistory godoc
// @Summary Get Recent Login History
// @Description Get recent login history for a specific user (last 10 logins)
// @Tags Users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/users/{id}/recent-logins [get]
func (r *AuthRoutes) GetRecentLoginHistory(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	grpcReq := &pb.GetRecentLoginHistoryRequest{
		UserId: userID,
	}

	resp, err := r.authClient.GetRecentLoginHistory(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"login_history": resp.LoginHistory,
		"success":       true,
	})
}

// GetFailedLoginAttempts godoc
// @Summary Get Failed Login Attempts
// @Description Get failed login attempts for a specific user within a time window
// @Tags Users
// @Produce json
// @Param id path string true "User ID"
// @Param since query string true "Start time in ISO format (e.g., 2023-01-01T00:00:00Z)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/users/{id}/failed-attempts [get]
func (r *AuthRoutes) GetFailedLoginAttempts(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	since := c.Query("since")
	if since == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Since parameter is required (ISO timestamp format)"})
		return
	}

	grpcReq := &pb.GetFailedLoginAttemptsRequest{
		UserId: userID,
		Since:  since,
	}

	resp, err := r.authClient.GetFailedLoginAttempts(c.Request.Context(), grpcReq)
	if err != nil {
		statusCode, errorResponse := HandleAuthError(err)
		c.JSON(statusCode, errorResponse)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"failed_attempts": resp.FailedAttempts,
		"success":         true,
		"since":           since,
	})
}

// GetProfile godoc
// @Summary Get Current User Profile
// @Description Get current user's profile information from JWT token
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} models.ErrorResponse
// @Router /api/v1/users/me [get]
func (r *AuthRoutes) GetProfile(c *gin.Context) {
	// Get user information from JWT middleware context
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":    user,
		"message": "Profile retrieved successfully",
	})
}
