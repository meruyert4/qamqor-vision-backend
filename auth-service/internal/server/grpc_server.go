package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"auth-service/config"
	"auth-service/internal/models"
	"auth-service/internal/server/validation"
	"auth-service/internal/service"

	pb "github.com/meruyert4/qamqor-vision-backend/proto/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type GRPCServer struct {
	pb.UnimplementedAuthServiceServer
	authService *service.AuthService
}

func NewGRPCServer(authService *service.AuthService) *GRPCServer {
	return &GRPCServer{
		authService: authService,
	}
}

func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getClientIP extracts the client IP address from the gRPC context
func (s *GRPCServer) getClientIP(ctx context.Context) string {
	// Try to get IP from peer info
	if peer, ok := peer.FromContext(ctx); ok {
		if tcpAddr, ok := peer.Addr.(*net.TCPAddr); ok {
			return tcpAddr.IP.String()
		}
	}
	return "unknown"
}

// getUserAgent extracts the user agent from the gRPC context metadata
func (s *GRPCServer) getUserAgent(ctx context.Context) *string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	if userAgents := md.Get("user-agent"); len(userAgents) > 0 {
		return &userAgents[0]
	}

	return nil
}

// getAuthToken extracts the authorization token from gRPC context metadata
func (s *GRPCServer) getAuthToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata found")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", fmt.Errorf("authorization header not found")
	}

	token := authHeaders[0]
	token = strings.TrimPrefix(token, "Bearer ")
	return token, nil
}

// getCurrentUser extracts the current user from the JWT token in the gRPC context
func (s *GRPCServer) getCurrentUser(ctx context.Context) (*models.User, error) {
	token, err := s.getAuthToken(ctx)
	if err != nil {
		return nil, err
	}

	userID, _, err := s.authService.GetUserFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	user, err := s.authService.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return user, nil
}

func (s *GRPCServer) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	createReq := &models.CreateUserRequest{
		Email:                      req.Email,
		Password:                   req.Password,
		FirstName:                  req.FirstName,
		LastName:                   req.LastName,
		PhoneNumber:                req.PhoneNumber,
		PushNotificationPermission: req.PushNotificationPermission,
		Role:                       getStringValue(req.Role),
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(createReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	_, err := s.authService.CreateUser(createReq)
	if err != nil {
		if err == service.ErrUserAlreadyExists {
			return nil, status.Errorf(codes.AlreadyExists, "user with this email already exists")
		}
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return &pb.CreateUserResponse{
		Message: "User created successfully. Verify your email",
	}, nil
}

func (s *GRPCServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	loginReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(loginReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	// Extract IP address and user agent from context
	ipAddress := s.getClientIP(ctx)
	userAgent := s.getUserAgent(ctx)

	response, err := s.authService.LoginWithHistory(loginReq, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "please verify your email first" {
			return nil, status.Errorf(codes.PermissionDenied, "please verify your email first")
		}
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials: %v", err)
	}

	return &pb.LoginResponse{
		AccessToken: response.AccessToken,
		User: &pb.User{
			Id:                         response.User.ID,
			Email:                      response.User.Email,
			FirstName:                  response.User.FirstName,
			LastName:                   response.User.LastName,
			PhoneNumber:                getStringValue(response.User.PhoneNumber),
			PushNotificationPermission: response.User.PushNotificationPermission,
			Role:                       response.User.Role,
			CreatedAt:                  response.User.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}, nil
}

func (s *GRPCServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	getReq := &models.GetUserRequest{
		ID: req.Id,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(getReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	// Get current user from token
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Non-admin users can only access their own data
	if currentUser.Role != models.AdminRole && currentUser.ID != req.Id {
		return nil, status.Errorf(codes.PermissionDenied, "you don't have permission to access this user's data")
	}

	user, err := s.authService.GetUser(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	return &pb.GetUserResponse{
		User: &pb.User{
			Id:                         user.ID,
			Email:                      user.Email,
			FirstName:                  user.FirstName,
			LastName:                   user.LastName,
			PhoneNumber:                getStringValue(user.PhoneNumber),
			PushNotificationPermission: user.PushNotificationPermission,
			Role:                       user.Role,
			CreatedAt:                  user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}, nil
}

func (s *GRPCServer) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	updateReq := &models.UpdateUserRequest{
		Email:                      req.Email,
		FirstName:                  req.FirstName,
		LastName:                   req.LastName,
		PhoneNumber:                req.PhoneNumber,
		PushNotificationPermission: req.PushNotificationPermission,
		Role:                       req.Role,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(updateReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	user, err := s.authService.UpdateUser(req.Id, updateReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	return &pb.UpdateUserResponse{
		User: &pb.User{
			Id:                         user.ID,
			Email:                      user.Email,
			FirstName:                  user.FirstName,
			LastName:                   user.LastName,
			PhoneNumber:                getStringValue(user.PhoneNumber),
			PushNotificationPermission: user.PushNotificationPermission,
			Role:                       user.Role,
			CreatedAt:                  user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}, nil
}

func (s *GRPCServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	changeReq := &models.ChangePasswordRequest{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(changeReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	err := s.authService.ChangePassword(req.Id, req.OldPassword, req.NewPassword)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to change password: %v", err)
	}

	return &pb.ChangePasswordResponse{Success: true}, nil
}

func (s *GRPCServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	deleteReq := &models.DeleteUserRequest{
		ID: req.Id,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(deleteReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	// Get current user from token
	currentUser, err := s.getCurrentUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Non-admin users can only delete their own account
	if currentUser.Role != models.AdminRole && currentUser.ID != req.Id {
		return nil, status.Errorf(codes.PermissionDenied, "you don't have permission to delete this user")
	}

	err = s.authService.DeleteUser(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user: %v", err)
	}

	return &pb.DeleteUserResponse{Success: true}, nil
}

func (s *GRPCServer) VerifyUser(ctx context.Context, req *pb.VerifyUserRequest) (*pb.VerifyUserResponse, error) {
	verifyReq := &models.VerifyUserRequest{
		Token: req.Token,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(verifyReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	err := s.authService.VerifyUser(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to verify user: %v", err)
	}

	return &pb.VerifyUserResponse{Success: true}, nil
}

func (s *GRPCServer) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	forgotReq := &models.ForgotPasswordRequest{
		Email: req.Email,
	}

	// Validate the request
	if validationErrors := validation.ValidateStruct(forgotReq); len(validationErrors) > 0 {
		// Format validation errors for gRPC response
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Message)
		}
		formattedError := strings.Join(errorMessages, "; ")
		return nil, status.Errorf(codes.InvalidArgument, formattedError)
	}

	err := s.authService.ForgotPassword(req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to process forgot password: %v", err)
	}

	return &pb.ForgotPasswordResponse{Success: true}, nil
}

func (s *GRPCServer) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	// Use the existing ResetPassword method from auth service
	newPassword, err := s.authService.ResetPassword(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to reset password: %v", err)
	}

	return &pb.ResetPasswordResponse{
		Success:     true,
		NewPassword: newPassword,
	}, nil
}

// ValidateToken validates a JWT token and returns user information
func (s *GRPCServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	// Validate the token and extract user information
	userID, _, err := s.authService.GetUserFromToken(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	// Get user details from database
	user, err := s.authService.GetUser(userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	return &pb.ValidateTokenResponse{
		Valid: true,
		User: &pb.User{
			Id:                         user.ID,
			Email:                      user.Email,
			FirstName:                  user.FirstName,
			LastName:                   user.LastName,
			PhoneNumber:                getStringValue(user.PhoneNumber),
			PushNotificationPermission: user.PushNotificationPermission,
			Role:                       user.Role,
			CreatedAt:                  user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}, nil
}

func (s *GRPCServer) GetUserLoginHistory(ctx context.Context, req *pb.GetUserLoginHistoryRequest) (*pb.GetUserLoginHistoryResponse, error) {
	historyReq := &models.GetUserLoginHistoryRequest{
		UserID: req.UserId,
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	// Validate the request
	if errors := validation.ValidateStruct(historyReq); len(errors) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "validation failed: %v", errors)
	}

	histories, err := s.authService.GetUserLoginHistory(req.UserId, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get user login history: %v", err)
	}

	var pbHistories []*pb.UserLoginHistory
	for _, history := range histories {
		pbHistories = append(pbHistories, &pb.UserLoginHistory{
			Id:            history.ID,
			UserId:        history.UserID,
			IpAddress:     history.IPAddress,
			UserAgent:     getStringValue(history.UserAgent),
			LoginStatus:   string(history.LoginStatus),
			FailureReason: getStringValue(history.FailureReason),
			CreatedAt:     history.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	return &pb.GetUserLoginHistoryResponse{
		LoginHistory: pbHistories,
	}, nil
}

func (s *GRPCServer) GetRecentLoginHistory(ctx context.Context, req *pb.GetRecentLoginHistoryRequest) (*pb.GetRecentLoginHistoryResponse, error) {
	recentReq := &models.GetRecentLoginHistoryRequest{
		UserID: req.UserId,
	}

	// Validate the request
	if errors := validation.ValidateStruct(recentReq); len(errors) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "validation failed: %v", errors)
	}

	histories, err := s.authService.GetRecentLoginHistory(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get recent login history: %v", err)
	}

	var pbHistories []*pb.UserLoginHistory
	for _, history := range histories {
		pbHistories = append(pbHistories, &pb.UserLoginHistory{
			Id:            history.ID,
			UserId:        history.UserID,
			IpAddress:     history.IPAddress,
			UserAgent:     getStringValue(history.UserAgent),
			LoginStatus:   string(history.LoginStatus),
			FailureReason: getStringValue(history.FailureReason),
			CreatedAt:     history.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	return &pb.GetRecentLoginHistoryResponse{
		LoginHistory: pbHistories,
	}, nil
}

func (s *GRPCServer) GetFailedLoginAttempts(ctx context.Context, req *pb.GetFailedLoginAttemptsRequest) (*pb.GetFailedLoginAttemptsResponse, error) {
	failedReq := &models.GetFailedLoginAttemptsRequest{
		UserID: req.UserId,
		Since:  req.Since,
	}

	// Validate the request
	if errors := validation.ValidateStruct(failedReq); len(errors) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "validation failed: %v", errors)
	}

	since, err := time.Parse("2006-01-02T15:04:05Z", req.Since)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid since timestamp: %v", err)
	}

	histories, err := s.authService.GetFailedLoginAttempts(req.UserId, since)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get failed login attempts: %v", err)
	}

	var pbHistories []*pb.UserLoginHistory
	for _, history := range histories {
		pbHistories = append(pbHistories, &pb.UserLoginHistory{
			Id:            history.ID,
			UserId:        history.UserID,
			IpAddress:     history.IPAddress,
			UserAgent:     getStringValue(history.UserAgent),
			LoginStatus:   string(history.LoginStatus),
			FailureReason: getStringValue(history.FailureReason),
			CreatedAt:     history.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	return &pb.GetFailedLoginAttemptsResponse{
		FailedAttempts: pbHistories,
	}, nil
}

func StartGRPCServer(cfg *config.Config, authService *service.AuthService) error {
	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, NewGRPCServer(authService))

	log.Printf("gRPC server starting on port %s", cfg.GRPCPort)
	return grpcServer.Serve(lis)
}
