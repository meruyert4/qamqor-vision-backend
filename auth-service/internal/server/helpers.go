package server

import (
	"context"
	"fmt"
	"net"
	"strings"

	"auth-service/internal/middleware"
	"auth-service/internal/models"
	"auth-service/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getClientIP extracts the client IP address from the gRPC context
func getClientIP(ctx context.Context) string {
	// Try to get IP from peer info
	if peer, ok := peer.FromContext(ctx); ok {
		if tcpAddr, ok := peer.Addr.(*net.TCPAddr); ok {
			return tcpAddr.IP.String()
		}
	}
	return "unknown"
}

// getUserAgent extracts the user agent from the gRPC context metadata
func getUserAgent(ctx context.Context) *string {
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
func getAuthToken(ctx context.Context) (string, error) {
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
func getCurrentUser(ctx context.Context, authService *service.AuthService) (*models.User, error) {
	token, err := getAuthToken(ctx)
	if err != nil {
		return nil, err
	}

	userID, _, err := authService.GetUserFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	user, err := authService.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return user, nil
}

// checkPermission checks if the current user has permission to access the endpoint
func checkPermission(ctx context.Context, authService *service.AuthService, method, path string) error {
	// Get current user
	user, err := getCurrentUser(ctx, authService)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Check permission using RBAC middleware
	if !middleware.HasAccess(method, path, user.Role) {
		return status.Errorf(codes.PermissionDenied, "insufficient permissions")
	}

	return nil
}

// checkOwnResourcePermission checks if user can access their own resource or if admin
func checkOwnResourcePermission(ctx context.Context, authService *service.AuthService, resourceUserID string) error {
	// Get current user
	user, err := getCurrentUser(ctx, authService)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Check if user can access this resource (own resource or admin)
	if !middleware.CanAccessOwnResource(user.ID, resourceUserID, user.Role) {
		return status.Errorf(codes.PermissionDenied, "you don't have permission to access this resource")
	}

	return nil
}
