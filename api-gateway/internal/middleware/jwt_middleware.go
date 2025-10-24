package middleware

import (
	"context"
	"net/http"
	"strings"

	"api-gateway/internal/client"

	pb "github.com/meruyert4/qamqor-vision-backend/proto/auth"

	"github.com/gin-gonic/gin"
)

// UserContextKey is the key used to store user information in the request context
const UserContextKey = "user_id"

// JWTMiddleware validates JWT tokens and extracts user information
// It attaches the user ID to the request context for use in handlers
func JWTMiddleware(authClient *client.AuthClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Check if the header starts with "Bearer "
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format. Expected: Bearer <token>",
			})
			c.Abort()
			return
		}

		token := tokenParts[1]
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token is required",
			})
			c.Abort()
			return
		}

		// Validate token with auth service
		grpcReq := &pb.ValidateTokenRequest{
			Token: token,
		}

		resp, err := authClient.ValidateToken(c.Request.Context(), grpcReq)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		if !resp.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Attach user information to the request context
		ctx := context.WithValue(c.Request.Context(), UserContextKey, resp.User.Id)
		c.Request = c.Request.WithContext(ctx)

		// Store user information in Gin context for easy access
		c.Set("user_id", resp.User.Id)
		c.Set("user_email", resp.User.Email)
		c.Set("user", resp.User)

		// Continue to the next handler
		c.Next()
	}
}

// GetUserIDFromContext extracts the user ID from the request context
// This is a helper function for handlers to get the authenticated user's ID
func GetUserIDFromContext(c *gin.Context) (string, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return "", false
	}

	return userIDStr, true
}

// RequireAuth is a convenience function that combines JWT middleware with a check
// Use this for routes that require authentication
func RequireAuth(authClient *client.AuthClient) gin.HandlerFunc {
	return JWTMiddleware(authClient)
}
