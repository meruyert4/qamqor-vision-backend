package middleware

import (
	"auth-service/internal/models"
	"strings"
)

// PermissionMap maps API endpoints to allowed roles
var PermissionMap = map[string][]string{
	// Public endpoints (no authentication required)
	"POST:/api/v1/register":        {},
	"POST:/api/v1/login":           {},
	"POST:/api/v1/forgot-password": {},
	"GET:/api/v1/reset-password":   {},
	"GET:/api/v1/verify":           {},
	"GET:/health":                  {},

	// User profile endpoints (users can access their own data)
	"GET:/api/v1/users/me": {models.AdminRole, models.UserRole},

	// User management endpoints
	"GET:/api/v1/users/:id":          {models.AdminRole, models.UserRole}, // Users can view their own profile
	"PUT:/api/v1/users/:id":          {models.AdminRole, models.UserRole}, // Users can update their own profile
	"PUT:/api/v1/users/:id/password": {models.AdminRole, models.UserRole}, // Users can change their own password
	"DELETE:/api/v1/users/:id":       {models.AdminRole, models.UserRole}, // Users can delete their own account

	// Login history endpoints
	"GET:/api/v1/users/:id/login-history":   {models.AdminRole, models.UserRole}, // Users can view their own history
	"GET:/api/v1/users/:id/recent-logins":   {models.AdminRole, models.UserRole}, // Users can view their own recent logins
	"GET:/api/v1/users/:id/failed-attempts": {models.AdminRole, models.UserRole}, // Users can view their own failed attempts
}

// HasAccess checks if a user role has permission to access an endpoint
func HasAccess(method, path string, userRole string) bool {
	// Normalize the path by removing query parameters
	normalizedPath := strings.Split(path, "?")[0]
	key := method + ":" + normalizedPath

	// Check for exact match first
	if roles, ok := PermissionMap[key]; ok {
		return hasRole(roles, userRole)
	}

	// Check for wildcard patterns (e.g., /users/:id)
	for pattern, roles := range PermissionMap {
		if strings.Contains(pattern, ":") && matchWildcard(pattern, key) {
			if hasRole(roles, userRole) {
				return true
			}
		}
	}

	return false
}

// hasRole checks if the user role is in the allowed roles list
func hasRole(allowedRoles []string, userRole string) bool {
	for _, role := range allowedRoles {
		if role == userRole {
			return true
		}
	}
	return false
}

// matchWildcard matches patterns with wildcards (e.g., /users/:id matches /users/123)
func matchWildcard(pattern, path string) bool {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i := range patternParts {
		// If pattern part starts with ':', it's a wildcard
		if strings.HasPrefix(patternParts[i], ":") {
			continue
		}
		// Otherwise, parts must match exactly
		if patternParts[i] != pathParts[i] {
			return false
		}
	}

	return true
}

// CanAccessOwnResource checks if a user can access their own resource
// This is used for endpoints where users can only access their own data
func CanAccessOwnResource(userID, resourceUserID, userRole string) bool {
	// Admins can access any resource
	if userRole == models.AdminRole {
		return true
	}

	// Users can only access their own resources
	return userID == resourceUserID
}
