package health

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	pb "github.com/meruyert4/qamqor-vision-backend/proto/auth"

	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type HealthChecker struct {
	authServiceAddr string
	databaseURL     string
}

type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp string                 `json:"timestamp"`
	Services  map[string]ServiceInfo `json:"services"`
	Overall   bool                   `json:"overall_healthy"`
}

type ServiceInfo struct {
	Status       string `json:"status"`
	Message      string `json:"message"`
	ResponseTime string `json:"response_time,omitempty"`
}

func NewHealthChecker(authServiceAddr, databaseURL string) *HealthChecker {
	return &HealthChecker{
		authServiceAddr: authServiceAddr,
		databaseURL:     databaseURL,
	}
}

func (h *HealthChecker) CheckAllServices() HealthStatus {
	now := time.Now()
	services := make(map[string]ServiceInfo)

	// Check Auth Service (gRPC)
	authStatus := h.checkAuthService()
	services["auth-service"] = authStatus

	// Check Database
	dbStatus := h.checkDatabase()
	services["auth-db"] = dbStatus

	// Check API Gateway (self)
	apiStatus := h.checkAPIGateway()
	services["api-gateway"] = apiStatus

	// Determine overall health
	overallHealthy := authStatus.Status == "healthy" &&
		dbStatus.Status == "healthy" &&
		apiStatus.Status == "healthy"

	status := "unhealthy"
	if overallHealthy {
		status = "healthy"
	}

	return HealthStatus{
		Status:    status,
		Timestamp: now.Format(time.RFC3339),
		Services:  services,
		Overall:   overallHealthy,
	}
}

func (h *HealthChecker) checkAuthService() ServiceInfo {
	start := time.Now()

	// Create gRPC connection
	conn, err := grpc.Dial(h.authServiceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return ServiceInfo{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Failed to connect to auth service: %v", err),
		}
	}
	defer conn.Close()

	// Create client and make a test call
	client := pb.NewAuthServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to get a user (this will fail but we can check if the service responds)
	_, err = client.GetUser(ctx, &pb.GetUserRequest{Id: "e7358487-73e6-414f-81cd-11a316c832f9"})
	responseTime := time.Since(start).String()

	// We expect this to fail with "user not found" or similar, but the service should respond
	if err != nil {
		// Check if it's a gRPC error (service is responding)
		if _, ok := err.(interface{ Code() string }); ok {
			// Service is responding, just user not found
			return ServiceInfo{
				Status:       "healthy",
				Message:      "Auth service is responding",
				ResponseTime: responseTime,
			}
		}
		// Check if it's a context timeout or connection error
		if ctx.Err() == context.DeadlineExceeded {
			return ServiceInfo{
				Status:  "unhealthy",
				Message: "Auth service timeout",
			}
		}
		// Other gRPC errors might indicate service issues
		return ServiceInfo{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Auth service error: %v", err),
		}
	}

	return ServiceInfo{
		Status:       "healthy",
		Message:      "Auth service is responding",
		ResponseTime: responseTime,
	}
}

func (h *HealthChecker) checkDatabase() ServiceInfo {
	start := time.Now()

	// Connect to database
	db, err := sql.Open("postgres", h.databaseURL)
	if err != nil {
		return ServiceInfo{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Failed to connect to database: %v", err),
		}
	}
	defer db.Close()

	// Set connection timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test database connection
	err = db.PingContext(ctx)
	responseTime := time.Since(start).String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return ServiceInfo{
				Status:  "unhealthy",
				Message: "Database connection timeout",
			}
		}
		return ServiceInfo{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Database ping failed: %v", err),
		}
	}

	// Test a simple query
	var result int
	err = db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return ServiceInfo{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Database query failed: %v", err),
		}
	}

	return ServiceInfo{
		Status:       "healthy",
		Message:      "Database is responding",
		ResponseTime: responseTime,
	}
}

func (h *HealthChecker) checkAPIGateway() ServiceInfo {
	// API Gateway is self-checking, so if we reach this point, it's healthy
	return ServiceInfo{
		Status:  "healthy",
		Message: "API Gateway is running",
	}
}

// HTTP handler for health check endpoint
func (h *HealthChecker) HealthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := h.CheckAllServices()

		// Set appropriate HTTP status code
		httpStatus := http.StatusOK
		if !status.Overall {
			httpStatus = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)

		// Simple JSON response (you might want to use json.Marshal for more complex responses)
		fmt.Fprintf(w, `{
			"status": "%s",
			"timestamp": "%s",
			"overall_healthy": %t,
			"services": {
				"auth-service": {
					"status": "%s",
					"message": "%s",
					"response_time": "%s"
				},
				"auth-db": {
					"status": "%s",
					"message": "%s",
					"response_time": "%s"
				},
				"api-gateway": {
					"status": "%s",
					"message": "%s"
				}
			}
		}`,
			status.Status,
			status.Timestamp,
			status.Overall,
			status.Services["auth-service"].Status,
			status.Services["auth-service"].Message,
			status.Services["auth-service"].ResponseTime,
			status.Services["auth-db"].Status,
			status.Services["auth-db"].Message,
			status.Services["auth-db"].ResponseTime,
			status.Services["api-gateway"].Status,
			status.Services["api-gateway"].Message,
		)
	}
}
