package health

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	pbAuth "github.com/meruyert4/qamqor-vision-backend/proto/auth"

	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type HealthChecker struct {
	checks map[string]func() ServiceInfo
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
	h := &HealthChecker{checks: make(map[string]func() ServiceInfo)}

	// 1) api gateway
	h.Register("api-gateway", checkAPIGateway)

	// 2) auth-db
	h.Register("auth-db", func() ServiceInfo {
		return checkDatabase(databaseURL)
	})

	// 3) auth grpc service
	h.Register("auth-service", func() ServiceInfo {
		return checkGRPCService("auth-service", "localhost:50051", func(conn *grpc.ClientConn) error {
			client := pbAuth.NewAuthServiceClient(conn)
			_, err := client.GetUser(context.Background(), &pbAuth.GetUserRequest{Id: "test-id"})
			return err
		})
	})

	return h
}

func (h *HealthChecker) Register(name string, fn func() ServiceInfo) {
	h.checks[name] = fn
}

func (h *HealthChecker) CheckAllServices() HealthStatus {
	now := time.Now()
	services := make(map[string]ServiceInfo)
	overall := true

	for name, fn := range h.checks {
		info := fn()
		services[name] = info
		if info.Status != "healthy" {
			overall = false
		}
	}

	status := "unhealthy"
	if overall {
		status = "healthy"
	}

	return HealthStatus{
		Status:    status,
		Timestamp: now.Format(time.RFC3339),
		Services:  services,
		Overall:   overall,
	}
}

// grpc service checker
func checkGRPCService(name, addr string, healthFunc func(conn *grpc.ClientConn) error) ServiceInfo {
	start := time.Now()

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return ServiceInfo{
			Status:  "unhealthy",
			Message: fmt.Sprintf("%s: connection failed: %v", name, err),
		}
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = healthFunc(conn)
	responseTime := time.Since(start).String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return ServiceInfo{"unhealthy", fmt.Sprintf("%s timeout", name), ""}
		}
		return ServiceInfo{"healthy", fmt.Sprintf("%s is responding", name), responseTime}
	}

	return ServiceInfo{"healthy", fmt.Sprintf("%s OK", name), responseTime}
}

// postgew database checker
func checkDatabase(dsn string) ServiceInfo {
	start := time.Now()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return ServiceInfo{"unhealthy", fmt.Sprintf("DB connect error: %v", err), ""}
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = db.PingContext(ctx); err != nil {
		return ServiceInfo{"unhealthy", fmt.Sprintf("DB ping failed: %v", err), ""}
	}

	responseTime := time.Since(start).String()
	return ServiceInfo{"healthy", "Database OK", responseTime}
}

// api gateway checker
func checkAPIGateway() ServiceInfo {
	start := time.Now()

	// Simple check if port 8080 is responding
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get("http://localhost:8080")
	responseTime := time.Since(start).String()

	if err != nil {
		return ServiceInfo{
			Status:       "unhealthy",
			Message:      "API Gateway port 8080 not responding",
			ResponseTime: responseTime,
		}
	}
	defer resp.Body.Close()

	return ServiceInfo{
		Status:       "healthy",
		Message:      "API Gateway port 8080 is responding",
		ResponseTime: responseTime,
	}
}
