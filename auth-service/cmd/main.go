package main

import (
	"database/sql"
	"log"

	"auth-service/config"
	"auth-service/internal/repository"
	"auth-service/internal/server"
	"auth-service/internal/service"

	_ "github.com/lib/pq"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Initialize repositories and service
	userRepo := repository.NewUserRepository(db)
	loginHistoryRepo := repository.NewLoginHistoryRepository(db)
	authService := service.NewAuthService(userRepo, loginHistoryRepo, cfg)

	// Start gRPC server
	log.Println("Starting auth service...")
	if err := server.StartGRPCServer(cfg, authService); err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
	}
}
