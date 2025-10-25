package app

import (
	"fmt"
	"log"
	"os"

	"api-gateway/internal/client"

	"github.com/joho/godotenv"
)

func StartServer() error {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("failed to load .env file: %w", err)
	}

	// Get configuration from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	authServiceAddr := os.Getenv("AUTH_SERVICE_ADDR")
	if authServiceAddr == "" {
		authServiceAddr = "localhost:50051"
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://user:password@postgres:5432/authdb?sslmode=disable"
	}

	// Initialize gRPC client
	authClient, err := client.NewAuthClient(authServiceAddr)
	if err != nil {
		return fmt.Errorf("failed to create auth client: %w", err)
	}
	defer authClient.Close()

	// Setup router
	router := SetupRouter(authClient, authServiceAddr, databaseURL)

	// Start server
	log.Printf("Starting API Gateway on port %s", port)
	if err := router.Run(":" + port); err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	return err
}
