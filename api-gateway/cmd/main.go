package main

import (
	"log"
	"os"

	_ "api-gateway/docs"
	"api-gateway/internal/app"
	"api-gateway/internal/client"

	"github.com/joho/godotenv"
)

// @title QAMQOR-VISION API Gateway
// @version 1.0
// @description API Gateway for QAMQOR-VISION microservices
// @host localhost:8080
// @BasePath /
func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
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

	// Initialize gRPC client
	authClient, err := client.NewAuthClient(authServiceAddr)
	if err != nil {
		log.Fatalf("Failed to create auth client: %v", err)
	}
	defer authClient.Close()

	// Setup router
	router := app.SetupRouter(authClient)

	// Start server
	log.Printf("Starting API Gateway on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
