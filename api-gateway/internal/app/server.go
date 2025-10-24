package app

import (
	"log"

	"api-gateway/internal/client"
	"api-gateway/internal/config"
)

func StartServer() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Initialize gRPC client
	authClient, err := client.NewAuthClient(cfg.AuthServiceAddr)
	if err != nil {
		return err
	}
	defer authClient.Close()

	// Setup router
	router := SetupRouter(authClient, cfg.AuthServiceAddr, cfg.DatabaseURL)

	// Start server
	log.Printf("Starting API Gateway on port %s", cfg.Port)
	return router.Run(":" + cfg.Port)
}
