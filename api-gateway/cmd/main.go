package main

import (
	_ "api-gateway/docs"
	"api-gateway/internal/app"
	"log"
)

// @title QAMQOR-VISION API Gateway
// @version 1.0
// @description API Gateway for QAMQOR-VISION microservices
// @host localhost:8080
// @BasePath /
func main() {
	if err := app.StartServer(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
