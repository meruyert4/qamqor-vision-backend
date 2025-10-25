package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port            string
	AuthServiceAddr string
	DatabaseURL     string
}

func Load() (*Config, error) {
	// Try to load .env file, but don't fail if it doesn't exist
	if err := godotenv.Load(); err != nil {
		// .env file is optional, continue without it
	}

	return &Config{
		Port:            getEnv("PORT", "8080"),
		AuthServiceAddr: getEnv("AUTH_SERVICE_ADDR", "auth-service:50051"),
		DatabaseURL:     getEnv("DATABASE_URL", "postgres://user:password@postgres:5432/authdb?sslmode=disable"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
