package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port            string
	AuthServiceAddr string
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		// .env file is optional
	}

	return &Config{
		Port:            getEnv("PORT", "8080"),
		AuthServiceAddr: getEnv("AUTH_SERVICE_ADDR", "auth-service:50051"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
