package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL        string
	JWTSecret          string
	SMTPHost           string
	SMTPPort           int
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	FrontendURL        string
	GRPCPort           string
	VerificationSecret string
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		// .env file is optional
	}

	port, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))

	return &Config{
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5433/authdb?sslmode=disable"),
		JWTSecret:          getEnv("JWT_SECRET", "your-secret-key"),
		SMTPHost:           getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:           port,
		SMTPUsername:       getEnv("SMTP_USERNAME", ""),
		SMTPPassword:       getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:           getEnv("SMTP_FROM", ""),
		FrontendURL:        getEnv("FRONTEND_URL", "http://localhost:8080"),
		GRPCPort:           getEnv("GRPC_PORT", "50051"),
		VerificationSecret: getEnv("VERIFICATION_SECRET", "verification-secret"),
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
