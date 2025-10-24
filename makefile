.PHONY: help up down auth-up

.DEFAULT_GOAL := help

# Pink color
PINK := \033[95m
RESET := \033[0m

help:
	@echo "$(PINK)════════════════════════════════════════$(RESET)"
	@echo "$(PINK)   QAMQOR-VISION Backend Commands$(RESET)"
	@echo "$(PINK)════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(PINK)Available commands:$(RESET)"
	@echo "  $(PINK)make up$(RESET)       - Start all services with Docker"
	@echo "  $(PINK)make down$(RESET)     - Stop all services and remove volumes"
	@echo "  $(PINK)make auth-up$(RESET)  - Run auth-service locally"
	@echo ""
	@echo "$(PINK)Documentation:$(RESET)"
	@echo "  $(PINK)Swagger API Docs:$(RESET) http://localhost:8080/swagger/"
	@echo ""

up:
	@echo "$(PINK)🚀 Starting all services with Docker...$(RESET)"
	docker compose up --build
	@echo "$(PINK)✓ Services started$(RESET)"

down:
	@echo "$(PINK)🛑 Stopping all services...$(RESET)"
	docker compose down -v
	@echo "$(PINK)✓ Services stopped$(RESET)"

docker-info:
	@echo "$(PINK)� Docker container information:$(RESET)"
	docker ps

auth-up:
	@echo "$(PINK)🔧 Running auth-service locally...$(RESET)"
	cd auth-service && go run cmd/auth-service/main.go