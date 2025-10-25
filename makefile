.PHONY: help up down auth-up generate swagger

.DEFAULT_GOAL := help
PROTO_DIR=proto
SWAGGER_DIR=api-gateway/docs

# Pink color
PINK := \033[95m
RESET := \033[0m

help:
	@echo "$(PINK)════════════════════════════════════════$(RESET)"
	@echo "$(PINK)   QAMQOR-VISION Backend Commands$(RESET)"
	@echo "$(PINK)════════════════════════════════════════$(RESET)"
	@echo ""
	@echo "$(PINK)Available commands:$(RESET)"
	@echo "  $(PINK)make up$(RESET)         - Start all services with Docker"
	@echo "  $(PINK)make down$(RESET)       - Stop all services and remove volumes"
	@echo "  $(PINK)make generate$(RESET)   - Generate gRPC and Gateway code from .proto files"
	@echo "  $(PINK)make swagger$(RESET)    - Generate Swagger documentation"
	@echo ""
	@echo "$(PINK)Documentation:$(RESET)"
	@echo "  $(PINK)Swagger API Docs:$(RESET) http://localhost:8080/swagger/index.html"
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
	@echo "$(PINK)🐳 Docker container information:$(RESET)"
	docker ps

generate:
	@echo "$(PINK)⚙️ Generating gRPC and gateway files...$(RESET)"
	protoc -I $(PROTO_DIR) \
		--go_out=$(PROTO_DIR) \
		--go-grpc_out=$(PROTO_DIR) \
		--grpc-gateway_out=$(PROTO_DIR) \
		$(PROTO_DIR)/**/*.proto
	@echo "$(PINK)✓ gRPC and gateway files generated$(RESET)"

swagger:
	@echo "$(PINK)📘 Generating Swagger documentation...$(RESET)"
	swag init -g api-gateway/cmd/main.go -o $(SWAGGER_DIR)
	@echo "$(PINK)✓ Swagger docs generated at $(SWAGGER_DIR)$(RESET)"
