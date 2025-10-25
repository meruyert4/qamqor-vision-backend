# ===== BUILDER =====
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY ../proto ./proto
COPY . .
WORKDIR /app/auth-service

RUN go env -w GOPROXY=https://proxy.golang.org,direct && \
    go env -w GOSUMDB=sum.golang.org && \
    go mod download

RUN CGO_ENABLED=0 go build -o auth-service ./cmd/main.go

# ===== RUNNER =====
FROM alpine:3.20
RUN apk --no-cache add ca-certificates postgresql15-client

WORKDIR /app

COPY --from=builder /app/auth-service/auth-service .
COPY --from=builder /app/proto ./proto
COPY --from=builder /app/auth-service/internal/migrations ./internal/migrations
COPY --from=builder /app/auth-service/internal/service/email_templates ./internal/service/email_templates
COPY ./auth-service/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 50051
ENTRYPOINT ["/entrypoint.sh"]
