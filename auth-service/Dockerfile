FROM golang:1.21-alpine AS builder

# Install git for direct module downloads
RUN apk add --no-cache git

WORKDIR /app
COPY ../proto ./proto
COPY . .
WORKDIR /app/auth-service

# Configure Go to use direct downloads
RUN go env -w GOPROXY=direct && \
    go env -w GOSUMDB=off

RUN go mod download

RUN CGO_ENABLED=0 go build -o auth-service ./cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates postgresql-client
WORKDIR /app
COPY --from=builder /app/auth-service .
COPY --from=builder /app/proto ./proto
COPY --from=builder /app/auth-service/internal/migrations ./migrations
COPY --from=builder /app/auth-service/internal/service/email_templates ./email_templates
EXPOSE 50051
CMD ["sh", "-c", "sleep 10 && PGPASSWORD=password psql -h postgres -U user -d authdb -q -f ./migrations/001_create_users_table.up.sql 2>/dev/null && PGPASSWORD=password psql -h postgres -U user -d authdb -q -f ./migrations/002_create_user_login_history_table.up.sql 2>/dev/null && ./auth-service"]