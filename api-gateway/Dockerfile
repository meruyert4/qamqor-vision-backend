# ===== BUILDER =====
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY ../proto ./proto
COPY . .
WORKDIR /app/api-gateway

RUN go env -w GOPROXY=https://proxy.golang.org,direct && \
    go env -w GOSUMDB=sum.golang.org && \
    go mod download

RUN CGO_ENABLED=0 go build -o api-gateway ./cmd/main.go

# ===== RUNNER =====
FROM alpine:3.20
RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /app/api-gateway/api-gateway .
COPY --from=builder /app/proto ./proto

EXPOSE 8080
CMD ["./api-gateway"]
