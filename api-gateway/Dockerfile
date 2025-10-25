FROM golang:1.21-alpine AS builder

# Install git for direct module downloads
RUN apk add --no-cache git

WORKDIR /app
COPY ../proto ./proto
COPY . .
WORKDIR /app/api-gateway

# Configure Go to use direct downloads
RUN go env -w GOPROXY=direct && \
    go env -w GOSUMDB=off

RUN go mod download

RUN CGO_ENABLED=0 go build -o api-gateway ./cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/api-gateway .
COPY --from=builder /app/proto ./proto
EXPOSE 8080
CMD ["./api-gateway"]
    