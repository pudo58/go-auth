# ---------- Stage 1: Build ----------
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o auth-service .
FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/auth-service .
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates
ENV GIN_MODE=release
EXPOSE 8080
CMD ["./auth-service"]
