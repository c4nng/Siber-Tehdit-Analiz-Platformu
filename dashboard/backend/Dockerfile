FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o dashboard .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/dashboard .
EXPOSE 8090
CMD ["./dashboard"]
