FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -o /app/security-api .

FROM alpine:3.20
RUN adduser -D -u 65532 app
USER app
COPY --from=builder /app/security-api /app/security-api
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --retries=5 CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["/app/security-api"]
