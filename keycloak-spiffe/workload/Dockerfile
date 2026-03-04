FROM golang:1.24-alpine AS builder

WORKDIR /app

# Initialize module and download dependencies
RUN go mod init example-spiffe && \
    go get github.com/spiffe/go-spiffe/v2/workloadapi && \
    go get github.com/spiffe/go-spiffe/v2/svid/jwtsvid

COPY main.go .

# Static build for Alpine
RUN CGO_ENABLED=0 GOOS=linux go build -o fetcher main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/fetcher .
CMD ["./fetcher"]