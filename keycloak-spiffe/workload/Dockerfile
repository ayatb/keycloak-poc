FROM golang:1.24-alpine AS builder

WORKDIR /app

# On initialise le module et on télécharge les dépendances avant de copier le code
RUN go mod init example-spiffe && \
    go get github.com/spiffe/go-spiffe/v2/workloadapi && \
    go get github.com/spiffe/go-spiffe/v2/svid/jwtsvid

COPY main.go .

# Build statique pour Alpine
RUN CGO_ENABLED=0 GOOS=linux go build -o fetcher main.go

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /root/
COPY --from=builder /app/fetcher .
CMD ["./fetcher"]