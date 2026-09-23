FROM golang:1.23 AS build
WORKDIR /app
COPY scripts/run-utls.go .
RUN go mod init utls-fingerprint && \
    go get github.com/refraction-networking/utls@latest && \
    go build -o /utls-fingerprint run-utls.go
FROM debian:bookworm-slim
COPY --from=build /utls-fingerprint /usr/local/bin/utls-fingerprint
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["utls-fingerprint"]
