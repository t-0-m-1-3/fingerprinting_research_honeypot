FROM golang:latest AS build
RUN go install github.com/OJ/gobuster/v3@latest
FROM debian:bookworm-slim
COPY --from=build /go/bin/gobuster /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["gobuster"]
