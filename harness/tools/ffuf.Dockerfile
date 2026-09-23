FROM golang:latest AS build
RUN go install github.com/ffuf/ffuf/v2@latest
FROM debian:bookworm-slim
COPY --from=build /go/bin/ffuf /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["ffuf"]
