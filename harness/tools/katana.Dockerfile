FROM golang:1.23 AS build
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
FROM debian:bookworm-slim
COPY --from=build /go/bin/katana /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["katana"]
