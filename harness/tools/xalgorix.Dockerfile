FROM golang:latest AS build
RUN go install github.com/xalgorix/xalgorix@latest 2>/dev/null || true

FROM debian:bookworm-slim
COPY --from=build /go/bin/xalgorix /usr/local/bin/ 2>/dev/null || true
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl chromium && \
    rm -rf /var/lib/apt/lists/*
# Fallback: if go install didn't work, clone and build
RUN if [ ! -f /usr/local/bin/xalgorix ]; then \
    apt-get update && apt-get install -y --no-install-recommends git golang && \
    git clone --depth 1 https://github.com/xalgorix/xalgorix.git /tmp/xalgorix && \
    cd /tmp/xalgorix && go build -o /usr/local/bin/xalgorix . && \
    rm -rf /tmp/xalgorix && apt-get purge -y git golang && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*; \
    fi
ENTRYPOINT ["xalgorix"]
