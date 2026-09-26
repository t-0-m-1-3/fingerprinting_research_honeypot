# xalgorix: Go + Chromium AI pentest platform
# Uses official Docker image as base — includes Go binary, Chromium, and all tools.
# We add curl for health checks and configure for headless/non-interactive use.

FROM xalgord/xalgorix:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Default: run a scan against the honeypot target (overridden by harness)
ENTRYPOINT ["xalgorix"]
