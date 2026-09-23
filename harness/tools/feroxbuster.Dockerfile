FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip && \
    curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip -o /tmp/ferox.zip && \
    unzip /tmp/ferox.zip -d /tmp && \
    dpkg -i /tmp/feroxbuster_*_amd64.deb || apt-get install -f -y && \
    rm -rf /tmp/*.deb /tmp/*.zip /var/lib/apt/lists/*
ENTRYPOINT ["feroxbuster"]
