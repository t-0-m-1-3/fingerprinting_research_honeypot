FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libcurl4 && \
    curl -sL https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz \
    | tar xz -C /opt && \
    ln -s /opt/arachni-1.6.1.3-0.6.1.1/bin/arachni /usr/local/bin/arachni && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["arachni"]
