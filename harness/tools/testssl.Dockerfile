FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates openssl procps bsdmainutils dnsutils && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["testssl.sh"]
