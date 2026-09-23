FROM perl:5-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates libnet-ssleay-perl openssl && \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/nikto/program:$PATH"
ENTRYPOINT ["nikto"]
