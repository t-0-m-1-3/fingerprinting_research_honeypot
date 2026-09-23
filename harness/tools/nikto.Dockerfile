FROM perl:5-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates libnet-ssleay-perl openssl && \
    cpanm --notest XML::Writer && \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    rm -rf /var/lib/apt/lists/*
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
ENTRYPOINT ["nikto"]
