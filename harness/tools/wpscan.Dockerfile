FROM ruby:3.3-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libcurl4-openssl-dev zlib1g-dev ca-certificates && \
    gem install wpscan --no-document && \
    apt-get purge -y build-essential && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["wpscan"]
