FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium ca-certificates fonts-liberation && \
    rm -rf /var/lib/apt/lists/*
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
RUN npm install -g puppeteer
COPY scripts/run-puppeteer.js /scripts/run-puppeteer.js
ENTRYPOINT ["node", "/scripts/run-puppeteer.js"]
