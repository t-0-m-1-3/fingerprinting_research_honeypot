FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/faizann24/rogue.git /opt/rogue
WORKDIR /opt/rogue
RUN pip install --no-cache-dir -r requirements.txt
# Playwright needs browser binaries
RUN pip install --no-cache-dir playwright && playwright install --with-deps chromium
ENTRYPOINT ["python", "run.py"]
