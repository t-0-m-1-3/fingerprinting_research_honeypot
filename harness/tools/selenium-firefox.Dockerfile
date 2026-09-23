FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    firefox-esr ca-certificates && \
    pip install --no-cache-dir selenium webdriver-manager && \
    rm -rf /var/lib/apt/lists/*
COPY scripts/run-selenium.py /scripts/run-selenium.py
ENTRYPOINT ["python3", "/scripts/run-selenium.py"]
