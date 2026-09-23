FROM mcr.microsoft.com/playwright/python:v1.48.0-noble
COPY scripts/run-playwright.py /scripts/run-playwright.py
ENTRYPOINT ["python3", "/scripts/run-playwright.py"]
