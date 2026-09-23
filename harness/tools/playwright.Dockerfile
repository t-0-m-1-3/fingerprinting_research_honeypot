FROM mcr.microsoft.com/playwright/python:v1.48.0-noble
RUN pip install playwright==1.48.0
COPY scripts/run-playwright.py /scripts/run-playwright.py
ENTRYPOINT ["python3", "/scripts/run-playwright.py"]
