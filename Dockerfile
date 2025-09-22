# Base on Playwright image to have headless browsers available
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

COPY requirements.txt ./
RUN apt-get update && apt-get install -y --no-install-recommends \
        masscan nmap ca-certificates wget unzip && \
    rm -rf /var/lib/apt/lists/* && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /tmp && mv /tmp/nuclei /usr/local/bin/nuclei && rm -rf /tmp/* && \
    pip install --no-cache-dir -r requirements.txt && \
    playwright install --with-deps chromium

COPY app ./app

ENV PYTHONUNBUFFERED=1 \
    OTEL_SERVICE_NAME=globalscanner \
    OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317 \
    LOG_LEVEL=INFO

EXPOSE 8080

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
