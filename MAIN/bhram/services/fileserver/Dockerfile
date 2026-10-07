FROM python:3.12-slim

LABEL maintainer="BHRAM Project"
LABEL description="BHRAM Deception File Server — Observable file access with orchestrator API"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /srv/company-files
RUN useradd -m -u 1001 fileserver && chown -R fileserver:fileserver /app /srv/company-files
USER fileserver

EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=15s \
    CMD curl -f http://localhost:8081/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8081"]
