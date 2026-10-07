FROM python:3.12-slim

LABEL maintainer="BHRAM Project"
LABEL description="BHRAM Technologies — Fake Company Web Application (Honeypot Surface)"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1001 webuser && chown -R webuser:webuser /app
USER webuser

EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=15s \
    CMD curl -f http://localhost:5000/ || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "app:create_app()"]
