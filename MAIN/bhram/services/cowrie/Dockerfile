FROM python:3.11-slim

LABEL maintainer="BHRAM Project"
LABEL description="Cowrie SSH Honeypot — BHRAM Deception Surface"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-dev \
    authbind \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create cowrie user
RUN useradd -m -u 1000 -s /bin/bash cowrie

# Install Cowrie from PyPI
RUN pip install --no-cache-dir cowrie==2.5.0

# Create directory structure
RUN mkdir -p \
    /home/cowrie/var/log/cowrie \
    /home/cowrie/var/lib/cowrie/downloads \
    /home/cowrie/var/lib/cowrie/tty \
    /home/cowrie/etc \
    /home/cowrie/honeyfs

# Copy configuration
COPY cowrie.cfg     /home/cowrie/etc/cowrie.cfg
COPY userdb.txt     /home/cowrie/etc/userdb.txt
COPY honeyfs/       /home/cowrie/honeyfs/

# Fix ownership
RUN chown -R cowrie:cowrie /home/cowrie

USER cowrie
WORKDIR /home/cowrie

EXPOSE 2222

HEALTHCHECK --interval=20s --timeout=5s --retries=5 --start-period=30s \
    CMD pgrep -f "twistd\|cowrie" || exit 1

CMD ["python", "-m", "cowrie.core.main", "-c", "/home/cowrie/etc/cowrie.cfg"]
