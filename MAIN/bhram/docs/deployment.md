# BHRAM — Deployment Guide

## Prerequisites

- Ubuntu Server 24.04 LTS (or WSL2 on Windows for development)
- Docker Engine 26.x
- Docker Compose Plugin (v2+)
- Git
- Python 3.12+ (for running tests on host)
- `make` (GNU Make)
- At least 4GB RAM, 20GB disk

## Installation

```bash
# 1. Clone the repository
git clone <your-repo-url> bhram
cd bhram

# 2. Create your environment file
make setup      # copies .env.example → .env

# 3. Edit .env — change passwords for your lab
nano .env

# 4. Build and start all services
make up

# 5. Verify health
make status
make health-check
```

## Service Ports

| Service         | Host Binding      | Purpose              |
|-----------------|-------------------|----------------------|
| SSH Honeypot    | 0.0.0.0:2222      | Attacker SSH surface |
| Web App         | 0.0.0.0:8080      | Attacker web surface |
| BHRAM API       | 127.0.0.1:8000    | Internal API (loopback) |
| File Server     | 127.0.0.1:8081    | Internal file ops    |
| PostgreSQL      | Not exposed       | Internal only        |

## Starting / Stopping

```bash
make up          # Start all services (build if needed)
make down        # Stop all services (keep volumes)
make clean       # Stop and destroy all volumes (WARNING: data loss)
make restart     # Restart all services
make logs        # Tail all logs
make status      # Show container status
```

## Testing

```bash
# Install test dependencies (on host)
cd tests && pip install -r requirements-test.txt

# Run unit tests (no Docker required)
make test-unit

# Run integration tests (Docker must be running)
make up          # ensure services are running
make test-integration

# Run all tests
make test
```

## SSH Honeypot Access (as attacker simulation)

```bash
# Simulate attacker SSH access
ssh -p 2222 admin@localhost
# Try credentials from userdb.txt — all are fictional

# Test Cowrie logging
docker compose logs -f cowrie
# Check: data/cowrie/logs/cowrie.json
```

## API Access

```bash
# Health check
curl http://localhost:8000/health | python3 -m json.tool

# Environment state
curl http://localhost:8000/api/v1/environment | python3 -m json.tool

# Users
curl http://localhost:8000/api/v1/users | python3 -m json.tool

# Services
curl http://localhost:8000/api/v1/services | python3 -m json.tool

# Decoy files
curl http://localhost:8000/api/v1/files | python3 -m json.tool

# OpenAPI docs
open http://localhost:8000/docs
```

## Database Access

```bash
# Connect to PostgreSQL (internal, via Docker exec)
make shell-db
# Or manually:
docker compose exec postgres psql -U bhram_user -d bhram_db
```

## Troubleshooting

### Services not starting
```bash
make validate    # Validate compose.yaml
make logs        # Check logs for errors
docker compose ps --all  # Check exit codes
```

### Database not ready
The BHRAM API waits for PostgreSQL to pass health checks. Allow 30-60 seconds on first start for:
1. PostgreSQL to initialize
2. Schema to be applied
3. Seed data to be inserted
4. API to run first database ping

### Cowrie not accepting connections
```bash
docker compose exec cowrie pgrep -f twistd  # Check if running
docker compose logs cowrie  # Check startup errors
```
