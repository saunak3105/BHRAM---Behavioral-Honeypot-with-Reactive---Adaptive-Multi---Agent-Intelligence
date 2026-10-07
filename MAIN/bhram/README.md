# BHRAM
## Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence

> **University Major Project — Part 1: Isolated Fake Company Environment**
>
> ⚠️ **FOR ACADEMIC / RESEARCH USE ONLY** — Run in an isolated lab. Do not deploy against systems you do not own.

---

## Table of Contents

1. [Project Purpose](#project-purpose)
2. [Architecture](#architecture)
3. [Services](#services)
4. [Directory Structure](#directory-structure)
5. [Security Boundaries](#security-boundaries)
6. [Setup and Installation](#setup-and-installation)
7. [Starting the System](#starting-the-system)
8. [Testing the System](#testing-the-system)
9. [Network Design](#network-design)
10. [API Reference](#api-reference)
11. [Deception Artifacts](#deception-artifacts)
12. [Part 2: Telemetry & Event Normalization Layer](#part-2-status-completed)
13. [Demonstration & Attack Simulation Guide](docs/demonstration-and-attack-guide.md)
14. [Developer Deep Dive (Parts 1 & 2)](docs/developer-deep-dive.md)
15. [Part 3 Scope (Upcoming)](#part-3-scope-upcoming)

---

## Project Purpose

BHRAM is a cyber-deception research platform built as a university major project. It implements a **realistic, isolated fake company environment** that:

- Presents multiple attacker-facing deception surfaces (SSH honeypot, web application)
- Captures and logs all attacker interactions with full telemetry
- Maintains a centralized environment state modifiable by AI/ML agents
- Provides a clean internal API for the AI/ML orchestration team
- Contains no real credentials, no real personal data, and no connection to real infrastructure

### Target Deception Company
> **BHRAM Technologies** — a fictional enterprise cybersecurity company

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ATTACKER                                      │
└───────────────┬─────────────────────────────────────┬───────────────────┘
                │ SSH :2222                             │ HTTP :8080
                ▼                                       ▼
   ┌────────────────────────┐             ┌─────────────────────────────┐
   │   Cowrie SSH Honeypot  │             │  BHRAM Technologies Website │
   │   bhram_cowrie         │             │  bhram_web (Flask)          │
   │   Frontend Net only    │             │  Frontend + Backend Net     │
   └────────────────────────┘             └─────────────────────────────┘
          (no backend access)                          │
                                                       │
          ─────────────── Backend Network (172.21.0.0/24) ─────────────────
                                    │                  │
                      ┌─────────────┘                  └──────────────┐
                      ▼                                                ▼
         ┌────────────────────────┐                    ┌──────────────────────────┐
         │   BHRAM API (FastAPI)  │                    │  Deception File Server   │
         │   bhram_api            │                    │  bhram_fileserver        │
         │   :8000 (loopback)     │                    │  :8081 (loopback)        │
         └──────────┬─────────────┘                    └──────────────┬───────────┘
                    │                                                   │
          ─── Internal Network (172.22.0.0/24 — Docker internal:true) ──
                    │                                                   │
                    └───────────────────┬───────────────────────────────┘
                                        ▼
                            ┌────────────────────────┐
                            │   PostgreSQL 16         │
                            │   bhram_postgres        │
                            │   Internal only         │
                            │   No host port exposed  │
                            └────────────────────────┘
```

---

## Services

| Container          | Role                          | Port (Host)        | Network             |
|--------------------|-------------------------------|--------------------|---------------------|
| `bhram_postgres`   | PostgreSQL database           | None (internal)    | internal            |
| `bhram_api`        | FastAPI internal API          | 127.0.0.1:8000     | backend + internal  |
| `bhram_web`        | Fake company website (Flask)  | 0.0.0.0:8080       | frontend + backend  |
| `bhram_fileserver` | Deception file server         | 127.0.0.1:8081     | backend + internal  |
| `bhram_cowrie`     | Cowrie SSH honeypot           | 0.0.0.0:2222       | frontend only       |

---

## Directory Structure

```
bhram/
├── README.md                    ← You are here
├── LICENSE                      ← MIT License
├── .gitignore
├── .env.example                 ← Copy to .env before running
├── compose.yaml                 ← Docker Compose (all services)
├── Makefile                     ← Convenience targets
│
├── docs/
│   ├── architecture.md          ← System architecture
│   ├── threat-model.md          ← Threat model & controls
│   ├── network.md               ← Network design
│   └── deployment.md            ← Deployment guide
│
├── database/
│   ├── schema.sql               ← PostgreSQL schema (8 tables)
│   └── seed.sql                 ← Initial fictional data
│
├── services/
│   ├── bhram-api/               ← FastAPI internal API
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── app/
│   │       ├── main.py          ← FastAPI app + health endpoint
│   │       ├── config.py        ← Settings (pydantic-settings)
│   │       ├── database.py      ← Async SQLAlchemy engine
│   │       ├── models.py        ← ORM models
│   │       ├── schemas.py       ← Pydantic request/response schemas
│   │       └── routes/
│   │           ├── environment.py  ← GET /api/v1/environment
│   │           ├── services.py     ← GET /api/v1/services
│   │           ├── users.py        ← GET /api/v1/users
│   │           └── files.py        ← GET /api/v1/files
│   │
│   ├── web/                     ← Flask fake company website
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   ├── app.py               ← Flask application factory
│   │   ├── templates/           ← Jinja2 HTML templates
│   │   │   ├── base.html
│   │   │   ├── index.html       ← Home page
│   │   │   ├── about.html       ← About / leadership
│   │   │   ├── careers.html     ← Job listings
│   │   │   ├── contact.html     ← Contact form (honeypot)
│   │   │   ├── employee.html    ← Employee portal
│   │   │   ├── login.html       ← Login honeypot
│   │   │   ├── support.html     ← IT Support portal
│   │   │   ├── internal.html    ← Intranet (deception artifacts)
│   │   │   ├── documents.html   ← Document portal (bait files)
│   │   │   └── error.html
│   │   └── static/
│   │       ├── css/main.css     ← Dark cyber-security theme
│   │       └── js/main.js
│   │
│   ├── cowrie/                  ← Cowrie SSH honeypot
│   │   ├── Dockerfile
│   │   ├── cowrie.cfg           ← Cowrie configuration
│   │   ├── userdb.txt           ← Fake SSH users
│   │   └── honeyfs/             ← Fake filesystem content
│   │       ├── home/
│   │       │   ├── admin/
│   │       │   │   ├── vpn_config.txt
│   │       │   │   └── backup/database_backup.sql
│   │       │   ├── developer/
│   │       │   │   └── developer_notes.txt
│   │       │   ├── finance/
│   │       │   │   └── salary_structure.csv
│   │       │   └── it_support/
│   │       │       ├── network_inventory.txt
│   │       │       └── it_support_notes.txt
│   │       └── srv/internal/
│   │           └── employee_directory.csv
│   │
│   └── fileserver/              ← Deception file server
│       ├── Dockerfile
│       ├── requirements.txt
│       └── app.py               ← FastAPI with orchestrator API
│
├── data/
│   ├── cowrie/logs/             ← Cowrie JSON + text logs (gitignored)
│   └── decoy-files/             ← Static decoy files (mounted read-only)
│
└── tests/
    ├── conftest.py              ← Shared fixtures
    ├── pyproject.toml           ← pytest configuration
    ├── requirements-test.txt    ← Test dependencies
    ├── test_unit.py             ← Unit tests (no Docker required)
    ├── test_api.py              ← BHRAM API integration tests
    ├── test_web.py              ← Web app integration tests
    ├── test_database.py         ← Database integration tests
    └── test_fileserver.py       ← File server integration tests
```

---

## Security Boundaries

BHRAM implements the following security controls:

| Control                            | Implementation                                      |
|------------------------------------|-----------------------------------------------------|
| No real credentials                | All passwords/keys in honeyfs are labeled FAKE      |
| No real personal data              | All names/emails are entirely fictional             |
| DB not exposed to attacker         | PostgreSQL on `internal` network (no external route)|
| API not accessible from attacker   | Bound to `127.0.0.1` only                          |
| Cowrie cannot reach internal net   | No backend/internal network in Cowrie service       |
| No container privilege escalation  | All run as UID 1001, `cap_drop: ALL`, no privileged |
| No shell execution via API         | No `/exec`, `/cmd`, or `/run` endpoints             |
| No host filesystem mount (Cowrie)  | Honeyfs mounted read-only                           |
| Path traversal rejected            | File server validates all paths against file root   |
| No privileged containers           | No `privileged: true` in compose.yaml               |

---

## Setup and Installation

### Prerequisites

- Ubuntu Server 24.04 LTS (lab environment)
- Docker Engine 26.x + Compose Plugin v2
- Git, Python 3.12+, Make

```bash
# Install Docker (Ubuntu)
curl -fsSL https://get.docker.com | sudo bash
sudo usermod -aG docker $USER

# Clone repo
git clone <repo-url> bhram && cd bhram
```

### First-Time Setup

```bash
make setup          # Creates .env from .env.example, creates data dirs
nano .env           # Edit passwords (keep them fictional/lab-only)
```

---

## Starting the System

```bash
# Build images and start all services
make up

# Expected output:
#   BHRAM is starting. Use 'make status' to check health.
#   Web Application : http://localhost:8080
#   BHRAM API       : http://localhost:8000
#   API Docs        : http://localhost:8000/docs
#   SSH Honeypot    : ssh root@localhost -p 2222
#   File Server     : http://localhost:8081  (loopback only)

# Check status (wait ~60 seconds on first run for DB init)
make status

# Run health check
make health-check
```

### Stopping

```bash
make down           # Stop services (keep data)
make clean          # Stop and destroy all data (WARNING)
```

---

## Testing the System

### Quick Validation

```bash
# 1. Validate Docker Compose config
make validate

# 2. Check container health
make status

# 3. Check health endpoints
make health-check

# 4. Manually test API
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/environment
curl http://localhost:8000/api/v1/users
curl http://localhost:8000/api/v1/services
curl http://localhost:8000/api/v1/files

# 5. Test SSH honeypot
ssh -p 2222 admin@localhost        # try password: admin123
ssh -p 2222 developer@localhost    # try password: dev123

# 6. Test web application
curl -I http://localhost:8080/
curl -I http://localhost:8080/login
curl -I http://localhost:8080/documents

# 7. Test file server orchestrator
curl http://localhost:8081/health
curl http://localhost:8081/structure
```

### Automated Test Suite

```bash
# Install test dependencies
cd tests && pip install -r requirements-test.txt && cd ..

# Unit tests (no Docker required)
make test-unit

# Integration tests (Docker must be running)
make test-integration

# All tests
make test
```

### Expected test results

```
tests/test_unit.py         — 13 tests  PASS (no Docker needed)
tests/test_api.py          — 17 tests  PASS (requires: make up)
tests/test_web.py          — 14 tests  PASS (requires: make up)
tests/test_database.py     —  8 tests  PASS (requires: make up)
tests/test_fileserver.py   —  9 tests  PASS (requires: make up)
```

---

## Network Design

Three isolated Docker networks:

| Network         | Subnet          | Type     | Members                            |
|-----------------|-----------------|----------|------------------------------------|
| `bhram_frontend`| 172.20.0.0/24   | Bridge   | cowrie, web                        |
| `bhram_backend` | 172.21.0.0/24   | Bridge   | web, bhram-api, fileserver         |
| `bhram_internal`| 172.22.0.0/24   | Internal | bhram-api, fileserver, postgres    |

See [`docs/network.md`](docs/network.md) for full connectivity matrix.

---

## API Reference

| Endpoint                 | Method | Description                          |
|--------------------------|--------|--------------------------------------|
| `/health`                | GET    | API and DB health check              |
| `/api/v1/environment`    | GET    | Current deception environment state  |
| `/api/v1/services`       | GET    | All registered services              |
| `/api/v1/users`          | GET    | All fictional honeypot users         |
| `/api/v1/files`          | GET    | All decoy files (with filters)       |
| `/docs`                  | GET    | Interactive OpenAPI documentation    |
| `/openapi.json`          | GET    | Machine-readable OpenAPI schema      |

### File Server Orchestrator API (`:8081`)

| Endpoint            | Method | Description                   |
|---------------------|--------|-------------------------------|
| `/health`           | GET    | File server health            |
| `/files`            | GET    | List files at path            |
| `/structure`        | GET    | Full directory tree           |
| `/files/create`     | POST   | Create decoy file             |
| `/files/delete`     | DELETE | Delete decoy file             |
| `/files/modify`     | PUT    | Modify decoy file content     |
| `/files/move`       | POST   | Move decoy file               |
| `/files/content`    | GET    | Read decoy file content       |

---

## Deception Artifacts

The following fictional artifacts are embedded to lure and engage attackers:

| Artifact                     | Location                                     | Bait Level |
|------------------------------|----------------------------------------------|------------|
| VPN WireGuard config         | `/home/admin/vpn_config.txt` (SSH)           | 4/5        |
| Employee directory CSV       | `/srv/internal/employee_directory.csv` (SSH) | 3/5        |
| Salary structure CSV         | `/home/finance/salary_structure.csv` (SSH)   | 5/5        |
| Database backup SQL          | `/home/admin/backup/database_backup.sql`     | 5/5        |
| Developer notes + infra refs | `/home/developer/developer_notes.txt`        | 3/5        |
| Network inventory (full IPs) | `/home/it_support/network_inventory.txt`     | 4/5        |
| IT support notes + jump host | `/home/it_support/it_support_notes.txt`      | 3/5        |
| Internal hostnames (web)     | Visible in HTML source of `/internal`        | 3/5        |
| Employee usernames (web)     | Visible in `/employee` directory table       | 3/5        |
| SSO hint (web login)         | Visible in login page source                 | 2/5        |

All content is **entirely fictional**. No real data, real credentials, or real infrastructure is referenced.

---

## Part 2 Status: Completed

The complete telemetry collection, normalization, and forensic storage layer is implemented:
- **Canonical Schema**: Defined in `bhram.telemetry.schemas.CanonicalEvent`
- **Collectors**: Cowrie SSH honeypot, Web Flask decoy, File server, Network telemetry
- **Normalizer**: Slotted deduplication, dynamic severity escalation, MITRE ATT&CK TTP mapping
- **Forensic Pipeline**: Dual-write append-only flat files (`data/raw/`, `data/normalized/`) and PostgreSQL tables (`raw_events`, `events`, `session_events`)
- **AI/ML API**: Strict allowlist-validated endpoints (`/api/v1/ai/events`, `/api/v1/ai/profile`, `/api/v1/ai/decision`)
- **Documentation**: Detailed in [`docs/telemetry-pipeline.md`](docs/telemetry-pipeline.md)

### Running Telemetry Tests
```bash
# Run unit tests across all telemetry modules and core logic:
cd bhram
python -m pytest telemetry/tests/ -v
# or
pytest -m unit -v
```

### Generating Demo Attacker Activity
```bash
# Safe synthetic event generation:
python scripts/demo_generate_events.py --no-api
```

---

## Part 3 Scope (Upcoming)

| Feature | Scope |
|---|---|
| Behavioral Analysis Agent | Multi-agent AI/ML teammate scope |
| Intent Analysis Agent | LLM / pattern recognition classification |
| Attacker Profiling Agent | Skill scoring and attribution heuristics |
| Threat Assessment Agent | Real-time threat calculation |
| Deception Orchestration Agent | Executing allowlisted deception actions from Part 2 decisions |
| Real-time Stream Engine | WebSocket or pub/sub event broadcasting |

---

## License

MIT — See [LICENSE](LICENSE) for details.

> **All company names, employee names, credentials, documents, and network information within this repository are entirely fictional and for academic research purposes only.**
