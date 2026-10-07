# BHRAM — Architecture Documentation
# Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence

## System Overview

BHRAM is a cyber-deception platform composed of an isolated attacker-facing environment and an internal intelligence/control plane. Part 1 establishes the deception surface and foundational infrastructure.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ATTACKER                                                               │
│  (External)                                                             │
└─────────┬───────────────────────┬───────────────────────────────────────┘
          │ SSH :2222              │ HTTP :8080
          ▼                        ▼
┌─────────────────────┐  ┌─────────────────────┐
│   Cowrie SSH        │  │   BHRAM Technologies │
│   Honeypot          │  │   Web Application    │
│   (Frontend Net)    │  │   (Frontend Net)     │
└─────────┬───────────┘  └─────────┬────────────┘
          │                         │
          │  FRONTEND NETWORK (172.20.0.0/24)
          │  ← Cowrie has NO access to backend/internal
          │
          │  BACKEND NETWORK (172.21.0.0/24)
          ▼                         ▼
┌─────────────────────┐  ┌─────────────────────┐
│   BHRAM API         │  │   File Server        │
│   (FastAPI)         │  │   (Decoy FS)         │
│   :8000 (loopback)  │  │   :8081 (loopback)   │
└─────────┬───────────┘  └─────────┬────────────┘
          │                         │
          │  INTERNAL NETWORK (172.22.0.0/24 — no external routing)
          ▼
┌─────────────────────┐
│   PostgreSQL        │
│   (Internal only)   │
│   No host port      │
└─────────────────────┘
```

## Network Isolation

| Network   | Subnet          | Purpose                        | External? |
|-----------|-----------------|--------------------------------|-----------|
| frontend  | 172.20.0.0/24   | Attacker-facing services       | Yes       |
| backend   | 172.21.0.0/24   | Internal API + File Server     | Loopback  |
| internal  | 172.22.0.0/24   | Database (no external routing) | No        |

## Service Responsibilities

### Cowrie (SSH Honeypot)
- Listens on TCP 2222
- Emulates Ubuntu 22.04 SSH server
- Captures all commands, keystrokes, and file transfers
- Logs to JSON (cowrie.json) and text (cowrie.log)
- Fake filesystem with high-value bait files
- **Network**: frontend only — zero access to backend/internal

### BHRAM Technologies Web App (Flask)
- Serves the fictional company website on :8080
- All pages contain deception artifacts
- Login form is a honeypot (always rejects, logs attempts)
- Reveals: internal hostnames, employee usernames, tech stack
- **Network**: frontend + backend

### BHRAM API (FastAPI)
- Internal management and AI/ML interface
- Bound to 127.0.0.1:8000 on the host
- OpenAPI documentation at /docs
- Provides environment state to AI/ML agents
- **Network**: backend + internal

### File Server (FastAPI)
- Hosts deception files with full access observability
- Orchestrator API for dynamic file management
- Path traversal protected
- **Network**: backend + internal (NOT frontend)

### PostgreSQL
- Stores all environment state, events, and profiles
- No host port exposed
- Only accessible from internal Docker network
- **Network**: internal only

## Deception Layers

| Layer        | What the attacker sees                                    |
|--------------|-----------------------------------------------------------|
| Web (HTTP)   | Company site, employee directory, internal hostnames      |
| SSH          | Fake Ubuntu shell, high-value bait files, fake users      |
| File System  | VPN configs, salary data, DB backups, network inventory   |
| Auth         | Login honeypot (all attempts logged)                      |

## Part 2 Status: Telemetry & Normalization Layer (Completed)

The telemetry pipeline has been fully implemented:
- **Canonical Schema**: Single `CanonicalEvent` format unifying all sources
- **Collectors**: Cowrie (SSH), Flask (Web), File Server, and Network
- **Normalizer Engine**: Deduplication, dynamic severity escalation, MITRE ATT&CK TTP mapping
- **Forensic Pipeline**: Dual-write append-only JSONL files (`data/raw/`, `data/normalized/`) and PostgreSQL tables (`raw_events`, `events`, `session_events`)
- **AI/ML API**: Strict allowlist-validated endpoints (`/api/v1/ai/events`, `/api/v1/ai/profile`, `/api/v1/ai/decision`)
- *See full architecture in [telemetry-pipeline.md](telemetry-pipeline.md).*

## Part 3 Upcoming: Reactive-Adaptive Multi-Agent Intelligence

- Behavioral, Intent, and Threat Assessment AI Agents
- Automated deception action execution from the `AI_ACTION_ALLOWLIST`
- Real-time dashboard streaming
