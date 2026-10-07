# BHRAM — Threat Model
# Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence
# Part 1 Threat Model

## Scope

This threat model covers Part 1 of BHRAM: the deception environment infrastructure.
It defines trusted vs. untrusted actors, assets, threats, and controls.

## Actors

| Actor               | Trust Level | Description                                               |
|---------------------|-------------|-----------------------------------------------------------|
| BHRAM operator      | Trusted     | Researcher/student managing the lab                       |
| AI/ML agents        | Semi-trusted| Part 2 agents — access via BHRAM API only                 |
| Simulated attacker  | Untrusted   | Any actor connecting to port 2222 or 8080                 |
| Docker engine       | Trusted     | Container runtime on the lab host                         |
| Lab host OS         | Trusted     | Ubuntu Server 24.04 running the lab                       |

## Assets

| Asset                  | Sensitivity | Location                          |
|------------------------|-------------|-----------------------------------|
| PostgreSQL data        | High        | Internal Docker volume            |
| BHRAM API              | Medium      | Backend network, loopback only    |
| Cowrie logs            | High        | Docker volume (cowrie_logs)       |
| Decoy files (bait)     | Low (bait)  | File server volume                |
| Lab host filesystem    | Critical    | Not accessible to containers      |

## Threats and Controls

### T1: Attacker escapes Cowrie to host
- **Likelihood**: Low
- **Impact**: Critical
- **Controls**:
  - Cowrie runs as UID 1000 (non-root)
  - `cap_drop: ALL`
  - `no-new-privileges: true`
  - Cowrie container has NO access to backend/internal networks
  - No host filesystem mounts in Cowrie container

### T2: Attacker reaches database via web application
- **Likelihood**: Low
- **Impact**: High
- **Controls**:
  - PostgreSQL is on `internal` network only (`internal: true` in Docker)
  - Web app is on `frontend` network — cannot reach `internal`
  - No dynamic SQL execution via web app
  - No database connection string exposed to web tier

### T3: Attacker uses BHRAM API to execute commands
- **Likelihood**: Medium (if API were exposed)
- **Impact**: Critical
- **Controls**:
  - API bound to `127.0.0.1` only — not reachable from frontend/attacker
  - No command execution endpoint exists
  - All inputs validated by Pydantic
  - Path traversal rejected in file server

### T4: Attacker discovers real credentials in deception files
- **Likelihood**: N/A (mitigated by design)
- **Impact**: N/A
- **Controls**:
  - All credentials in honeypot files are explicitly labeled FAKE
  - Fake hashes use non-existent hash prefixes (`FAKEHASH_NOT_REAL_`)
  - Fake API keys use `FAKE_KEY_NOT_REAL_` prefix
  - No real `.env` values appear in repository

### T5: Container privilege escalation
- **Likelihood**: Low
- **Impact**: High  
- **Controls**:
  - All service containers run as non-root users (UID 1001)
  - Cowrie runs as UID 1000
  - `no-new-privileges: true` on Cowrie
  - `cap_drop: ALL` on Cowrie
  - No `privileged: true` containers

### T6: Attacker enumerates internal services via Cowrie
- **Likelihood**: Medium (intentional deception)
- **Impact**: Low (deception is the goal)
- **Controls**:
  - Cowrie's fake filesystem contains fictional network data only
  - Cowrie cannot reach 172.21.0.0/24 or 172.22.0.0/24
  - All hostnames in bait files are `.internal` — not real

## Security Boundaries Summary

```
[ATTACKER] → [FRONTEND NETWORK] → [Cowrie / Web]
                                        ↓
                               !! CANNOT REACH !!
                                        ↓
                         [BACKEND] → [API / FileServer]
                                        ↓
                               !! CANNOT REACH !!
                                        ↓
                          [INTERNAL] → [PostgreSQL]
                                        ↓
                               !! CANNOT REACH !!
                                        ↓
                              [LAB HOST FILESYSTEM]
```

## Out of Scope (Part 1)

- Real attacker attribution
- AI/ML agent security (Part 2)
- Production network exposure
- Inter-agent trust model (Part 2)
