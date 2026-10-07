# BHRAM — Network Design

## Overview

BHRAM uses three segregated Docker networks implementing strict least-connectivity principles:

## Network Definitions

### `bhram_frontend` — Attacker-Facing Surface
- **Subnet**: 172.20.0.0/24
- **Members**: `cowrie`, `web`
- **Routing**: External (attacker-reachable)
- **Design**: Services here MUST be able to receive untrusted input safely

### `bhram_backend` — Internal Service Plane  
- **Subnet**: 172.21.0.0/24
- **Members**: `bhram-api`, `fileserver`, `web`
- **Routing**: Host loopback only (127.0.0.1:8000, 127.0.0.1:8081)
- **Design**: Never directly reachable from attacker

### `bhram_internal` — Management Plane
- **Subnet**: 172.22.0.0/24
- **Members**: `postgres`, `bhram-api`, `fileserver`
- **Routing**: `internal: true` — Docker blocks all external routing
- **Design**: Physically impossible to route to from outside Docker

## Connectivity Matrix

| From → To      | frontend | backend | internal |
|----------------|----------|---------|----------|
| cowrie         | ✓        | ✗       | ✗        |
| web            | ✓        | ✓       | ✗        |
| bhram-api      | ✗        | ✓       | ✓        |
| fileserver     | ✗        | ✓       | ✓        |
| postgres       | ✗        | ✗       | ✓        |

## Port Exposure

| Container   | Internal Port | Host Binding      | Accessible From  |
|-------------|---------------|-------------------|------------------|
| cowrie      | 2222          | 0.0.0.0:2222      | Anywhere (bait)  |
| web         | 5000          | 0.0.0.0:8080      | Anywhere (bait)  |
| bhram-api   | 8000          | 127.0.0.1:8000    | Localhost only   |
| fileserver  | 8081          | 127.0.0.1:8081    | Localhost only   |
| postgres    | 5432          | Not exposed       | Internal Docker  |

## Key Security Properties

1. **Cowrie isolation**: The honeypot container cannot initiate connections to the database or API
2. **Database isolation**: `internal: true` network makes it unreachable from outside Docker
3. **API loopback**: BHRAM API only binds to 127.0.0.1 — no exposure to lab LAN
4. **No cross-contamination**: Cowrie has zero network path to PostgreSQL

## DNS Within Docker

Docker provides automatic DNS for container names:
- `postgres` resolves within internal + backend networks
- `bhram-api` resolves within backend network
- `cowrie` resolves within frontend network only
