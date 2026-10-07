# BHRAM Telemetry & Event-Normalization Pipeline
## Part 2 Architecture Specification

> **Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence**  
> Status: **Part 2 Complete**

---

## 1. Overview & Objectives

BHRAM Part 2 builds the complete cybersecurity telemetry and event-normalization layer. Its primary responsibility is transforming raw, heterogeneous attacker activity from multiple deception surfaces into a standardized canonical event stream for downstream consumption by AI/ML agents, relational storage, and forensic archiving.

```
Raw Attacker Activity
  ├── Cowrie SSH Honeypot (:2222)
  ├── Fake Company Website (:8080)
  ├── Deception File Server (:8081)
  └── Network Telemetry (Connections, Scans, DNS)
          │
          ▼
Telemetry Collectors
  ├── CowrieCollector (JSON-lines stream/tail)
  ├── WebCollector (HTTP access/audit log)
  ├── FileCollector (Access, modify, download audit)
  └── SyntheticNetworkAdapter (SYN scan, TCP flow, DNS)
          │
          ▼
Event Normalizer & Session State Engine
  ├── Canonical Schema Normalization
  ├── Deduplication Cache (sliding window)
  ├── Automatic Severity Assignment
  ├── MITRE ATT&CK TTP Tagging (T1046, T1110, T1003, T1083, etc.)
  └── Multi-session Correlator (IP + session ID)
          │
          ▼
Telemetry Storage Pipeline (Dual-Write)
  ├── Forensic Storage (Immutable Append-only JSONL files)
  │     ├── data/raw/YYYY/MM/DD/{source}.jsonl
  │     └── data/normalized/YYYY/MM/DD/events.jsonl
  └── PostgreSQL 16 (Relational + JSONB)
        ├── raw_events (raw immutable log + SHA-256 integrity hash)
        ├── events (canonical normalized data + analysis status)
        ├── attack_sessions (aggregated session timeline)
        └── session_events (junction table for instant lookup)
          │
          ▼
AI/ML Interface API
  ├── GET  /api/v1/ai/events       (Batched unanalyzed events)
  ├── POST /api/v1/ai/profile      (Attacker profile submission)
  ├── POST /api/v1/ai/decision     (Allowlist-validated deception decisions)
  └── GET  /api/v1/telemetry/stats (Pipeline volume, top IPs, event breakdown)
```

---

## 2. Canonical BHRAM Event Schema

Every incoming event from any collector is mapped to the single canonical schema (`bhram.telemetry.schemas.CanonicalEvent`):

| Field | Type | Description |
|---|---|---|
| `event_id` | UUID | Globally unique event identifier |
| `timestamp` | ISO-8601 UTC | Exact time of event occurrence |
| `session_id` | String | Source component or correlated session identifier |
| `source_ip` | INET / String | Attacker IP address |
| `source_port` | Integer | Attacker client port |
| `destination_host` | String | Honeypot host/container target |
| `destination_port` | Integer | Honeypot service port |
| `source` | Object | `{ component, version, host }` |
| `event` | Object | `{ type, category, action, outcome }` |
| `actor` | Object | `{ username, session_id, user_agent }` |
| `target` | Object | `{ host, port, service, path, filename }` |
| `severity` | Enum | `info`, `low`, `medium`, `high`, `critical` |
| `metadata` | JSONB / Dict | Source-specific data, MITRE ATT&CK TTPs, bait levels |

### Event Type Taxonomy
- `authentication`: Login attempts, successes, failures.
- `command`: Interactive shell commands executed in Cowrie.
- `network_connection`: TCP/UDP connections established or dropped.
- `port_scan`: Multi-port scanning activity detected.
- `file_access`: File read, download, or access attempts.
- `file_create`: File upload, creation, staging.
- `file_modify`: File tampering or editing attempts.
- `file_delete`: File removal.
- `web_request`: HTTP requests to decoy endpoints.
- `credential_attempt`: Web login/form credential submission.
- `honeypot_detection_attempt`: Attacker probing for honeypot artifacts (`/.env`, `/robots.txt`).
- `session_start` / `session_end`: Lifecycle markers of attack interactions.

---

## 3. Telemetry Collectors

### 3.1 Cowrie Collector (`bhram/telemetry/collectors/cowrie.py`)
- Ingests Cowrie JSON-lines log stream (`cowrie.json`).
- Handles `cowrie.session.connect`, `cowrie.login.success`, `cowrie.login.failed`, `cowrie.command.input`, `cowrie.session.file_upload`, and `cowrie.session.closed`.
- Preserves full raw event in `raw_data`.
- Automatically maps commands to MITRE ATT&CK TTPs (e.g. `whoami` -> `T1033`, `cat /etc/shadow` -> `T1003`).

### 3.2 Web Collector (`bhram/telemetry/collectors/web.py`)
- Ingests Flask request records from `bhram_web`.
- Distinguishes standard decoy browsing from credential probing and honeypot detection attempts.
- Flags suspicious path traversals, configuration probing (`/.env`, `/admin`, `/robots.txt`).

### 3.3 File Server Collector (`bhram/telemetry/collectors/fileserver.py`)
- Captures file access events on the decoy file server (`bhram_fileserver`).
- Contextualizes file accesses with honeytoken bait levels (e.g., `salary_structure.csv` bait=5 -> critical severity).

### 3.4 Network Telemetry Collector (`bhram/telemetry/collectors/network.py`)
- Parses SYN port scans, TCP connection logs, and internal DNS queries.
- Associates port scan summaries with `T1046 - Network Service Scanning`.

---

## 4. Normalizer & Session State Tracking

The `EventNormalizer` (`bhram/telemetry/normalizer/normalizer.py`):
1. **Deduplication:** Drops rapid identical duplicate events (e.g., repeating port scans or failed auth bursts) within a configurable sliding window.
2. **Dynamic Severity Escalation:** If a session issues >5 commands or probes sensitive assets, severity is automatically escalated.
3. **Session State Correlation:** Maintains active session summaries including:
   - Total duration
   - Command history
   - Hosts and services touched
   - Observed MITRE ATT&CK TTPs
   - Authentication attempt tally

---

## 5. Dual-Write Storage Pipeline

The pipeline (`bhram/telemetry/storage/pipeline.py`) ensures forensic integrity:
1. **Forensic Storage (Append-only Flat Files):**
   - Raw logs: `data/raw/YYYY/MM/DD/{source}.jsonl`
   - Normalized logs: `data/normalized/YYYY/MM/DD/events.jsonl`
   - Raw records are immutable and never modified or deleted.
2. **PostgreSQL Relational Storage:**
   - `raw_events`: Contains `raw_data` JSONB along with a SHA-256 hash for evidentiary verification.
   - `events`: Contains full canonical representation with indexed lookups on `session_id`, `source_ip`, `category`, and `severity`.
   - `session_events`: Junction table providing instant timeline reconstructions.

---

## 6. AI/ML Agent Interface Contract

Downstream AI/ML agents interact with the telemetry pipeline via REST API:

- **`GET /api/v1/ai/events?limit=50`**
  Fetches batches of unanalyzed canonical events with both `normalized_data` and original `raw_data`.
- **`POST /api/v1/ai/profile`**
  Submits an AI-synthesized attacker profile (skill level, intent, threat score, observed TTPs) correlated with an active session.
- **`POST /api/v1/ai/decision`**
  Submits deception response decisions. Validated strictly against `AI_ACTION_ALLOWLIST`:
  - `add_decoy_file`
  - `modify_decoy_content`
  - `delay_response`
  - `simulate_service_crash`
  - `escalate_privilege_fake`
  - `inject_fake_process`
  - `isolate_session`
  - `log_forensic_snapshot`
  - `change_deception_mode`
  - `alert_operator`

Arbitrary commands, unvetted action strings, or shell payloads are rejected with HTTP 422.

---

## 7. Verification & Testing

### Running Unit Tests (no external dependencies)
```bash
cd bhram
python -m pytest telemetry/tests/ -v
# or
pytest -m unit -v
```
All 58 unit tests pass in < 0.3s.

### Generating Safe Synthetic Telemetry
```bash
python scripts/demo_generate_events.py --no-api
```
Simulates a multi-stage attack scenario (network scan -> SSH brute force -> command execution -> credential dumping -> file exfiltration) and writes forensic files.
