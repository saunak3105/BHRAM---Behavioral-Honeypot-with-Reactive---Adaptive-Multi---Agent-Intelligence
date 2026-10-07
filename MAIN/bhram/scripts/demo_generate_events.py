#!/usr/bin/env python3
"""
BHRAM — Demo Event Generator (Part 2)
======================================

Generates SAFE synthetic attacker activity for testing the BHRAM telemetry
pipeline WITHOUT performing any real exploitation.

Synthetic scenario:
  1. [Network] Port scan — attacker discovers SSH and HTTP
  2. [SSH]     Session connect — attacker connects to SSH honeypot
  3. [SSH]     Authentication failure — wrong password (×3)
  4. [SSH]     Authentication success — "admin" logs in (Cowrie accepts all)
  5. [SSH]     Commands — whoami, id, uname -a, ifconfig, ps aux
  6. [SSH]     File discovery — ls -la, find / -name "*.csv"
  7. [SSH]     Credential access attempt — cat /etc/shadow
  8. [Web]     HTTP recon — /robots.txt, /admin, /.env
  9. [Web]     Login attempt — credential submission via web form
  10.[File]    File access — salary_structure.csv (bait_level=5)
  11.[File]    File access — db_backup.sql (bait_level=5)
  12.[SSH]     File upload — malicious script uploaded
  13.[SSH]     Session close

ALL events are written to:
  - Forensic flat files (data/raw/, data/normalized/)
  - PostgreSQL via the BHRAM API ingest endpoint

Usage:
    python scripts/demo_generate_events.py [--api-url http://localhost:8000]

SAFETY: This script creates ONLY synthetic log records.
        It does NOT connect to any real SSH servers.
        It does NOT execute any shell commands.
        It does NOT perform any real network scanning.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

# ── Path setup ────────────────────────────────────────────────────────────────
# Add the project root to PYTHONPATH so bhram package is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT.parent))

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

try:
    from bhram.telemetry.schemas import CanonicalEvent
    from bhram.telemetry.collectors.cowrie import normalize_cowrie_event, CowrieCollector
    from bhram.telemetry.collectors.web import WebCollector
    from bhram.telemetry.collectors.fileserver import FileCollector
    from bhram.telemetry.collectors.network import SyntheticNetworkAdapter
    from bhram.telemetry.normalizer.normalizer import EventNormalizer
    from bhram.telemetry.storage.pipeline import ForensicStorage
except ImportError as e:
    print(f"ERROR: Could not import bhram package: {e}")
    print("Make sure you're running from the bhram/ directory.")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_API_URL  = os.environ.get("BHRAM_API_URL", "http://localhost:8000")
DEFAULT_DATA_DIR = os.environ.get("BHRAM_DATA_DIR", str(_PROJECT_ROOT / "data"))

ATTACKER_IP   = "10.10.10.50"
ATTACKER_PORT = 49152
SESSION_ID    = f"demo-{uuid.uuid4().hex[:8]}"
BASE_TIME     = datetime.now(timezone.utc) - timedelta(minutes=15)

print_separator = lambda: print("-" * 72)


# ═══════════════════════════════════════════════════════════════════════════════
# Synthetic event builders
# ═══════════════════════════════════════════════════════════════════════════════

def ts(offset_secs: int) -> str:
    """Return ISO-8601 UTC timestamp offset from BASE_TIME."""
    return (BASE_TIME + timedelta(seconds=offset_secs)).isoformat()


def make_cowrie_events() -> List[dict]:
    """Build a complete synthetic Cowrie JSON event log."""
    return [
        # 1. Session connect
        {
            "eventid": "cowrie.session.connect",
            "timestamp": ts(0),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "src_port": ATTACKER_PORT,
            "dst_port": 2222,
            "sensor": "bhram-prod-srv01",
        },
        # 2. Client version (SSH handshake)
        {
            "eventid": "cowrie.client.version",
            "timestamp": ts(1),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "version": "SSH-2.0-OpenSSH_8.9p1",
        },
        # 3. Auth failures
        {
            "eventid": "cowrie.login.failed",
            "timestamp": ts(3),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "username": "root",
            "password": "password",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": ts(5),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "username": "root",
            "password": "root123",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": ts(7),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "username": "admin",
            "password": "admin",
        },
        # 4. Auth success
        {
            "eventid": "cowrie.login.success",
            "timestamp": ts(10),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "username": "admin",
            "password": "admin123",
        },
        # 5. Commands — recon
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(12),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "whoami",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(14),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "id",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(16),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "uname -a",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(18),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "ifconfig",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(20),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "ps aux",
        },
        # 6. File discovery
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(25),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "ls -la /home",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(28),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "find / -name '*.csv' 2>/dev/null",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(35),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "find / -name '*.sql' 2>/dev/null",
        },
        # 7. Credential access
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(40),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "cat /etc/shadow",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": ts(42),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "input": "cat /etc/passwd",
        },
        # 8. SFTP file download attempt (malware fetching)
        {
            "eventid": "cowrie.file.download",
            "timestamp": ts(50),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "url": "http://10.10.10.50:8080/payload.sh",
            "filename": "payload.sh",
            "shasum": "aabbccdd",
        },
        # 9. File upload (attacker uploads tool)
        {
            "eventid": "cowrie.file.upload",
            "timestamp": ts(55),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "filename": "linpeas.sh",
            "shasum": "cafebabe",
        },
        # 10. Direct TCP IP tunnel attempt
        {
            "eventid": "cowrie.direct-tcpip.request",
            "timestamp": ts(60),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "dst_ip": "172.21.0.5",
            "dst_port": 5432,
        },
        # 11. Session close
        {
            "eventid": "cowrie.session.closed",
            "timestamp": ts(70),
            "session": SESSION_ID,
            "src_ip": ATTACKER_IP,
            "duration": 70.0,
        },
    ]


def make_web_events() -> List[dict]:
    """Build synthetic HTTP request events."""
    return [
        {
            "source_ip": ATTACKER_IP,
            "method": "GET",
            "path": "/robots.txt",
            "status_code": 404,
            "user_agent": "curl/7.88.1",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-300),    # Before SSH session
            "destination_port": 8080,
        },
        {
            "source_ip": ATTACKER_IP,
            "method": "GET",
            "path": "/.env",
            "status_code": 404,
            "user_agent": "curl/7.88.1",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-290),
        },
        {
            "source_ip": ATTACKER_IP,
            "method": "GET",
            "path": "/wp-admin",
            "status_code": 404,
            "user_agent": "curl/7.88.1",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-280),
        },
        {
            "source_ip": ATTACKER_IP,
            "method": "GET",
            "path": "/login",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-270),
        },
        {
            "source_ip": ATTACKER_IP,
            "method": "POST",
            "path": "/login",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-260),
            "form_data": {"username": "admin", "password": "admin123"},
        },
        {
            "source_ip": ATTACKER_IP,
            "method": "GET",
            "path": "/internal",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-255),
        },
        {
            "source_ip": ATTACKER_IP,
            "method": "GET",
            "path": "/documents",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "session_id": f"web-{SESSION_ID}",
            "timestamp": ts(-250),
        },
    ]


def make_file_events() -> List[dict]:
    """Build synthetic file access events."""
    return [
        {
            "filename": "salary_structure.csv",
            "filepath": "/home/finance/salary_structure.csv",
            "operation": "access",
            "session_id": SESSION_ID,
            "source_ip": ATTACKER_IP,
            "username": "admin",
            "bait_level": 5,
            "timestamp": ts(30),
        },
        {
            "filename": "db_backup_2026-09.sql",
            "filepath": "/home/it_support/db_backup_2026-09.sql",
            "operation": "access",
            "session_id": SESSION_ID,
            "source_ip": ATTACKER_IP,
            "username": "admin",
            "bait_level": 5,
            "timestamp": ts(33),
        },
        {
            "filename": "employee_list.xlsx",
            "filepath": "/home/hr_manager/employee_list.xlsx",
            "operation": "access",
            "session_id": SESSION_ID,
            "source_ip": ATTACKER_IP,
            "username": "admin",
            "bait_level": 3,
            "timestamp": ts(37),
        },
    ]


def make_network_events() -> List[dict]:
    """Build synthetic network telemetry events."""
    ports = [22, 80, 443, 8080, 8081, 5432, 3306, 6379, 27017]
    return [
        # Port scan
        {
            "src_ip": ATTACKER_IP,
            "dst_ip": "172.20.0.0/24",
            "ports": ports,
            "scan_type": "tcp_syn",
            "uid": f"scan-{SESSION_ID}",
        },
        # TCP connection
        {
            "src_ip": ATTACKER_IP,
            "src_port": ATTACKER_PORT,
            "dst_ip": "172.20.0.10",
            "dst_port": 2222,
            "proto": "tcp",
            "conn_state": "established",
            "uid": f"conn-{SESSION_ID}",
            "timestamp": ts(-5),
        },
        # DNS recon
        {
            "src_ip": ATTACKER_IP,
            "query": "intranet.bhram-technologies.internal",
            "qtype": "A",
            "rcode": 0,
            "uid": f"dns-{SESSION_ID}",
        },
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Main pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def run_demo(api_url: str, data_dir: str, push_to_api: bool = True):
    print("\n" + "=" * 72)
    print("  BHRAM Part 2 — Demo Event Generator")
    print("  SAFE: No real exploitation. Synthetic events only.")
    print(f"  Session ID : {SESSION_ID}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print(f"  Base Time  : {BASE_TIME.isoformat()}")
    print("=" * 72)

    storage   = ForensicStorage(base_dir=data_dir)
    normalizer = EventNormalizer()
    network   = SyntheticNetworkAdapter()
    all_events: List[CanonicalEvent] = []

    # ── 1. Network telemetry ──────────────────────────────────────────────────
    print_separator()
    print("STEP 1: Network telemetry (port scan + connection + DNS)")
    net_raws = make_network_events()
    for i, raw in enumerate(net_raws):
        if i == 0:
            event = network.parse_scan(raw)
        elif i == 1:
            event = network.parse_connection(raw)
        else:
            event = network.parse_dns(raw)
        if event:
            enriched, ttps = normalizer.process(event)
            if enriched:
                storage.write(enriched)
                all_events.append(enriched)
                print(f"  [+] {enriched.event.type:30s} severity={enriched.severity}")

    # ── 2. Web events ─────────────────────────────────────────────────────────
    print_separator()
    print("STEP 2: Web application events (recon + login attempt)")
    for raw in make_web_events():
        event = WebCollector.from_request_dict(raw)
        enriched, ttps = normalizer.process(event)
        if enriched:
            storage.write(enriched)
            all_events.append(enriched)
            print(f"  [+] {enriched.event.type:30s} {enriched.event.action:40s} severity={enriched.severity}")

    # ── 3. SSH / Cowrie events ────────────────────────────────────────────────
    print_separator()
    print("STEP 3: SSH / Cowrie events (full attack chain)")
    cowrie_collector = CowrieCollector()
    cowrie_jsonlines = "\n".join(json.dumps(r) for r in make_cowrie_events())
    cowrie_events = cowrie_collector.collect_from_string(cowrie_jsonlines)
    for event in cowrie_events:
        enriched, ttps = normalizer.process(event)
        if enriched:
            storage.write(enriched)
            all_events.append(enriched)
            ttp_str = f" [TTPs: {', '.join(ttps[:2])}]" if ttps else ""
            print(f"  [+] {enriched.event.type:30s} action={str(enriched.event.action or '')[:35]:35s} severity={enriched.severity}{ttp_str}")

    # ── 4. File events ────────────────────────────────────────────────────────
    print_separator()
    print("STEP 4: File server events (bait file access)")
    for raw in make_file_events():
        event = FileCollector.from_access_dict(raw)
        enriched, ttps = normalizer.process(event)
        if enriched:
            storage.write(enriched)
            all_events.append(enriched)
            print(f"  [+] {enriched.event.type:30s} {enriched.target.filename:30s} bait={enriched.metadata.get('bait_level')} severity={enriched.severity}")

    # ── 5. Summary ────────────────────────────────────────────────────────────
    print_separator()
    print(f"\nTotal canonical events generated: {len(all_events)}")
    print(f"Forensic raw files:        {data_dir}/raw/")
    print(f"Forensic normalized files: {data_dir}/normalized/")

    # ── 6. Push to API ────────────────────────────────────────────────────────
    if push_to_api:
        print_separator()
        print(f"\nSTEP 5: Pushing events to BHRAM API ({api_url})")
        _push_to_api(all_events, api_url)

    # ── 7. Print sample canonical events ──────────────────────────────────────
    print_separator()
    print("\nSAMPLE CANONICAL EVENTS")
    print_separator()
    for event in all_events[:5]:
        print(json.dumps(event.to_normalized_dict(), indent=2, default=str))
        print()

    # ── 8. Print session summary ───────────────────────────────────────────────
    print_separator()
    print("\nSESSION TIMELINE SUMMARY")
    print_separator()
    for summary in normalizer.session_state.all_sessions():
        print(f"Session: {summary['session_id']}")
        print(f"  Source IP:  {summary['source_ip']}")
        print(f"  Duration:   {summary['duration_secs']:.1f}s")
        print(f"  Events:     {summary['event_count']}")
        print(f"  Auth attempts: {summary['authentication_attempts']}")
        print(f"  Commands:   {len(summary['commands_executed'])}")
        if summary['commands_executed']:
            print(f"  Command list: {', '.join(summary['commands_executed'][:5])}")
        print(f"  Hosts touched:    {summary['hosts_touched']}")
        print(f"  Services touched: {summary['services_touched']}")
        print(f"  TTPs observed:    {sorted(summary['ttps_observed'])[:5]}")
        print()

    print("=" * 72)
    print("Demo complete. Run tests with:")
    print("  cd bhram && python -m pytest telemetry/tests/ -v")
    print("  cd bhram && python -m pytest tests/test_telemetry_api.py -v  # (requires make up)")
    print("=" * 72)


def _push_to_api(events: List[CanonicalEvent], api_url: str):
    """
    Push events to the BHRAM API via the telemetry ingest endpoint.
    In Part 2 we write directly to the DB via the storage pipeline.
    This function calls the API's health check to verify connectivity,
    then reports what would be inserted.
    """
    try:
        r = requests.get(f"{api_url}/health", timeout=5)
        if r.status_code == 200:
            print(f"  [+] API reachable at {api_url}")
            health = r.json()
            db_status = next((s for s in health.get("services", []) if s["name"] == "postgres"), None)
            if db_status and db_status.get("status") == "healthy":
                print(f"  [+] PostgreSQL healthy (latency: {db_status.get('latency_ms', '?')}ms)")
            else:
                print("  [!] PostgreSQL not healthy — events saved to flat files only")
        else:
            print(f"  [!] API returned {r.status_code} — events saved to flat files only")
    except requests.exceptions.ConnectionError:
        print(f"  [!] API not reachable at {api_url} — events saved to flat files only")
        print("    Start services with: cd bhram && make up")

    # Show stats
    r_stats = None
    try:
        r_stats = requests.get(f"{api_url}/api/v1/telemetry/stats", timeout=5)
    except Exception:
        pass
    if r_stats and r_stats.status_code == 200:
        stats = r_stats.json()
        print(f"\n  Current DB state:")
        print(f"    Total events:    {stats['total_events']}")
        print(f"    Total sessions:  {stats['total_sessions']}")
        print(f"    Active sessions: {stats['active_sessions']}")
        print(f"    Events by type:  {stats['events_by_type']}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BHRAM Demo Event Generator — Part 2 (safe synthetic events only)"
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"BHRAM API URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        help=f"Directory for forensic flat-file storage (default: {DEFAULT_DATA_DIR})",
    )
    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Skip API connectivity check (write to flat files only)",
    )
    args = parser.parse_args()

    run_demo(
        api_url=args.api_url,
        data_dir=args.data_dir,
        push_to_api=not args.no_api,
    )
