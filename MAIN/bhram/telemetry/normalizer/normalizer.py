"""
BHRAM Telemetry — Event Normalizer
====================================

The normalizer is the central processing stage:

  Raw Source → Collector → [Normalizer] → Storage / API / Dashboard

Responsibilities:
  1. Session correlation — link events to an AttackSession by source_ip + session_id
  2. Severity enrichment — bump severity based on session context
  3. TTP tagging — classify events against MITRE ATT&CK-inspired tags
  4. Deduplication guard — flag repeated identical events within a short window

The normalizer does NOT persist data — that is done by the StoragePipeline.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

from bhram.telemetry.schemas import CanonicalEvent

logger = logging.getLogger("bhram.telemetry.normalizer")

# ── MITRE ATT&CK inspired TTP tags ───────────────────────────────────────────

_COMMAND_TTP_PATTERNS: List[tuple] = [
    # (substring_match, ttp_tag)
    ("whoami",              "T1033 - System Owner Discovery"),
    ("id\n",                "T1033 - System Owner Discovery"),
    ("cat /etc/passwd",     "T1003 - OS Credential Dumping"),
    ("cat /etc/shadow",     "T1003 - OS Credential Dumping"),
    ("/etc/passwd",         "T1003 - OS Credential Dumping"),
    ("/etc/shadow",         "T1003 - OS Credential Dumping"),
    ("ifconfig",            "T1016 - System Network Config Discovery"),
    ("ip addr",             "T1016 - System Network Config Discovery"),
    ("netstat",             "T1049 - System Network Connections Discovery"),
    ("ps aux",              "T1057 - Process Discovery"),
    ("ls -la",              "T1083 - File and Directory Discovery"),
    ("find /",              "T1083 - File and Directory Discovery"),
    ("wget ",               "T1105 - Ingress Tool Transfer"),
    ("curl ",               "T1105 - Ingress Tool Transfer"),
    ("chmod +x",            "T1222 - File and Directory Permissions Modification"),
    ("ssh ",                "T1021 - Remote Services"),
    ("ssh-keygen",          "T1098 - Account Manipulation"),
    ("history",             "T1552 - Credentials in Files"),
    (".ssh/",               "T1552 - Credentials in Files"),
    ("sudo ",               "T1548 - Abuse Elevation Control"),
    ("su ",                 "T1548 - Abuse Elevation Control"),
    ("uname -a",            "T1082 - System Information Discovery"),
    ("cat /proc/version",   "T1082 - System Information Discovery"),
    ("crontab",             "T1053 - Scheduled Task/Job"),
    ("nmap",                "T1046 - Network Service Scanning"),
    ("/bin/bash",           "T1059 - Command and Scripting Interpreter"),
    ("python",              "T1059 - Command and Scripting Interpreter"),
    ("perl",                "T1059 - Command and Scripting Interpreter"),
    ("base64",              "T1027 - Obfuscated Files or Information"),
    ("tar ",                "T1560 - Archive Collected Data"),
    ("zip ",                "T1560 - Archive Collected Data"),
]

_AUTH_SUCCESS_TTP = "T1078 - Valid Accounts"
_PORT_SCAN_TTP    = "T1046 - Network Service Scanning"
_FILE_ACCESS_TTP  = "T1083 - File and Directory Discovery"
_FILE_EXFIL_TTP   = "T1041 - Exfiltration over C2 Channel"


def _tag_ttps(event: CanonicalEvent) -> List[str]:
    """Identify applicable MITRE ATT&CK-inspired TTP tags for an event."""
    ttps: Set[str] = set()

    evt_type = event.event.type
    action = (event.event.action or "").lower()

    if evt_type == "command":
        for pattern, ttp in _COMMAND_TTP_PATTERNS:
            if pattern in action:
                ttps.add(ttp)

    elif evt_type == "authentication" and event.event.outcome == "success":
        ttps.add(_AUTH_SUCCESS_TTP)

    elif evt_type == "port_scan":
        ttps.add(_PORT_SCAN_TTP)

    elif evt_type in ("file_access", "file_create", "file_modify", "file_delete"):
        ttps.add(_FILE_ACCESS_TTP)
        bait = event.metadata.get("bait_level", 1)
        if bait >= 4:
            ttps.add(_FILE_EXFIL_TTP)

    elif evt_type == "credential_attempt":
        ttps.add("T1110 - Brute Force")

    return sorted(ttps)


# ── Session state (in-memory per-normalizer instance) ────────────────────────

class SessionState:
    """Lightweight in-memory session tracker for the normalizer."""

    def __init__(self):
        # Maps canonical session key → session metadata
        self._sessions: Dict[str, Dict] = {}
        # Deduplication: maps event fingerprint → last seen timestamp
        self._recent_hashes: Dict[str, datetime] = {}

    def _session_key(self, event: CanonicalEvent) -> Optional[str]:
        """Derive a session grouping key from event fields."""
        if event.session_id:
            return event.session_id
        if event.source_ip:
            return f"ip:{event.source_ip}"
        return None

    def get_or_create_session(self, event: CanonicalEvent) -> Optional[str]:
        """Return session key and update session metadata."""
        key = self._session_key(event)
        if not key:
            return None

        if key not in self._sessions:
            self._sessions[key] = {
                "session_id": key,
                "source_ip": event.source_ip,
                "start_time": event.timestamp,
                "last_seen": event.timestamp,
                "event_count": 0,
                "hosts_touched": set(),
                "services_touched": set(),
                "commands_executed": [],
                "authentication_attempts": 0,
                "ttps_observed": set(),
            }

        sess = self._sessions[key]
        sess["last_seen"] = event.timestamp
        sess["event_count"] += 1

        if event.target.host:
            sess["hosts_touched"].add(event.target.host)
        if event.target.service:
            sess["services_touched"].add(event.target.service)
        if event.event.type == "command" and event.event.action:
            sess["commands_executed"].append(event.event.action)
        if event.event.type in ("authentication", "credential_attempt"):
            sess["authentication_attempts"] += 1

        return key

    def is_duplicate(self, event: CanonicalEvent, window_secs: int = 5) -> bool:
        """Detect identical events within a dedup window (prevents log storms)."""
        fingerprint = hashlib.sha256(
            f"{event.source_ip}{event.event.type}{event.event.action}{event.target.path}".encode()
        ).hexdigest()[:16]

        now = event.timestamp
        if fingerprint in self._recent_hashes:
            last = self._recent_hashes[fingerprint]
            if (now - last).total_seconds() < window_secs:
                return True

        self._recent_hashes[fingerprint] = now
        # Prune old hashes to avoid memory growth
        cutoff = now - timedelta(minutes=5)
        self._recent_hashes = {
            k: v for k, v in self._recent_hashes.items() if v > cutoff
        }
        return False

    def session_summary(self, session_key: str) -> Optional[Dict]:
        """Return a summary dict for a given session key."""
        sess = self._sessions.get(session_key)
        if not sess:
            return None
        return {
            **sess,
            "hosts_touched": list(sess["hosts_touched"]),
            "services_touched": list(sess["services_touched"]),
            "ttps_observed": list(sess["ttps_observed"]),
            "duration_secs": (
                (sess["last_seen"] - sess["start_time"]).total_seconds()
            ),
        }

    def all_sessions(self) -> List[Dict]:
        return [self.session_summary(k) for k in self._sessions]


# ── Main normalizer ───────────────────────────────────────────────────────────

class EventNormalizer:
    """
    Central normalizer that enriches CanonicalEvents before storage.

    Pipeline:
      1. Session correlation (group by session_id or source_ip)
      2. TTP tagging
      3. Duplicate detection
      4. Severity escalation (based on session context)

    Usage:
        normalizer = EventNormalizer()
        enriched, ttps = normalizer.process(event)
        if enriched:
            await storage.save(enriched)
    """

    def __init__(self, dedup_window_secs: int = 5):
        self.session_state = SessionState()
        self._dedup_window = dedup_window_secs

    def process(
        self, event: CanonicalEvent
    ) -> tuple[Optional[CanonicalEvent], List[str]]:
        """
        Enrich event and return (enriched_event, ttp_list).
        Returns (None, []) if event is a duplicate and should be dropped.
        """
        # Dedup check
        if self.session_state.is_duplicate(event, self._dedup_window):
            logger.debug("Duplicate event dropped: %s", event.event.type)
            return None, []

        # Session correlation
        session_key = self.session_state.get_or_create_session(event)

        # TTP tagging
        ttps = _tag_ttps(event)

        # Inject TTPs into metadata
        if ttps:
            event.metadata["ttps"] = ttps
            if session_key:
                sess = self.session_state._sessions.get(session_key, {})
                if "ttps_observed" in sess:
                    sess["ttps_observed"].update(ttps)

        # Severity escalation: if session has prior auth success + now commands → high
        if session_key:
            sess = self.session_state._sessions.get(session_key, {})
            cmd_count = len(sess.get("commands_executed", []))
            if event.event.type == "command" and cmd_count > 10:
                if event.severity in ("low", "medium"):
                    event.severity = "high"
                    event.metadata["severity_escalated"] = True

        return event, ttps
