"""
BHRAM Telemetry — Cowrie Collector
====================================

Reads Cowrie JSON event logs and normalizes them into canonical BHRAM events.

Cowrie emits JSON-lines files at:
  /home/cowrie/var/log/cowrie/cowrie.json[.YYYY-MM-DD]

Each line is a JSON object with an "eventid" field that determines its type.

Supported Cowrie eventids:
  cowrie.session.connect     → session_start
  cowrie.session.closed      → session_end
  cowrie.login.success       → authentication (success)
  cowrie.login.failed        → authentication (failure)
  cowrie.command.input       → command
  cowrie.command.failed      → command (failed)
  cowrie.file.upload         → file_create
  cowrie.file.download       → file_access
  cowrie.sftp.open           → file_access
  cowrie.sftp.put            → file_create
  cowrie.client.version      → service_interaction (SSH version exchange)
  cowrie.client.fingerprint  → service_interaction (SSH key fingerprint)
  cowrie.direct-tcpip.request → network_connection
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from bhram.telemetry.schemas import (
    ActorInfo,
    CanonicalEvent,
    EventDetail,
    EventSource,
    TargetInfo,
)

logger = logging.getLogger("bhram.telemetry.cowrie")


# ── Cowrie event → canonical mapping ─────────────────────────────────────────

_COWRIE_SOURCE = EventSource(component="cowrie", version="2.x")

_EVENTID_MAP = {
    "cowrie.session.connect":       "session_start",
    "cowrie.session.closed":        "session_end",
    "cowrie.login.success":         "authentication",
    "cowrie.login.failed":          "authentication",
    "cowrie.command.input":         "command",
    "cowrie.command.failed":        "command",
    "cowrie.file.upload":           "file_create",
    "cowrie.file.download":         "file_access",
    "cowrie.sftp.open":             "file_access",
    "cowrie.sftp.put":              "file_create",
    "cowrie.client.version":        "service_interaction",
    "cowrie.client.fingerprint":    "service_interaction",
    "cowrie.direct-tcpip.request":  "network_connection",
}

_CATEGORY_MAP = {
    "session_start":        "ssh",
    "session_end":          "ssh",
    "authentication":       "auth",
    "command":              "ssh",
    "file_create":          "file_access",
    "file_access":          "file_access",
    "service_interaction":  "system",
    "network_connection":   "network",
}


def _parse_timestamp(ts: Optional[str]) -> datetime:
    """Parse Cowrie ISO timestamp to UTC datetime."""
    if not ts:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _cowrie_severity(eventid: str, raw: dict) -> str:
    """Map Cowrie event to BHRAM severity."""
    if eventid == "cowrie.login.success":
        return "critical"
    if eventid == "cowrie.login.failed":
        return "medium"
    if eventid == "cowrie.command.input":
        cmd = raw.get("input", "").lower()
        dangerous = ("passwd", "shadow", "/etc/", "curl ", "wget ", "chmod", "ssh-keygen", "id_rsa", "sudo", "su ")
        return "high" if any(d in cmd for d in dangerous) else "medium"
    if eventid in ("cowrie.file.upload", "cowrie.sftp.put"):
        return "high"
    if eventid in ("cowrie.file.download", "cowrie.sftp.open"):
        return "medium"
    if eventid == "cowrie.direct-tcpip.request":
        return "high"
    return "info"


def normalize_cowrie_event(raw: dict) -> Optional[CanonicalEvent]:
    """
    Convert a single raw Cowrie JSON event dict into a CanonicalEvent.
    Returns None if the event cannot be mapped.
    """
    eventid = raw.get("eventid", "")
    event_type = _EVENTID_MAP.get(eventid)
    if not event_type:
        logger.debug("Skipping unmapped Cowrie eventid: %s", eventid)
        return None

    category = _CATEGORY_MAP.get(event_type, "system")
    severity = _cowrie_severity(eventid, raw)
    ts = _parse_timestamp(raw.get("timestamp"))

    # Build action string from event data
    action: Optional[str] = None
    if eventid == "cowrie.command.input":
        action = raw.get("input", "")[:512]
    elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
        action = f"login:{'success' if 'success' in eventid else 'failed'}"
    elif eventid in ("cowrie.file.upload", "cowrie.sftp.put"):
        action = f"upload:{raw.get('filename', raw.get('shasum', ''))}"
    elif eventid in ("cowrie.file.download", "cowrie.sftp.open"):
        action = f"download:{raw.get('url', raw.get('filename', ''))}"
    elif eventid == "cowrie.client.version":
        action = f"ssh_version:{raw.get('version', '')}"
    elif eventid == "cowrie.direct-tcpip.request":
        action = f"tcpip:{raw.get('dst_ip', '')}:{raw.get('dst_port', '')}"
    elif eventid in ("cowrie.session.connect", "cowrie.session.closed"):
        action = eventid.split(".")[-1]

    # Outcome
    outcome = None
    if "success" in eventid:
        outcome = "success"
    elif "failed" in eventid or "closed" in eventid:
        outcome = "failure"

    return CanonicalEvent(
        timestamp=ts,
        session_id=raw.get("session"),
        source_ip=raw.get("src_ip"),
        source_port=raw.get("src_port"),
        destination_host=raw.get("sensor", "cowrie"),
        destination_port=raw.get("dst_port", 2222),
        source=EventSource(
            component="cowrie",
            version=raw.get("cowrie_version", "2.x"),
            host=raw.get("sensor"),
        ),
        event=EventDetail(
            type=event_type,
            category=category,
            action=action,
            outcome=outcome,
        ),
        actor=ActorInfo(
            username=raw.get("username"),
            session_id=raw.get("session"),
        ),
        target=TargetInfo(
            host=raw.get("sensor", "cowrie"),
            port=raw.get("dst_port", 2222),
            service="ssh",
            filename=(
                raw.get("filename") or raw.get("url") or
                raw.get("shasum")
            ),
        ),
        severity=severity,
        raw_data=raw,
        metadata={
            "cowrie_eventid": eventid,
            "duration": raw.get("duration"),
            "protocol": raw.get("protocol", "ssh"),
        },
    )


class CowrieCollector:
    """
    Reads Cowrie JSON log files and yields normalized CanonicalEvents.

    Usage:
        collector = CowrieCollector(log_dir="/home/cowrie/var/log/cowrie")
        for event in collector.collect():
            store(event)
    """

    def __init__(self, log_dir: str = "/home/cowrie/var/log/cowrie"):
        self.log_dir = Path(log_dir)

    def _log_files(self) -> List[Path]:
        """Find all cowrie.json* log files sorted oldest→newest."""
        if not self.log_dir.exists():
            logger.warning("Cowrie log dir does not exist: %s", self.log_dir)
            return []
        files = sorted(self.log_dir.glob("cowrie.json*"))
        return files

    def collect_from_file(self, path: Path) -> Generator[CanonicalEvent, None, None]:
        """Parse a single Cowrie JSON-lines log file."""
        logger.info("Parsing Cowrie log: %s", path)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Bad JSON at %s:%d — %s", path, lineno, exc)
                    continue
                event = normalize_cowrie_event(raw)
                if event:
                    yield event

    def collect(self) -> Generator[CanonicalEvent, None, None]:
        """Collect from all Cowrie log files in log_dir."""
        for log_file in self._log_files():
            yield from self.collect_from_file(log_file)

    def collect_from_string(self, jsonlines: str) -> List[CanonicalEvent]:
        """Parse a string of JSON-lines (for testing / in-memory use)."""
        events = []
        for line in jsonlines.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = normalize_cowrie_event(raw)
            if event:
                events.append(event)
        return events
