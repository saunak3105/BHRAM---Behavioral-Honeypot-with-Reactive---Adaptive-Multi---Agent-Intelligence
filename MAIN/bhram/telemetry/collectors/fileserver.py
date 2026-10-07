"""
BHRAM Telemetry — File Collector
===================================

Normalizes file system events (access, create, modify, delete) from the
BHRAM deception file server into canonical BHRAM events.

Usage:
    from bhram.telemetry.collectors.fileserver import FileCollector

    collector = FileCollector()
    event = collector.from_access_dict({
        "filename": "salary_structure.csv",
        "filepath": "/home/finance/salary_structure.csv",
        "operation": "access",
        "session_id": "abc123",
        "source_ip": "10.10.10.50",
        "username": "finance",
    })
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from bhram.telemetry.schemas import (
    ActorInfo,
    CanonicalEvent,
    EventDetail,
    EventSource,
    TargetInfo,
)

logger = logging.getLogger("bhram.telemetry.fileserver")

FileOperation = Literal["access", "create", "modify", "delete", "list"]

_OP_TO_EVENT_TYPE = {
    "access": "file_access",
    "create": "file_create",
    "modify": "file_modify",
    "delete": "file_delete",
    "list":   "file_access",
}

_BAIT_LEVEL_SEVERITY = {
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


class FileCollector:
    """Normalize file server events into canonical BHRAM events."""

    SOURCE = EventSource(component="fileserver", version="1.0.0", host="bhram_fileserver")

    @classmethod
    def from_access_dict(cls, data: Dict[str, Any]) -> CanonicalEvent:
        """
        Normalize a file operation event dict.

        Expected keys:
          filename, filepath, operation, session_id, source_ip,
          username, bait_level, timestamp, content_type, size_bytes
        """
        operation = data.get("operation", "access")
        event_type = _OP_TO_EVENT_TYPE.get(operation, "file_access")
        bait_level = int(data.get("bait_level", 1))
        severity = _BAIT_LEVEL_SEVERITY.get(bait_level, "medium")

        # Higher severity for mutating operations
        if operation in ("modify", "delete") and bait_level >= 3:
            severity = "critical"
        elif operation in ("modify", "delete"):
            severity = "high"

        ts_raw = data.get("timestamp")
        ts = (
            datetime.fromisoformat(ts_raw).astimezone(timezone.utc)
            if ts_raw else datetime.now(timezone.utc)
        )

        filename = data.get("filename", "")
        filepath = data.get("filepath", "")
        action = f"{operation}:{filename}"

        return CanonicalEvent(
            timestamp=ts,
            session_id=data.get("session_id"),
            source_ip=data.get("source_ip"),
            destination_host="bhram_fileserver",
            destination_port=8081,
            source=cls.SOURCE,
            event=EventDetail(
                type=event_type,
                category="file_access",
                action=action,
                outcome="success",
            ),
            actor=ActorInfo(
                username=data.get("username"),
                session_id=data.get("session_id"),
            ),
            target=TargetInfo(
                host="bhram_fileserver",
                port=8081,
                service="fileserver",
                path=filepath,
                filename=filename,
            ),
            severity=severity,
            raw_data=data,
            metadata={
                "operation": operation,
                "bait_level": bait_level,
                "content_type": data.get("content_type", ""),
                "size_bytes": data.get("size_bytes", 0),
            },
        )

    @classmethod
    def from_orchestrator_event(cls, data: Dict[str, Any]) -> CanonicalEvent:
        """
        Normalize an orchestrator-driven file change event (create/modify/delete
        performed by the BHRAM orchestrator rather than an attacker).
        """
        operation = data.get("operation", "create")
        event_type = _OP_TO_EVENT_TYPE.get(operation, "file_create")

        return CanonicalEvent(
            session_id=None,
            source_ip=None,
            destination_host="bhram_fileserver",
            destination_port=8081,
            source=EventSource(component="orchestrator", version="1.0.0", host="bhram_api"),
            event=EventDetail(
                type=event_type,
                category="file_access",
                action=f"orchestrator:{operation}:{data.get('filename', '')}",
                outcome="success",
            ),
            actor=ActorInfo(username="orchestrator"),
            target=TargetInfo(
                host="bhram_fileserver",
                service="fileserver",
                path=data.get("filepath", ""),
                filename=data.get("filename", ""),
            ),
            severity="info",
            raw_data=data,
            metadata={"triggered_by": "orchestrator", "operation": operation},
        )
