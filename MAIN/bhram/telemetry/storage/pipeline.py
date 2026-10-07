"""
BHRAM Telemetry — Storage Pipeline
=====================================

Persists canonical events and raw evidence to:
  1. PostgreSQL (via SQLAlchemy async) — normalized + raw_data columns
  2. Forensic flat-file storage — raw JSON-lines, never modified

FORENSIC PRINCIPLE:
  Raw evidence is NEVER destroyed or modified.
  The raw_data field in PostgreSQL mirrors the original event.
  Flat files provide an additional immutable forensic layer.

Storage layout:
  data/raw/        — raw JSON-lines files (one per day per source)
  data/normalized/ — normalized event JSON-lines for analysis/replay
  data/pcap/       — pcap files (populated externally by tcpdump/Zeek)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bhram.telemetry.schemas import CanonicalEvent

logger = logging.getLogger("bhram.telemetry.storage")


# ── Forensic flat-file writer ─────────────────────────────────────────────────

class ForensicStorage:
    """
    Writes raw and normalized events to append-only JSON-lines flat files.

    Files are organized as:
      {base_dir}/raw/{YYYY}/{MM}/{DD}/{source}.jsonl
      {base_dir}/normalized/{YYYY}/{MM}/{DD}/events.jsonl

    NEVER deletes or modifies existing files.
    """

    def __init__(self, base_dir: str = "data"):
        self.base_dir = Path(base_dir)
        self._ensure_dirs()

    def _ensure_dirs(self):
        (self.base_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.base_dir / "normalized").mkdir(parents=True, exist_ok=True)
        (self.base_dir / "pcap").mkdir(parents=True, exist_ok=True)

    def _raw_path(self, event: CanonicalEvent) -> Path:
        ts = event.timestamp
        source = event.source.component.replace("/", "_")
        folder = self.base_dir / "raw" / f"{ts.year:04d}" / f"{ts.month:02d}" / f"{ts.day:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"{source}.jsonl"

    def _normalized_path(self, event: CanonicalEvent) -> Path:
        ts = event.timestamp
        folder = self.base_dir / "normalized" / f"{ts.year:04d}" / f"{ts.month:02d}" / f"{ts.day:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        return folder / "events.jsonl"

    def write_raw(self, event: CanonicalEvent) -> None:
        """Append raw_data to the forensic raw log file."""
        path = self._raw_path(event)
        try:
            raw_record = {
                "_bhram_event_id": str(event.event_id),
                "_bhram_source": event.source.component,
                "_bhram_collected_at": datetime.now(timezone.utc).isoformat(),
                **event.raw_data,
            }
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(raw_record, default=str) + "\n")
        except Exception as exc:
            logger.error("ForensicStorage.write_raw failed: %s", exc)

    def write_normalized(self, event: CanonicalEvent) -> None:
        """Append normalized event to the forensic normalized log file."""
        path = self._normalized_path(event)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_normalized_dict(), default=str) + "\n")
        except Exception as exc:
            logger.error("ForensicStorage.write_normalized failed: %s", exc)

    def write(self, event: CanonicalEvent) -> None:
        """Write both raw and normalized records."""
        self.write_raw(event)
        self.write_normalized(event)


# ── Async PostgreSQL storage (used inside FastAPI/API context) ────────────────

class AsyncEventStorage:
    """
    Persists CanonicalEvents to PostgreSQL using the existing SQLAlchemy
    async session from app.database.

    This is injected into the API pipeline — it does NOT create its own
    engine or session, it accepts a session from a FastAPI dependency.
    """

    @staticmethod
    async def upsert_session(
        db,
        event: CanonicalEvent,
    ) -> Optional[str]:
        """
        Find or create an AttackSession for this event.
        Returns the internal PostgreSQL UUID string of the session record.
        """
        from sqlalchemy import select
        from app.models import AttackSession

        if not event.source_ip:
            return None

        session_id_str = event.session_id or f"ip:{event.source_ip}"

        # Try to find existing session
        result = await db.execute(
            select(AttackSession).where(AttackSession.session_id == session_id_str)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update last seen via metadata
            existing.metadata_["last_seen"] = event.timestamp.isoformat()
            existing.metadata_["event_count"] = existing.metadata_.get("event_count", 0) + 1
            await db.flush()
            return str(existing.id)

        # Create new session
        new_session = AttackSession(
            session_id=session_id_str,
            source_ip=event.source_ip,
            source_port=event.source_port,
            destination_ip=event.destination_host if event.destination_host and "." in str(event.destination_host) else None,
            destination_port=event.destination_port,
            protocol=event.source.component if event.source.component in ("ssh", "cowrie") else "http",
            start_time=event.timestamp,
            is_active=True,
            metadata_={
                "source_component": event.source.component,
                "event_count": 1,
                "last_seen": event.timestamp.isoformat(),
            },
        )
        db.add(new_session)
        await db.flush()
        return str(new_session.id)

    @staticmethod
    async def save_event(
        db,
        event: CanonicalEvent,
        session_uuid: Optional[str] = None,
    ) -> str:
        """
        Save a CanonicalEvent to the PostgreSQL events table.
        Returns the new event UUID string.
        """
        import uuid as _uuid
        from app.models import Event, EventCategory, EventSeverity

        # Map category/severity to enum values
        def _safe_category(cat: str) -> EventCategory:
            try:
                return EventCategory(cat)
            except ValueError:
                return EventCategory.system

        def _safe_severity(sev: str) -> EventSeverity:
            try:
                return EventSeverity(sev)
            except ValueError:
                return EventSeverity.info

        db_event = Event(
            session_id=_uuid.UUID(session_uuid) if session_uuid else None,
            event_time=event.timestamp,
            source=event.source.component,
            category=_safe_category(event.event.category),
            severity=_safe_severity(event.severity),
            event_type=event.event.type,
            source_ip=event.source_ip,
            raw_data=event.raw_data,
            normalized_data=event.to_normalized_dict(),
            analyzed=False,
        )
        db.add(db_event)
        await db.flush()
        return str(db_event.id)
