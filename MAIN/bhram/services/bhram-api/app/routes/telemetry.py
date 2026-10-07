"""
BHRAM API — Telemetry Stats Routes (Part 2)
=============================================

GET  /api/v1/telemetry/stats  — aggregated telemetry statistics

Returns counts, breakdowns by type/severity/source, and top attacker IPs.
Used by dashboards and AI agents to understand the current telemetry volume.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AttackSession, Event
from app.schemas import TelemetryStats

router = APIRouter(prefix="/api/v1", tags=["Telemetry"])


@router.get(
    "/telemetry/stats",
    response_model=TelemetryStats,
    summary="Get telemetry pipeline statistics",
    description=(
        "Returns aggregated statistics across all telemetry events and sessions. "
        "Includes event counts by type, severity, and source component; "
        "top attacker source IPs; and session activity counts. "
        "Intended for dashboard display and AI/ML agent context awareness."
    ),
)
async def get_telemetry_stats(
    db: AsyncSession = Depends(get_db),
) -> TelemetryStats:

    # ── Total event count ──────────────────────────────────────────────────────
    total_result = await db.execute(select(func.count()).select_from(Event))
    total_events: int = total_result.scalar_one() or 0

    # ── Unanalyzed events ──────────────────────────────────────────────────────
    unanalyzed_result = await db.execute(
        select(func.count()).select_from(Event).where(Event.analyzed == False)  # noqa: E712
    )
    unanalyzed_events: int = unanalyzed_result.scalar_one() or 0

    # ── Total sessions ─────────────────────────────────────────────────────────
    total_sess_result = await db.execute(select(func.count()).select_from(AttackSession))
    total_sessions: int = total_sess_result.scalar_one() or 0

    active_sess_result = await db.execute(
        select(func.count()).select_from(AttackSession).where(AttackSession.is_active == True)  # noqa: E712
    )
    active_sessions: int = active_sess_result.scalar_one() or 0

    # ── Events by type ─────────────────────────────────────────────────────────
    type_result = await db.execute(
        select(Event.event_type, func.count().label("cnt"))
        .group_by(Event.event_type)
        .order_by(func.count().desc())
    )
    events_by_type: Dict[str, int] = {row.event_type: row.cnt for row in type_result}

    # ── Events by severity ─────────────────────────────────────────────────────
    sev_result = await db.execute(
        select(Event.severity, func.count().label("cnt"))
        .group_by(Event.severity)
        .order_by(func.count().desc())
    )
    events_by_severity: Dict[str, int] = {
        (row.severity.value if hasattr(row.severity, "value") else str(row.severity)): row.cnt
        for row in sev_result
    }

    # ── Events by source ───────────────────────────────────────────────────────
    src_result = await db.execute(
        select(Event.source, func.count().label("cnt"))
        .group_by(Event.source)
        .order_by(func.count().desc())
    )
    events_by_source: Dict[str, int] = {row.source: row.cnt for row in src_result}

    # ── Top source IPs ─────────────────────────────────────────────────────────
    top_ip_result = await db.execute(
        select(Event.source_ip, func.count().label("cnt"))
        .where(Event.source_ip != None)  # noqa: E711
        .group_by(Event.source_ip)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_source_ips = [
        {"source_ip": str(row.source_ip), "event_count": row.cnt}
        for row in top_ip_result
    ]

    return TelemetryStats(
        total_events=total_events,
        total_sessions=total_sessions,
        active_sessions=active_sessions,
        unanalyzed_events=unanalyzed_events,
        events_by_type=events_by_type,
        events_by_severity=events_by_severity,
        events_by_source=events_by_source,
        top_source_ips=top_source_ips,
        generated_at=datetime.now(timezone.utc),
    )
