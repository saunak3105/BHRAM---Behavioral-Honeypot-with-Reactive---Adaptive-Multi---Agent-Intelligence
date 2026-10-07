"""
BHRAM API — Sessions Routes (Part 2)
======================================

GET  /api/v1/sessions                          — list attack sessions
GET  /api/v1/sessions/{session_id}             — single session detail
GET  /api/v1/sessions/{session_id}/timeline    — ordered event timeline for a session

Filters on list:
  source_ip, is_active, start_time, end_time, limit, offset
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AttackSession, Event
from app.schemas import (
    AttackSessionSchema,
    SessionListResponse,
    SessionTimeline,
    SessionTimelineEntry,
)

router = APIRouter(prefix="/api/v1", tags=["Sessions"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _session_to_schema(s: AttackSession) -> AttackSessionSchema:
    return AttackSessionSchema(
        id=s.id,
        session_id=s.session_id,
        source_ip=str(s.source_ip),
        source_port=s.source_port,
        protocol=s.protocol,
        start_time=s.start_time,
        end_time=s.end_time,
        duration_secs=float(s.duration_secs) if s.duration_secs is not None else None,
        is_active=s.is_active,
        threat_score=float(s.threat_score) if s.threat_score is not None else None,
        intent=s.intent,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List attack sessions",
    description=(
        "Returns all attack sessions. Sessions group related events from the same attacker "
        "(same source IP + session identifier). "
        "Ordered most-recent-start first."
    ),
)
async def list_sessions(
    source_ip:  Optional[str]      = Query(None, description="Filter by attacker source IP"),
    is_active:  Optional[bool]     = Query(None, description="Filter active (ongoing) sessions only"),
    start_time: Optional[datetime] = Query(None, description="Sessions started after this timestamp"),
    end_time:   Optional[datetime] = Query(None, description="Sessions started before this timestamp"),
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0,  ge=0),
    db: AsyncSession = Depends(get_db),
) -> SessionListResponse:
    query = select(AttackSession).order_by(AttackSession.start_time.desc())
    filters = []

    if source_ip:
        filters.append(AttackSession.source_ip == source_ip)
    if is_active is not None:
        filters.append(AttackSession.is_active == is_active)
    if start_time:
        filters.append(AttackSession.start_time >= start_time)
    if end_time:
        filters.append(AttackSession.start_time <= end_time)

    if filters:
        query = query.where(and_(*filters))

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    sessions = result.scalars().all()

    return SessionListResponse(
        total=len(sessions),
        sessions=[_session_to_schema(s) for s in sessions],
    )


@router.get(
    "/sessions/{session_id}",
    response_model=AttackSessionSchema,
    summary="Get session detail",
    description="Returns full detail for a single attack session by its UUID.",
)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AttackSessionSchema:
    result = await db.execute(
        select(AttackSession).where(AttackSession.id == session_id)
    )
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found.",
        )
    return _session_to_schema(s)


@router.get(
    "/sessions/{session_id}/timeline",
    response_model=SessionTimeline,
    summary="Get session event timeline",
    description=(
        "Returns the complete ordered event timeline for a session. "
        "Each entry includes event type, severity, extracted action, outcome, and MITRE TTPs. "
        "This is the primary interface for AI/ML agents to reconstruct attacker behavior."
    ),
)
async def get_session_timeline(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> SessionTimeline:
    # Fetch session
    sess_result = await db.execute(
        select(AttackSession).where(AttackSession.id == session_id)
    )
    s = sess_result.scalar_one_or_none()
    if not s:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found.",
        )

    # Fetch all events for this session, ordered by time
    evt_result = await db.execute(
        select(Event)
        .where(Event.session_id == session_id)
        .order_by(Event.event_time.asc())
    )
    events = evt_result.scalars().all()

    # Build timeline entries from normalized_data
    timeline_entries: List[SessionTimelineEntry] = []
    hosts_touched: set = set()
    services_touched: set = set()
    ttps_observed: set = set()

    for e in events:
        nd = e.normalized_data or {}

        # Extract action/outcome/ttps from normalized_data
        event_detail = nd.get("event", {})
        target = nd.get("target", {})
        metadata = nd.get("metadata", {})

        action  = event_detail.get("action")
        outcome = event_detail.get("outcome")
        ttps    = metadata.get("ttps", [])

        if nd.get("destination_host"):
            hosts_touched.add(nd["destination_host"])
        if target.get("host"):
            hosts_touched.add(target["host"])
        if target.get("service"):
            services_touched.add(target["service"])

        ttps_observed.update(ttps)

        timeline_entries.append(SessionTimelineEntry(
            event_id=e.id,
            event_time=e.event_time,
            event_type=e.event_type,
            category=e.category.value if hasattr(e.category, "value") else str(e.category),
            severity=e.severity.value if hasattr(e.severity, "value") else str(e.severity),
            source=e.source,
            action=action,
            outcome=outcome,
            ttps=ttps,
        ))

    # Determine last_seen from session metadata or last event time
    last_seen = None
    if s.metadata_ and "last_seen" in s.metadata_:
        try:
            last_seen = datetime.fromisoformat(s.metadata_["last_seen"])
        except (ValueError, TypeError):
            pass
    if not last_seen and events:
        last_seen = events[-1].event_time

    return SessionTimeline(
        session_id=s.session_id,
        source_ip=str(s.source_ip),
        start_time=s.start_time,
        last_seen=last_seen,
        event_count=len(events),
        duration_secs=float(s.duration_secs) if s.duration_secs is not None else None,
        is_active=s.is_active,
        timeline=timeline_entries,
        hosts_touched=sorted(hosts_touched),
        services_touched=sorted(services_touched),
        ttps_observed=sorted(ttps_observed),
    )
