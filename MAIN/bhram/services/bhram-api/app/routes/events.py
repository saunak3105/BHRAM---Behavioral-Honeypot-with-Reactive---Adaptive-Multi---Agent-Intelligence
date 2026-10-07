"""
BHRAM API — Events Routes (Part 2)
=====================================

GET  /api/v1/events              — list all normalized events (paginated, filtered)
GET  /api/v1/events/{event_id}   — single event with full normalized_data

Filters:
  source_ip, session_id, event_type, source, severity,
  start_time, end_time, host, service, analyzed

All raw_data and normalized_data columns are exposed for AI/ML consumption.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Event
from app.schemas import EventDetailSchema, EventListResponse, EventSchema

router = APIRouter(prefix="/api/v1", tags=["Events"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event_to_schema(e: Event) -> EventSchema:
    return EventSchema(
        id=e.id,
        session_id=e.session_id,
        event_time=e.event_time,
        source=e.source,
        category=e.category.value if hasattr(e.category, "value") else str(e.category),
        severity=e.severity.value if hasattr(e.severity, "value") else str(e.severity),
        event_type=e.event_type,
        source_ip=str(e.source_ip) if e.source_ip else None,
        analyzed=e.analyzed,
        created_at=e.created_at,
    )


def _event_to_detail_schema(e: Event) -> EventDetailSchema:
    return EventDetailSchema(
        id=e.id,
        session_id=e.session_id,
        event_time=e.event_time,
        source=e.source,
        category=e.category.value if hasattr(e.category, "value") else str(e.category),
        severity=e.severity.value if hasattr(e.severity, "value") else str(e.severity),
        event_type=e.event_type,
        source_ip=str(e.source_ip) if e.source_ip else None,
        analyzed=e.analyzed,
        analysis_result=e.analysis_result,
        normalized_data=e.normalized_data or {},
        raw_data=e.raw_data or {},
        created_at=e.created_at,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get(
    "/events",
    response_model=EventListResponse,
    summary="List telemetry events",
    description=(
        "Returns normalized telemetry events from all honeypot surfaces. "
        "Supports rich filtering by source IP, session, event type, severity, time range, "
        "destination host, and service. "
        "Results are ordered newest-first. Default limit is 100."
    ),
)
async def list_events(
    # Filters
    source_ip:    Optional[str]      = Query(None, description="Filter by attacker source IP"),
    session_id:   Optional[str]      = Query(None, description="Filter by attack session UUID"),
    event_type:   Optional[str]      = Query(None, description="Filter by event type (e.g. 'command', 'authentication')"),
    source:       Optional[str]      = Query(None, description="Filter by source component: cowrie | web | fileserver | network"),
    severity:     Optional[str]      = Query(None, description="Filter by severity: info | low | medium | high | critical"),
    host:         Optional[str]      = Query(None, description="Filter by destination host (from normalized_data->destination_host)"),
    service:      Optional[str]      = Query(None, description="Filter by service (from normalized_data->target->service)"),
    analyzed:     Optional[bool]     = Query(None, description="Filter by analyzed flag"),
    start_time:   Optional[datetime] = Query(None, description="Filter events after this ISO-8601 timestamp"),
    end_time:     Optional[datetime] = Query(None, description="Filter events before this ISO-8601 timestamp"),
    # Pagination
    limit:  int = Query(100, ge=1, le=1000, description="Max events to return"),
    offset: int = Query(0,   ge=0,          description="Pagination offset"),
    db: AsyncSession = Depends(get_db),
) -> EventListResponse:

    query = select(Event).order_by(Event.event_time.desc())
    filters = []

    if source_ip:
        filters.append(Event.source_ip == source_ip)
    if session_id:
        try:
            sid_uuid = uuid.UUID(session_id)
            filters.append(Event.session_id == sid_uuid)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid session_id UUID: {session_id}",
            )
    if event_type:
        filters.append(Event.event_type == event_type)
    if source:
        filters.append(Event.source == source)
    if severity:
        filters.append(Event.severity == severity)
    if analyzed is not None:
        filters.append(Event.analyzed == analyzed)
    if start_time:
        filters.append(Event.event_time >= start_time)
    if end_time:
        filters.append(Event.event_time <= end_time)
    # host / service require querying JSONB normalized_data
    if host:
        filters.append(Event.normalized_data["destination_host"].astext == host)
    if service:
        filters.append(Event.normalized_data["target"]["service"].astext == service)

    if filters:
        query = query.where(and_(*filters))

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    return EventListResponse(
        total=len(events),
        events=[_event_to_schema(e) for e in events],
    )


@router.get(
    "/events/{event_id}",
    response_model=EventDetailSchema,
    summary="Get a single event with full detail",
    description=(
        "Returns one normalized event including its complete `normalized_data` "
        "and `raw_data` JSONB fields. "
        "Intended for AI/ML agents that need the full canonical event for analysis."
    ),
)
async def get_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> EventDetailSchema:
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found.",
        )
    return _event_to_detail_schema(event)
