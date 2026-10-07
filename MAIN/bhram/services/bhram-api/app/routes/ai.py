"""
BHRAM API — AI/ML Interface Routes (Part 2)
=============================================

These endpoints form the strict AI/ML API contract for the BHRAM system.

GET  /api/v1/ai/events                — unanalyzed events batch for AI processing
POST /api/v1/ai/profile               — submit an attacker profile for a session
POST /api/v1/ai/decision              — submit a deception decision

SECURITY:
  - POST /ai/decision validates action against AI_ACTION_ALLOWLIST only.
  - Arbitrary shell commands are NEVER accepted.
  - Decisions are RECORDED but NOT EXECUTED in Part 2 (execution is Part 3).
  - Input is fully validated via Pydantic schemas.

AI/ML API CONTRACT:
  The AI agent reads events, builds a profile, then submits a decision.
  BHRAM records both the profile and the decision in the database.
  In Part 3, BHRAM will read these decisions and execute approved actions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AttackSession, AttackerProfile, DeceptionAction, Event
from app.schemas import (
    AI_ACTION_ALLOWLIST,
    AIDecisionRequest,
    AIDecisionSchema,
    AttackerProfileSchema,
    EventDetailSchema,
)

router = APIRouter(prefix="/api/v1/ai", tags=["AI/ML Interface"])


# ── Helpers ───────────────────────────────────────────────────────────────────

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


# ── GET /ai/events — unanalyzed event batch ───────────────────────────────────

@router.get(
    "/events",
    response_model=List[EventDetailSchema],
    summary="Fetch unanalyzed events for AI processing",
    description=(
        "Returns a batch of unanalyzed events for the AI/ML agent to process. "
        "Each event includes full `normalized_data` (canonical BHRAM format) "
        "and `raw_data` (original source format). "
        "After processing, the AI agent should mark events as analyzed via "
        "POST /ai/profile or the events PATCH endpoint (Part 3). "
        "Filter by `session_id` to process one session at a time. "
        "Default batch size: 50."
    ),
)
async def get_ai_events(
    session_id:  Optional[str]  = Query(None, description="Filter by attack session UUID"),
    event_type:  Optional[str]  = Query(None, description="Filter by event type"),
    severity:    Optional[str]  = Query(None, description="Filter by minimum severity"),
    limit:       int            = Query(50, ge=1, le=500, description="Batch size"),
    db: AsyncSession = Depends(get_db),
) -> List[EventDetailSchema]:

    query = (
        select(Event)
        .where(Event.analyzed == False)  # noqa: E712
        .order_by(Event.event_time.asc())   # oldest-first for sequential AI processing
    )

    if session_id:
        try:
            sid_uuid = uuid.UUID(session_id)
            query = query.where(Event.session_id == sid_uuid)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid session_id UUID: {session_id}",
            )
    if event_type:
        query = query.where(Event.event_type == event_type)
    if severity:
        query = query.where(Event.severity == severity)

    query = query.limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    return [_event_to_detail_schema(e) for e in events]


# ── POST /ai/profile — submit attacker profile ────────────────────────────────

@router.post(
    "/profile",
    response_model=AttackerProfileSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Submit AI-generated attacker profile",
    description=(
        "The AI/ML agent submits a behavioral profile for an attack session. "
        "BHRAM stores the profile and links it to the AttackerProfile record "
        "for this source IP. "
        "If a profile already exists for this session's source IP, it is updated. "
        "The profile schema is strict — invalid suspicion_score ranges are rejected."
    ),
)
async def submit_attacker_profile(
    payload: AttackerProfileSchema,
    db: AsyncSession = Depends(get_db),
) -> AttackerProfileSchema:

    # Validate session exists
    try:
        session_uuid = uuid.UUID(payload.session_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid session_id UUID: {payload.session_id}",
        )

    sess_result = await db.execute(
        select(AttackSession).where(AttackSession.id == session_uuid)
    )
    session = sess_result.scalar_one_or_none()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack session {payload.session_id} not found.",
        )

    source_ip_str = str(session.source_ip)

    # Find or create AttackerProfile for this source IP
    profile_result = await db.execute(
        select(AttackerProfile).where(AttackerProfile.source_ip == source_ip_str)
    )
    profile = profile_result.scalar_one_or_none()

    profile_data = {
        "skill_level":       payload.skill_level,
        "observed_ttps":     payload.observed_ttps,
        "suspected_intent":  payload.suspected_intent,
        "behavior_summary":  payload.behavior_summary,
        "suspicion_score":   payload.suspicion_score,
        **payload.metadata,
    }

    if profile:
        # Update existing profile
        profile.last_seen     = datetime.now(timezone.utc)
        profile.session_count = (profile.session_count or 0) + 1
        profile.skill_level   = payload.skill_level
        profile.likely_intent = payload.suspected_intent
        profile.threat_score  = payload.suspicion_score * 10  # normalize to 0–10
        profile.ttps          = payload.observed_ttps
        profile.profile_data  = profile_data
    else:
        profile = AttackerProfile(
            source_ip     = source_ip_str,
            session_count = 1,
            skill_level   = payload.skill_level,
            likely_intent = payload.suspected_intent,
            threat_score  = payload.suspicion_score * 10,
            ttps          = payload.observed_ttps,
            profile_data  = profile_data,
        )
        db.add(profile)

    # Link session to profile
    await db.flush()
    session.attacker_profile_id = profile.id
    session.intent = payload.suspected_intent
    session.threat_score = payload.suspicion_score * 10

    await db.flush()

    return payload


# ── POST /ai/decision — submit deception decision ─────────────────────────────

@router.post(
    "/decision",
    response_model=AIDecisionSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Submit AI deception decision",
    description=(
        "The AI/ML agent submits a deception decision for BHRAM to record. "
        "**SECURITY**: `action` must be one of the allowlisted action names. "
        "Any action not in the allowlist is rejected with HTTP 422. "
        "Decisions are RECORDED but NOT EXECUTED in Part 2 — execution is Part 3. "
        "No arbitrary shell commands, file paths, or system calls are accepted."
    ),
)
async def submit_decision(
    payload: AIDecisionRequest,
    db: AsyncSession = Depends(get_db),
) -> AIDecisionSchema:

    # ── SECURITY: strict action allowlist validation ───────────────────────────
    if payload.action not in AI_ACTION_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Action '{payload.action}' is not in the BHRAM allowlist. "
                f"Valid actions: {', '.join(AI_ACTION_ALLOWLIST)}"
            ),
        )

    # Validate session exists
    try:
        session_uuid = uuid.UUID(payload.session_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid session_id UUID: {payload.session_id}",
        )

    sess_result = await db.execute(
        select(AttackSession).where(AttackSession.id == session_uuid)
    )
    session = sess_result.scalar_one_or_none()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack session {payload.session_id} not found.",
        )

    # Record the decision in deception_actions table
    decision_id = uuid.uuid4()
    action_record = DeceptionAction(
        id          = decision_id,
        action_type = payload.action,
        trigger_session = session_uuid,
        parameters  = {
            "confidence":  payload.confidence,
            "reason":      payload.reason,
            "ai_params":   payload.parameters,
            "submitted_by": "ai_agent",
        },
        result  = None,     # Not executed yet — Part 3
        success = None,     # Not executed yet — Part 3
        applied_by = "ai_agent",
        notes = f"Part 2 AI decision — queued for Part 3 execution. Action: {payload.action}",
    )
    db.add(action_record)
    await db.flush()

    return AIDecisionSchema(
        decision_id  = decision_id,
        session_id   = payload.session_id,
        action       = payload.action,
        confidence   = payload.confidence,
        reason       = payload.reason,
        parameters   = payload.parameters,
        recorded_at  = datetime.now(timezone.utc),
        status       = "recorded",
    )
