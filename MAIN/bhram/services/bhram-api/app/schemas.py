"""
BHRAM API — Pydantic Schemas (Request/Response models)
These schemas form the clean API contract for the AI/ML team.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


# ─── Base ─────────────────────────────────────────────────────────────────────

class BHRAMBaseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ─── Health ───────────────────────────────────────────────────────────────────

class ServiceHealth(BHRAMBaseModel):
    name:    str
    status:  str
    latency_ms: Optional[float] = None


class HealthResponse(BHRAMBaseModel):
    status:    str = Field(..., examples=["healthy"])
    version:   str
    timestamp: datetime
    services:  List[ServiceHealth] = []


# ─── Users ────────────────────────────────────────────────────────────────────

class UserSchema(BHRAMBaseModel):
    id:         uuid.UUID
    username:   str
    full_name:  str
    email:      str
    department: str
    role:       str
    is_decoy:   bool
    ssh_enabled: bool
    home_dir:   Optional[str] = None
    created_at: datetime


class UserListResponse(BHRAMBaseModel):
    total:  int
    users:  List[UserSchema]


# ─── Services ─────────────────────────────────────────────────────────────────

class ServiceSchema(BHRAMBaseModel):
    id:          uuid.UUID
    name:        str
    description: Optional[str] = None
    status:      str
    host:        str
    port:        Optional[int] = None
    protocol:    Optional[str] = None
    is_honeypot: bool
    is_decoy:    bool
    network:     Optional[str] = None
    docker_name: Optional[str] = None
    created_at:  datetime


class ServiceListResponse(BHRAMBaseModel):
    total:    int
    services: List[ServiceSchema]


# ─── Decoy Files ──────────────────────────────────────────────────────────────

class DecoyFileSchema(BHRAMBaseModel):
    id:            uuid.UUID
    filename:      str
    filepath:      str
    content_type:  Optional[str] = None
    size_bytes:    int
    is_active:     bool
    bait_level:    int = Field(..., ge=1, le=5)
    access_count:  int
    last_accessed: Optional[datetime] = None
    created_at:    datetime


class FileListResponse(BHRAMBaseModel):
    total:  int
    files:  List[DecoyFileSchema]


# ─── Environment State ────────────────────────────────────────────────────────

class NetworkInfo(BHRAMBaseModel):
    frontend_subnet: str
    backend_subnet:  str
    internal_subnet: str


class EnvironmentStateSchema(BHRAMBaseModel):
    """
    Central environment state model.
    This is the primary interface for AI/ML agents to read the current
    deception environment configuration.
    """
    id:              uuid.UUID
    snapshot_time:   datetime
    deception_mode:  str
    is_current:      bool
    company:         str = "BHRAM Technologies"
    services:        List[Dict[str, Any]] = []
    users:           List[str] = []
    active_decoys:   int = 0
    network:         Optional[Dict[str, Any]] = None
    applied_by:      Optional[str] = None
    notes:           Optional[str] = None

    @classmethod
    def from_orm_state(cls, orm_obj: Any) -> "EnvironmentStateSchema":
        """Build from ORM EnvironmentState — extracts fields from JSONB 'state'."""
        state = orm_obj.state or {}
        return cls(
            id=orm_obj.id,
            snapshot_time=orm_obj.snapshot_time,
            deception_mode=orm_obj.deception_mode.value if hasattr(orm_obj.deception_mode, "value") else str(orm_obj.deception_mode),
            is_current=orm_obj.is_current,
            company=state.get("company", "BHRAM Technologies"),
            services=state.get("services", []),
            users=state.get("users", []),
            active_decoys=state.get("active_decoys", 0),
            network=state.get("network"),
            applied_by=orm_obj.applied_by,
            notes=orm_obj.notes,
        )


# ─── Attack Sessions ──────────────────────────────────────────────────────────

class AttackSessionSchema(BHRAMBaseModel):
    id:               uuid.UUID
    session_id:       str
    source_ip:        str
    source_port:      Optional[int] = None
    protocol:         str
    start_time:       datetime
    end_time:         Optional[datetime] = None
    duration_secs:    Optional[float] = None
    is_active:        bool
    threat_score:     Optional[float] = None
    intent:           Optional[str] = None


class SessionListResponse(BHRAMBaseModel):
    total:    int
    sessions: List[AttackSessionSchema]


# ─── Events ───────────────────────────────────────────────────────────────────

class EventSchema(BHRAMBaseModel):
    id:          uuid.UUID
    session_id:  Optional[uuid.UUID] = None
    event_time:  datetime
    source:      str
    category:    str
    severity:    str
    event_type:  str
    source_ip:   Optional[str] = None
    analyzed:    bool
    created_at:  datetime


class EventListResponse(BHRAMBaseModel):
    total:  int
    events: List[EventSchema]


# ─── Generic Response ─────────────────────────────────────────────────────────

class MessageResponse(BHRAMBaseModel):
    message: str
    success: bool = True


class ErrorResponse(BHRAMBaseModel):
    error:   str
    detail:  Optional[str] = None
    success: bool = False


# ─── Part 2: Detailed Event Schema ───────────────────────────────────────────

class EventDetailSchema(BHRAMBaseModel):
    """Full event with normalized_data for AI/ML consumption."""
    id:               uuid.UUID
    session_id:       Optional[uuid.UUID] = None
    event_time:       datetime
    source:           str
    category:         str
    severity:         str
    event_type:       str
    source_ip:        Optional[str] = None
    analyzed:         bool
    analysis_result:  Optional[Dict[str, Any]] = None
    normalized_data:  Dict[str, Any] = Field(default_factory=dict)
    raw_data:         Dict[str, Any] = Field(default_factory=dict)
    created_at:       datetime


# ─── Part 2: Session Timeline ─────────────────────────────────────────────────

class SessionTimelineEntry(BHRAMBaseModel):
    """A single event entry in a session timeline."""
    event_id:    uuid.UUID
    event_time:  datetime
    event_type:  str
    category:    str
    severity:    str
    source:      str
    action:      Optional[str] = None
    outcome:     Optional[str] = None
    ttps:        List[str] = []


class SessionTimeline(BHRAMBaseModel):
    """Full session timeline — ordered sequence of all events in a session."""
    session_id:   str
    source_ip:    str
    start_time:   datetime
    last_seen:    Optional[datetime] = None
    event_count:  int
    duration_secs: Optional[float] = None
    is_active:    bool
    timeline:     List[SessionTimelineEntry]
    hosts_touched:    List[str] = []
    services_touched: List[str] = []
    ttps_observed:    List[str] = []


# ─── Part 2: Telemetry Stats ──────────────────────────────────────────────────

class TelemetryStats(BHRAMBaseModel):
    """Aggregated telemetry statistics for dashboards and AI agents."""
    total_events:        int
    total_sessions:      int
    active_sessions:     int
    unanalyzed_events:   int
    events_by_type:      Dict[str, int] = Field(default_factory=dict)
    events_by_severity:  Dict[str, int] = Field(default_factory=dict)
    events_by_source:    Dict[str, int] = Field(default_factory=dict)
    top_source_ips:      List[Dict[str, Any]] = Field(default_factory=list)
    generated_at:        datetime


# ─── Part 2: AI/ML Interface Schemas ─────────────────────────────────────────
#
# STRICT ALLOWLIST: Only these action names are accepted by POST /ai/decision.
# Do NOT add arbitrary actions here without security review.
# Actual execution of these actions is NOT implemented until Part 3.

AI_ACTION_ALLOWLIST: List[str] = [
    "none",
    "create_decoy_file",
    "remove_decoy_file",
    "modify_decoy_file",
    "create_decoy_user",
    "disable_decoy_user",
    "enable_service",
    "disable_service",
    "change_banner",
    "change_web_content",
    "redirect_decoy_path",
    "reconstruct_environment",
]


class AttackerProfileSchema(BHRAMBaseModel):
    """
    AI/ML-generated attacker profile.
    Submitted by the AI agent via POST /api/v1/ai/profile.
    Used to annotate attack sessions with behavioral intelligence.
    """
    session_id:        str = Field(..., description="UUID of the attack session")
    skill_level:       str = Field(
        "unknown",
        description="Estimated skill level: script_kiddie | opportunist | skilled | advanced | nation_state | unknown",
    )
    observed_ttps:     List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK TTP identifiers observed in this session",
    )
    suspected_intent:  str = Field(
        "unknown",
        description="Inferred attacker intent: reconnaissance | credential_theft | lateral_movement | data_exfiltration | ransomware | unknown",
    )
    behavior_summary:  str = Field(
        "",
        description="Free-text summary of observed attacker behavior",
    )
    suspicion_score:   float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Normalized suspicion score 0.0 (none) – 1.0 (maximum)",
    )
    metadata:          Dict[str, Any] = Field(default_factory=dict)


class AIDecisionRequest(BHRAMBaseModel):
    """
    AI/ML decision submission.
    Submitted by the AI agent via POST /api/v1/ai/decision.

    SECURITY: `action` is validated against AI_ACTION_ALLOWLIST.
    Arbitrary shell commands or actions not in the allowlist are rejected.
    """
    session_id:   str = Field(..., description="UUID of the attack session triggering the decision")
    action:       str = Field(
        ...,
        description=f"Action to take. Must be one of: {', '.join(AI_ACTION_ALLOWLIST)}",
    )
    confidence:   float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="AI confidence in this decision, 0.0 to 1.0",
    )
    reason:       str = Field(
        "",
        description="Human-readable explanation of why this action was chosen",
    )
    parameters:   Dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters. Contents are action-dependent.",
    )


class AIDecisionSchema(BHRAMBaseModel):
    """AI decision response — confirmation of the recorded decision."""
    decision_id:  uuid.UUID
    session_id:   str
    action:       str
    confidence:   float
    reason:       str
    parameters:   Dict[str, Any] = Field(default_factory=dict)
    recorded_at:  datetime
    status:       str = "recorded"   # always 'recorded' in Part 2 — execution is Part 3
