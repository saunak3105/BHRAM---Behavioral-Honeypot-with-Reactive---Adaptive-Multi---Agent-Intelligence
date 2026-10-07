"""
BHRAM Telemetry — Canonical Event Schema
=========================================

Every raw event from every source (Cowrie, Web, Fileserver, Network) is
normalized into this single canonical schema before storage or AI/ML consumption.

EVENT TAXONOMY
--------------
authentication       — Login attempt, success, failure
command              — Shell command executed in honeypot
network_connection   — TCP/UDP connection observed
port_scan            — Port scan pattern detected
file_access          — File read/opened
file_create          — New file created
file_modify          — Existing file modified
file_delete          — File deleted/removed
service_interaction  — Generic service touched (non-auth, non-command)
web_request          — HTTP request received
credential_attempt   — Credential submission (web form, API)
session_start        — Attack session begun
session_end          — Attack session closed
honeypot_detection_attempt — Attacker probing for honeypot indicators
environment_change   — Deception environment state change recorded
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ── Event type taxonomy ───────────────────────────────────────────────────────

EVENT_TYPES = Literal[
    "authentication",
    "command",
    "network_connection",
    "port_scan",
    "file_access",
    "file_create",
    "file_modify",
    "file_delete",
    "service_interaction",
    "web_request",
    "credential_attempt",
    "session_start",
    "session_end",
    "honeypot_detection_attempt",
    "environment_change",
]

EVENT_CATEGORIES = Literal[
    "ssh",
    "http",
    "file_access",
    "auth",
    "network",
    "lateral_movement",
    "exfiltration",
    "deception_trigger",
    "system",
]

EVENT_SEVERITIES = Literal["info", "low", "medium", "high", "critical"]

# Map event_type -> default category
EVENT_TYPE_CATEGORY_MAP: Dict[str, str] = {
    "authentication":              "auth",
    "command":                     "ssh",
    "network_connection":          "network",
    "port_scan":                   "network",
    "file_access":                 "file_access",
    "file_create":                 "file_access",
    "file_modify":                 "file_access",
    "file_delete":                 "file_access",
    "service_interaction":         "system",
    "web_request":                 "http",
    "credential_attempt":          "auth",
    "session_start":               "ssh",
    "session_end":                 "ssh",
    "honeypot_detection_attempt":  "deception_trigger",
    "environment_change":          "system",
}

# Map event_type -> default severity
EVENT_TYPE_SEVERITY_MAP: Dict[str, str] = {
    "authentication":              "medium",
    "command":                     "high",
    "network_connection":          "low",
    "port_scan":                   "medium",
    "file_access":                 "medium",
    "file_create":                 "medium",
    "file_modify":                 "high",
    "file_delete":                 "high",
    "service_interaction":         "low",
    "web_request":                 "low",
    "credential_attempt":          "high",
    "session_start":               "info",
    "session_end":                 "info",
    "honeypot_detection_attempt":  "critical",
    "environment_change":          "info",
}


# ── Sub-schemas ───────────────────────────────────────────────────────────────

class EventSource(BaseModel):
    """Which BHRAM component produced this event."""
    component: str = Field(..., description="'cowrie' | 'web' | 'fileserver' | 'network' | 'system'")
    version: Optional[str] = None
    host: Optional[str] = None


class EventDetail(BaseModel):
    """What happened."""
    type: str = Field(..., description="One of the EVENT_TYPES taxonomy values")
    category: str = Field(..., description="One of the EVENT_CATEGORIES values")
    action: Optional[str] = Field(None, description="Specific action string, e.g. 'whoami', 'GET /login'")
    outcome: Optional[str] = Field(None, description="'success' | 'failure' | 'unknown'")


class ActorInfo(BaseModel):
    """Who performed the action."""
    username: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = Field(None, description="Source component session identifier")


class TargetInfo(BaseModel):
    """What was targeted."""
    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    path: Optional[str] = None
    filename: Optional[str] = None


# ── Canonical BHRAM Event ─────────────────────────────────────────────────────

class CanonicalEvent(BaseModel):
    """
    The single canonical event format for all BHRAM telemetry.

    Every collector normalizes raw events into this schema before they are:
      - Persisted to PostgreSQL
      - Forwarded to the AI/ML API
      - Written to forensic storage
    """

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO-8601 UTC timestamp of when the event occurred",
    )
    session_id: Optional[str] = Field(
        None,
        description="Raw session identifier from source component (Cowrie session ID, web session ID, etc.)",
    )

    # Network identifiers
    source_ip: Optional[str] = Field(None, description="Attacker IP address")
    source_port: Optional[int] = Field(None, description="Attacker source port")
    destination_host: Optional[str] = Field(None, description="Target honeypot host")
    destination_port: Optional[int] = Field(None, description="Target service port")

    # Structured sub-schemas
    source: EventSource
    event: EventDetail
    actor: ActorInfo = Field(default_factory=ActorInfo)
    target: TargetInfo = Field(default_factory=TargetInfo)

    # Severity (can be overridden by collectors)
    severity: str = "info"

    # Raw original data — never destroyed, always preserved
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Original unmodified raw event from source component",
    )

    # Additional context
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got '{v}'")
        return v

    @model_validator(mode="after")
    def auto_severity(self) -> "CanonicalEvent":
        """Auto-assign severity from event type if still at default 'info'."""
        if self.severity == "info" and self.event.type in EVENT_TYPE_SEVERITY_MAP:
            self.severity = EVENT_TYPE_SEVERITY_MAP[self.event.type]
        return self

    def to_normalized_dict(self) -> Dict[str, Any]:
        """Serialise to the normalized_data JSONB column format."""
        return {
            "event_id": str(self.event_id),
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_host": self.destination_host,
            "destination_port": self.destination_port,
            "source": self.source.model_dump(),
            "event": self.event.model_dump(),
            "actor": self.actor.model_dump(exclude_none=True),
            "target": self.target.model_dump(exclude_none=True),
            "severity": self.severity,
            "metadata": self.metadata,
        }

    model_config = ConfigDict(
        json_encoders={
            uuid.UUID: str,
            datetime: lambda dt: dt.isoformat(),
        }
    )
