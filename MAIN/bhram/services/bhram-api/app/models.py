"""
BHRAM API — SQLAlchemy ORM Models
Mirrors the PostgreSQL schema defined in database/schema.sql.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    BigInteger,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base


# ── Enums (mirror schema.sql) ─────────────────────────────────────────────────

class DeceptionMode(str, enum.Enum):
    baseline       = "baseline"
    passive        = "passive"
    active         = "active"
    aggressive     = "aggressive"
    reconstruction = "reconstruction"


class EventCategory(str, enum.Enum):
    ssh               = "ssh"
    http              = "http"
    file_access       = "file_access"
    auth              = "auth"
    network           = "network"
    lateral_movement  = "lateral_movement"
    exfiltration      = "exfiltration"
    deception_trigger = "deception_trigger"
    system            = "system"


class EventSeverity(str, enum.Enum):
    info     = "info"
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class ServiceStatus(str, enum.Enum):
    running  = "running"
    stopped  = "stopped"
    degraded = "degraded"
    honeypot = "honeypot"
    decoy    = "decoy"


class UserRole(str, enum.Enum):
    admin      = "admin"
    developer  = "developer"
    finance    = "finance"
    hr         = "hr"
    it_support = "it_support"
    intern     = "intern"
    management = "management"
    system     = "system"


# ── ORM Models ────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username    = Column(String(64),  nullable=False, unique=True)
    full_name   = Column(String(128), nullable=False)
    email       = Column(String(256), nullable=False, unique=True)
    department  = Column(String(64),  nullable=False)
    role        = Column(Enum(UserRole, name="user_role_enum"), nullable=False, default=UserRole.intern)
    is_decoy    = Column(Boolean, nullable=False, default=True)
    ssh_enabled = Column(Boolean, nullable=False, default=False)
    home_dir    = Column(String(256))
    created_at  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at  = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    metadata_   = Column("metadata", JSONB, nullable=False, default=dict)


class Service(Base):
    __tablename__ = "services"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(128), nullable=False, unique=True)
    description = Column(Text)
    status      = Column(Enum(ServiceStatus, name="service_status_enum"), nullable=False, default=ServiceStatus.running)
    host        = Column(String(256), nullable=False)
    port        = Column(Integer)
    protocol    = Column(String(32))
    is_honeypot = Column(Boolean, nullable=False, default=False)
    is_decoy    = Column(Boolean, nullable=False, default=False)
    network     = Column(String(64))
    docker_name = Column(String(128))
    created_at  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at  = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    metadata_   = Column("metadata", JSONB, nullable=False, default=dict)


class DecoyFile(Base):
    __tablename__ = "decoy_files"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename      = Column(String(512), nullable=False)
    filepath      = Column(Text, nullable=False)
    content_type  = Column(String(128))
    size_bytes    = Column(BigInteger, default=0)
    is_active     = Column(Boolean, nullable=False, default=True)
    bait_level    = Column(Integer, nullable=False, default=1)
    access_count  = Column(Integer, nullable=False, default=0)
    last_accessed = Column(DateTime(timezone=True))
    created_at    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at    = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    metadata_     = Column("metadata", JSONB, nullable=False, default=dict)


class AttackSession(Base):
    __tablename__ = "attack_sessions"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id        = Column(String(256), nullable=False, unique=True)
    source_ip         = Column(INET, nullable=False)
    source_port       = Column(Integer)
    destination_ip    = Column(INET)
    destination_port  = Column(Integer)
    protocol          = Column(String(32), nullable=False, default="ssh")
    start_time        = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    end_time          = Column(DateTime(timezone=True))
    duration_secs     = Column(Numeric(10, 3))
    is_active         = Column(Boolean, nullable=False, default=True)
    attacker_profile_id = Column(UUID(as_uuid=True), ForeignKey("attacker_profiles.id"), nullable=True)
    threat_score      = Column(Numeric(5, 2))
    intent            = Column(String(128))
    metadata_         = Column("metadata", JSONB, nullable=False, default=dict)

    events            = relationship("Event", back_populates="session", lazy="select")
    profile           = relationship("AttackerProfile", back_populates="sessions", lazy="select")


class Event(Base):
    __tablename__ = "events"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id      = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id", ondelete="SET NULL"), nullable=True)
    event_time      = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    source          = Column(String(128), nullable=False)
    category        = Column(Enum(EventCategory, name="event_category_enum"), nullable=False)
    severity        = Column(Enum(EventSeverity, name="event_severity_enum"), nullable=False, default=EventSeverity.info)
    event_type      = Column(String(128), nullable=False)
    source_ip       = Column(INET)
    raw_data        = Column(JSONB, nullable=False, default=dict)
    normalized_data = Column(JSONB, nullable=False, default=dict)
    analyzed        = Column(Boolean, nullable=False, default=False)
    analysis_result = Column(JSONB)
    created_at      = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    session = relationship("AttackSession", back_populates="events", lazy="select")


class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_ip     = Column(INET, nullable=False, unique=True)
    first_seen    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen     = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    session_count = Column(Integer, nullable=False, default=0)
    ttps          = Column(JSONB, nullable=False, default=list)
    skill_level   = Column(String(32))
    likely_intent = Column(String(128))
    threat_score  = Column(Numeric(5, 2), default=0)
    profile_data  = Column(JSONB, nullable=False, default=dict)
    created_at    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at    = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    sessions = relationship("AttackSession", back_populates="profile", lazy="select")


class EnvironmentState(Base):
    __tablename__ = "environment_state"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_time   = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    deception_mode  = Column(Enum(DeceptionMode, name="deception_mode_enum"), nullable=False, default=DeceptionMode.baseline)
    is_current      = Column(Boolean, nullable=False, default=False)
    state           = Column(JSONB, nullable=False, default=dict)
    applied_by      = Column(String(128), default="system")
    notes           = Column(Text)


class DeceptionAction(Base):
    __tablename__ = "deception_actions"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_time     = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    action_type     = Column(String(128), nullable=False)
    trigger_event   = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"), nullable=True)
    trigger_session = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id", ondelete="SET NULL"), nullable=True)
    parameters      = Column(JSONB, nullable=False, default=dict)
    result          = Column(JSONB)
    success         = Column(Boolean)
    applied_by      = Column(String(128), default="system")
    notes           = Column(Text)


class RawEvent(Base):
    """
    Part 2: Immutable forensic raw event record.
    Separate from the normalized events table — never modified after write.
    Maps 1:1 to a CanonicalEvent but stores only the original raw_data.
    """
    __tablename__ = "raw_events"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    received_at         = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    source              = Column(String(128), nullable=False)
    raw_data            = Column(JSONB, nullable=False, default=dict)
    canonical_event_id  = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"), nullable=True)
    data_hash           = Column(String(64))


from sqlalchemy import Table, PrimaryKeyConstraint

class SessionEvent(Base):
    """
    Part 2: Junction table — explicitly links AttackSession ↔ Event.
    Enables fast timeline queries without a full events table scan.
    """
    __tablename__ = "session_events"

    session_id  = Column(UUID(as_uuid=True), ForeignKey("attack_sessions.id", ondelete="CASCADE"), nullable=False)
    event_id    = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    event_time  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (PrimaryKeyConstraint("session_id", "event_id"),)
