"""
SENTINEL-X — Database Models
SQLAlchemy ORM models for the SOAR platform.
"""
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text,
    DateTime, JSON, ForeignKey, Enum
)
from sqlalchemy.orm import relationship, DeclarativeBase


class Base(DeclarativeBase):
    pass


# ─────────────────────────────── Enums ───────────────────────────────

class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, PyEnum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class PlaybookStatus(str, PyEnum):
    ACTIVE = "active"
    DRAFT = "draft"
    ARCHIVED = "archived"


class ExecutionStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


class AlertStatus(str, PyEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class ThreatCategory(str, PyEnum):
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    DATA_EXFIL = "data_exfiltration"
    LATERAL_MOVE = "lateral_movement"
    PRIVILEGE_ESC = "privilege_escalation"
    BRUTE_FORCE = "brute_force"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    APT = "apt"
    DOS = "denial_of_service"
    RECON = "reconnaissance"
    UNKNOWN = "unknown"


# ─────────────────────────────── Models ───────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    source = Column(String)           # e.g. "Splunk", "CrowdStrike", "Manual"
    source_ref = Column(String)       # External reference ID
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW)
    category = Column(Enum(ThreatCategory), default=ThreatCategory.UNKNOWN)
    raw_data = Column(JSON)           # Original event payload
    enrichment_data = Column(JSON)    # TI enrichment results
    risk_score = Column(Float, default=0.0)
    affected_host = Column(String)
    affected_user = Column(String)
    source_ip = Column(String)
    dest_ip = Column(String)
    mitre_tactics = Column(JSON)      # List of MITRE ATT&CK tactic IDs
    mitre_techniques = Column(JSON)   # List of MITRE ATT&CK technique IDs
    tags = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    incidents = relationship("Incident", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.NEW)
    category = Column(Enum(ThreatCategory), default=ThreatCategory.UNKNOWN)
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=True)
    assigned_to = Column(String)
    risk_score = Column(Float, default=0.0)
    affected_assets = Column(JSON)    # List of hosts/users
    iocs = Column(JSON)               # Indicators of Compromise
    timeline = Column(JSON)           # List of timeline events
    notes = Column(Text)
    mitre_tactics = Column(JSON)
    mitre_techniques = Column(JSON)
    tags = Column(JSON)
    resolution_summary = Column(Text)
    false_positive_reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    alert = relationship("Alert", back_populates="incidents")
    executions = relationship("PlaybookExecution", back_populates="incident")


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    version = Column(String, default="1.0.0")
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.ACTIVE)
    category = Column(Enum(ThreatCategory), default=ThreatCategory.UNKNOWN)
    trigger_conditions = Column(JSON)  # Auto-trigger rules
    steps = Column(JSON)               # Ordered list of step definitions
    nodes = Column(JSON)               # React-Flow compatible node layout
    edges = Column(JSON)               # React-Flow compatible edge layout
    author = Column(String)
    tags = Column(JSON)
    execution_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    avg_execution_time = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    executions = relationship("PlaybookExecution", back_populates="playbook")


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(String, primary_key=True)
    playbook_id = Column(String, ForeignKey("playbooks.id"))
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    alert_id = Column(String, nullable=True)
    status = Column(Enum(ExecutionStatus), default=ExecutionStatus.PENDING)
    triggered_by = Column(String)       # "auto" | "analyst:<name>"
    context = Column(JSON)              # Input context for this run
    step_results = Column(JSON)         # Per-step execution results
    current_step = Column(Integer, default=0)
    total_steps = Column(Integer, default=0)
    execution_time = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)
    report = Column(JSON, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    playbook = relationship("Playbook", back_populates="executions")
    incident = relationship("Incident", back_populates="executions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String)            # analyst name or "system"
    action = Column(String)           # e.g. "incident.created"
    resource_type = Column(String)    # "incident", "alert", "playbook", etc.
    resource_id = Column(String)
    resource_name = Column(String)
    details = Column(JSON)
    ip_address = Column(String)
    session_id = Column(String)
    severity = Column(String, default="info")  # info | warning | critical


class ThreatIntelFeed(Base):
    __tablename__ = "threat_intel"

    id = Column(String, primary_key=True)
    ioc_type = Column(String)         # ip, domain, hash, url, email
    ioc_value = Column(String, unique=True)
    reputation = Column(String)       # malicious | suspicious | clean | unknown
    confidence = Column(Float, default=0.0)
    tags = Column(JSON)
    sources = Column(JSON)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    context = Column(JSON)            # enrichment context


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    metric_type = Column(String)      # "daily_alerts", "mttd", "mttr", etc.
    value = Column(Float)
    labels = Column(JSON)
