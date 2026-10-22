"""
SENTINEL-X — FastAPI Application & API Routes
"""
import uuid
import json
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from sentinel_x.database import init_db, seed_db, SessionLocal, DATABASE_URL
from sentinel_x.models import (
    Alert, Incident, Playbook, PlaybookExecution, AuditLog,
    ThreatIntelFeed, MetricSnapshot,
    SeverityLevel, IncidentStatus, PlaybookStatus,
    ExecutionStatus, AlertStatus, ThreatCategory
)
import sentinel_x.engine as engine_module

# ─────────────────────── WebSocket Manager ───────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        disconnected = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)


manager = ConnectionManager()


async def broadcast_fn(message: dict):
    await manager.broadcast(message)


# ─────────────────────── Lifespan ───────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_db()
    engine_module.set_broadcast_fn(broadcast_fn)
    print("[OK] SENTINEL-X backend started")
    yield
    print("[STOP] SENTINEL-X backend stopping")


# ─────────────────────── App ───────────────────────

app = FastAPI(
    title="SENTINEL-X API",
    description="Intelligent Security Orchestration, Automation and Response Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────── Pydantic Schemas ───────────────────────

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution_summary: Optional[str] = None
    false_positive_reason: Optional[str] = None
    tags: Optional[List[str]] = None
    severity: Optional[str] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    tags: Optional[List[str]] = None


class ExecutionRequest(BaseModel):
    playbook_id: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    triggered_by: str = "analyst:admin"
    context: Optional[dict] = None


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    steps: Optional[List[dict]] = None
    tags: Optional[List[str]] = None
    trigger_conditions: Optional[dict] = None


class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    source: Optional[str] = "Manual"
    severity: str = "medium"
    category: Optional[str] = "unknown"
    affected_host: Optional[str] = None
    affected_user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    raw_data: Optional[dict] = None


class ThreatIntelLookup(BaseModel):
    ioc_type: str
    ioc_value: str


# ─────────────────────── Helper ───────────────────────

def _obj_to_dict(obj) -> dict:
    """Convert SQLAlchemy model to dict."""
    d = {}
    for col in obj.__table__.columns:
        val = getattr(obj, col.name)
        if isinstance(val, datetime):
            val = val.isoformat()
        elif hasattr(val, 'value'):
            val = val.value
        d[col.name] = val
    return d


def _severity_weight(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0)


def _add_audit(db: Session, actor: str, action: str, resource_type: str,
               resource_id: str, resource_name: str, details: dict = None, severity: str = "info"):
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details or {},
        ip_address="127.0.0.1",
        session_id="session-demo",
        severity=severity,
    ))


# ─────────────────────── WebSocket ───────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial ping
        await websocket.send_json({"type": "connected", "data": {"message": "SENTINEL-X WebSocket connected"}})
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping", "data": {}})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ─────────────────────── Dashboard Stats ───────────────────────

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(
        Incident.status.in_([IncidentStatus.NEW, IncidentStatus.TRIAGING, IncidentStatus.INVESTIGATING])
    ).count()
    critical_incidents = db.query(Incident).filter(
        Incident.severity == SeverityLevel.CRITICAL,
        Incident.status.notin_([IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE])
    ).count()

    total_alerts = db.query(Alert).count()
    new_alerts = db.query(Alert).filter(Alert.status == AlertStatus.NEW).count()

    total_executions = db.query(PlaybookExecution).count()
    successful_executions = db.query(PlaybookExecution).filter(
        PlaybookExecution.status == ExecutionStatus.SUCCESS
    ).count()

    resolved_with_time = db.query(Incident).filter(
        Incident.resolved_at.isnot(None),
        Incident.created_at.isnot(None)
    ).all()
    if resolved_with_time:
        avg_mttr = sum(
            (i.resolved_at - i.created_at).total_seconds() / 3600
            for i in resolved_with_time
        ) / len(resolved_with_time)
    else:
        avg_mttr = 4.2

    active_executions = db.query(PlaybookExecution).filter(
        PlaybookExecution.status.in_([ExecutionStatus.RUNNING, ExecutionStatus.PENDING])
    ).count()

    # Recent 24h
    cutoff = datetime.utcnow() - timedelta(hours=24)
    alerts_24h = db.query(Alert).filter(Alert.created_at >= cutoff).count()
    incidents_24h = db.query(Incident).filter(Incident.created_at >= cutoff).count()

    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "alerts_24h": alerts_24h,
        "incidents_24h": incidents_24h,
        "total_executions": total_executions,
        "successful_executions": successful_executions,
        "execution_success_rate": round(successful_executions / max(total_executions, 1) * 100, 1),
        "active_executions": active_executions,
        "avg_mttr_hours": round(avg_mttr, 2),
        "false_positive_rate": 8.3,
        "threat_score": 72,
    }


@app.get("/api/stats/metrics")
def get_metrics(metric_type: str = "daily_alerts", days: int = 30, db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(days=days)
    snapshots = db.query(MetricSnapshot).filter(
        MetricSnapshot.metric_type == metric_type,
        MetricSnapshot.timestamp >= cutoff,
    ).order_by(MetricSnapshot.timestamp).all()
    return [{"timestamp": s.timestamp.isoformat(), "value": round(s.value, 2), "labels": s.labels} for s in snapshots]


@app.get("/api/stats/severity_distribution")
def get_severity_distribution(db: Session = Depends(get_db)):
    results = db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all()
    return [{"severity": r[0].value if r[0] else "unknown", "count": r[1]} for r in results]


@app.get("/api/stats/category_distribution")
def get_category_distribution(db: Session = Depends(get_db)):
    results = db.query(Incident.category, func.count(Incident.id)).group_by(Incident.category).all()
    return [{"category": r[0].value if r[0] else "unknown", "count": r[1]} for r in results]


# ─────────────────────── Alerts ───────────────────────

@app.get("/api/alerts")
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if category:
        q = q.filter(Alert.category == category)
    total = q.count()
    alerts = q.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()
    return {"total": total, "items": [_obj_to_dict(a) for a in alerts]}


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return _obj_to_dict(alert)


@app.post("/api/alerts", status_code=201)
def create_alert(payload: AlertCreate, db: Session = Depends(get_db)):
    alert_id = f"alert-{uuid.uuid4().hex[:8]}"
    severity_map = {v.value: v for v in SeverityLevel}
    category_map = {v.value: v for v in ThreatCategory}

    alert = Alert(
        id=alert_id,
        title=payload.title,
        description=payload.description,
        source=payload.source or "Manual",
        severity=severity_map.get(payload.severity, SeverityLevel.MEDIUM),
        category=category_map.get(payload.category, ThreatCategory.UNKNOWN),
        affected_host=payload.affected_host,
        affected_user=payload.affected_user,
        source_ip=payload.source_ip,
        dest_ip=payload.dest_ip,
        raw_data=payload.raw_data or {},
        risk_score={"critical": 90, "high": 70, "medium": 50, "low": 25, "info": 10}.get(payload.severity, 50),
        tags=[],
        mitre_tactics=[],
        mitre_techniques=[],
    )
    db.add(alert)
    _add_audit(db, "analyst:admin", "alert.created", "alert", alert_id, payload.title)
    db.commit()

    asyncio.create_task(broadcast_fn({
        "type": "alert_created",
        "data": _obj_to_dict(alert),
        "timestamp": datetime.utcnow().isoformat(),
    }))

    return _obj_to_dict(alert)


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: str, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    if payload.status:
        status_map = {v.value: v for v in AlertStatus}
        alert.status = status_map.get(payload.status, alert.status)
    if payload.tags is not None:
        alert.tags = payload.tags
    _add_audit(db, "analyst:admin", "alert.updated", "alert", alert_id, alert.title, {"changes": payload.model_dump(exclude_none=True)})
    db.commit()
    return _obj_to_dict(alert)


@app.post("/api/alerts/{alert_id}/escalate")
def escalate_alert(alert_id: str, db: Session = Depends(get_db)):
    """Escalate alert to incident."""
    alert = db.query(Alert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")

    inc_id = f"inc-{uuid.uuid4().hex[:8]}"
    incident = Incident(
        id=inc_id,
        title=f"[Escalated] {alert.title}",
        description=alert.description,
        severity=alert.severity,
        status=IncidentStatus.NEW,
        category=alert.category,
        alert_id=alert_id,
        risk_score=alert.risk_score,
        affected_assets=[alert.affected_host, alert.affected_user] if alert.affected_host else [],
        iocs=[{"type": "ip", "value": alert.source_ip}] if alert.source_ip else [],
        mitre_tactics=alert.mitre_tactics or [],
        mitre_techniques=alert.mitre_techniques or [],
        tags=(alert.tags or []) + ["escalated"],
        timeline=[{
            "time": datetime.utcnow().isoformat(),
            "event": f"Alert escalated to incident from {alert.source}",
            "actor": "analyst:admin",
        }],
    )
    db.add(incident)
    alert.status = AlertStatus.ESCALATED
    _add_audit(db, "analyst:admin", "alert.escalated", "incident", inc_id, incident.title, {"alert_id": alert_id}, "warning")
    db.commit()
    return {"incident": _obj_to_dict(incident), "alert": _obj_to_dict(alert)}


# ─────────────────────── Incidents ───────────────────────

@app.get("/api/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if category:
        q = q.filter(Incident.category == category)
    if assigned_to:
        q = q.filter(Incident.assigned_to == assigned_to)
    total = q.count()
    incidents = q.order_by(desc(Incident.created_at)).offset(offset).limit(limit).all()
    return {"total": total, "items": [_obj_to_dict(i) for i in incidents]}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter_by(id=incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    result = _obj_to_dict(incident)
    # Include related executions
    execs = db.query(PlaybookExecution).filter_by(incident_id=incident_id).order_by(desc(PlaybookExecution.started_at)).all()
    result["executions"] = [_obj_to_dict(e) for e in execs]
    return result


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, payload: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter_by(id=incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")

    changes = {}
    if payload.status:
        status_map = {v.value: v for v in IncidentStatus}
        new_status = status_map.get(payload.status)
        if new_status:
            old_status = incident.status.value
            incident.status = new_status
            changes["status"] = {"from": old_status, "to": payload.status}
            if new_status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                incident.resolved_at = datetime.utcnow()
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to
        changes["assigned_to"] = payload.assigned_to
    if payload.notes is not None:
        incident.notes = payload.notes
    if payload.resolution_summary is not None:
        incident.resolution_summary = payload.resolution_summary
    if payload.false_positive_reason is not None:
        incident.false_positive_reason = payload.false_positive_reason
    if payload.tags is not None:
        incident.tags = payload.tags
    if payload.severity is not None:
        severity_map = {v.value: v for v in SeverityLevel}
        incident.severity = severity_map.get(payload.severity, incident.severity)

    # Append to timeline
    if changes:
        timeline = list(incident.timeline or [])
        for change_key, change_val in changes.items():
            timeline.append({
                "time": datetime.utcnow().isoformat(),
                "event": f"Incident {change_key} updated: {change_val}",
                "actor": "analyst:admin",
            })
        incident.timeline = timeline

    _add_audit(db, "analyst:admin", "incident.updated", "incident", incident_id, incident.title, changes)
    db.commit()

    asyncio.create_task(broadcast_fn({
        "type": "incident_updated",
        "data": {"incident_id": incident_id, "changes": changes},
        "timestamp": datetime.utcnow().isoformat(),
    }))

    return _obj_to_dict(incident)


@app.post("/api/incidents/{incident_id}/timeline")
def add_timeline_event(incident_id: str, event: dict, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter_by(id=incident_id).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    timeline = list(incident.timeline or [])
    timeline.append({
        "time": datetime.utcnow().isoformat(),
        "event": event.get("event", "Manual entry"),
        "actor": event.get("actor", "analyst:admin"),
    })
    incident.timeline = timeline
    db.commit()
    return {"timeline": timeline}


# ─────────────────────── Playbooks ───────────────────────

@app.get("/api/playbooks")
def list_playbooks(
    status: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db)
):
    q = db.query(Playbook)
    if status:
        q = q.filter(Playbook.status == status)
    if category:
        q = q.filter(Playbook.category == category)
    playbooks = q.order_by(desc(Playbook.execution_count)).all()
    return [_obj_to_dict(p) for p in playbooks]


@app.get("/api/playbooks/{playbook_id}")
def get_playbook(playbook_id: str, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter_by(id=playbook_id).first()
    if not pb:
        raise HTTPException(404, "Playbook not found")
    result = _obj_to_dict(pb)
    # Include recent executions
    execs = db.query(PlaybookExecution).filter_by(playbook_id=playbook_id).order_by(desc(PlaybookExecution.started_at)).limit(10).all()
    result["recent_executions"] = [_obj_to_dict(e) for e in execs]
    return result


@app.post("/api/playbooks", status_code=201)
def create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db)):
    pb_id = f"pb-{uuid.uuid4().hex[:12]}"
    category_map = {v.value: v for v in ThreatCategory}
    steps = payload.steps or []
    pb = Playbook(
        id=pb_id,
        name=payload.name,
        description=payload.description,
        category=category_map.get(payload.category or "unknown", ThreatCategory.UNKNOWN),
        steps=steps,
        nodes=[],
        edges=[],
        tags=payload.tags or [],
        trigger_conditions=payload.trigger_conditions or {},
        status=PlaybookStatus.DRAFT,
        author="analyst:admin",
    )
    db.add(pb)
    _add_audit(db, "analyst:admin", "playbook.created", "playbook", pb_id, payload.name)
    db.commit()
    return _obj_to_dict(pb)


# ─────────────────────── Playbook Executions ───────────────────────

@app.post("/api/executions", status_code=201)
async def trigger_execution(payload: ExecutionRequest, db: Session = Depends(get_db)):
    try:
        context = payload.context or {}
        if payload.incident_id:
            incident = db.query(Incident).filter_by(id=payload.incident_id).first()
            if incident:
                context.update({
                    "severity": incident.severity.value,
                    "category": incident.category.value,
                    "incident_title": incident.title,
                })
        if payload.alert_id:
            alert = db.query(Alert).filter_by(id=payload.alert_id).first()
            if alert:
                context.update({
                    "alert_title": alert.title,
                    "severity": context.get("severity") or alert.severity.value,
                })

        exec_obj = await engine_module.start_execution(
            playbook_id=payload.playbook_id,
            incident_id=payload.incident_id,
            alert_id=payload.alert_id,
            triggered_by=payload.triggered_by,
            context=context,
            db=db,
            db_factory=SessionLocal,
        )
        return _obj_to_dict(exec_obj)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/executions")
def list_executions(
    status: Optional[str] = None,
    playbook_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    q = db.query(PlaybookExecution)
    if status:
        q = q.filter(PlaybookExecution.status == status)
    if playbook_id:
        q = q.filter(PlaybookExecution.playbook_id == playbook_id)
    if incident_id:
        q = q.filter(PlaybookExecution.incident_id == incident_id)
    execs = q.order_by(desc(PlaybookExecution.started_at)).limit(limit).all()
    return [_obj_to_dict(e) for e in execs]


@app.get("/api/executions/{execution_id}")
def get_execution(execution_id: str, db: Session = Depends(get_db)):
    exec_obj = db.query(PlaybookExecution).filter_by(id=execution_id).first()
    if not exec_obj:
        raise HTTPException(404, "Execution not found")
    result = _obj_to_dict(exec_obj)
    if exec_obj.playbook:
        result["playbook_name"] = exec_obj.playbook.name
    return result


# ─────────────────────── Audit Logs ───────────────────────

@app.get("/api/audit")
def list_audit_logs(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    q = db.query(AuditLog)
    if actor:
        q = q.filter(AuditLog.actor == actor)
    if action:
        q = q.filter(AuditLog.action.contains(action))
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)
    if severity:
        q = q.filter(AuditLog.severity == severity)
    total = q.count()
    logs = q.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()
    return {"total": total, "items": [_obj_to_dict(l) for l in logs]}


# ─────────────────────── Threat Intel ───────────────────────

@app.get("/api/threat-intel")
def list_threat_intel(
    ioc_type: Optional[str] = None,
    reputation: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    q = db.query(ThreatIntelFeed)
    if ioc_type:
        q = q.filter(ThreatIntelFeed.ioc_type == ioc_type)
    if reputation:
        q = q.filter(ThreatIntelFeed.reputation == reputation)
    items = q.order_by(desc(ThreatIntelFeed.confidence)).limit(limit).all()
    return [_obj_to_dict(i) for i in items]


@app.post("/api/threat-intel/lookup")
def lookup_threat_intel(payload: ThreatIntelLookup, db: Session = Depends(get_db)):
    item = db.query(ThreatIntelFeed).filter_by(ioc_value=payload.ioc_value).first()
    if item:
        return {"found": True, "data": _obj_to_dict(item)}
    return {
        "found": False,
        "data": {
            "ioc_type": payload.ioc_type,
            "ioc_value": payload.ioc_value,
            "reputation": "unknown",
            "confidence": 0.0,
            "message": "IOC not found in local threat intelligence database.",
        }
    }


# ─────────────────────── Demo Scenarios ───────────────────────

@app.post("/api/demo/trigger-incident")
async def demo_trigger_incident(db: Session = Depends(get_db)):
    """Trigger a live demo: create a new alert and auto-run a playbook."""
    import random

    scenarios = [
        {
            "title": "DEMO: Ransomware Detected — ENDPOINT-DEMO",
            "severity": "critical",
            "category": "ransomware",
            "playbook_id": "pb-ransomware-response",
            "source": "CrowdStrike Falcon",
            "description": "Demo: EDR detected ransomware file encryption pattern on demonstration endpoint.",
            "affected_host": "ENDPOINT-DEMO",
        },
        {
            "title": "DEMO: Phishing Email Campaign Detected",
            "severity": "high",
            "category": "phishing",
            "playbook_id": "pb-phishing-investigation",
            "source": "Proofpoint TAP",
            "description": "Demo: Multiple suspicious emails detected targeting employee credentials.",
            "affected_host": "MAIL-DEMO",
        },
        {
            "title": "DEMO: Brute Force Attack on SSH Service",
            "severity": "high",
            "category": "brute_force",
            "playbook_id": "pb-brute-force-response",
            "source": "Splunk SIEM",
            "description": "Demo: 1,500+ failed SSH authentication attempts from external IP.",
            "affected_host": "SERVER-DEMO",
        },
    ]
    scenario = random.choice(scenarios)

    # Create alert
    alert_id = f"alert-demo-{uuid.uuid4().hex[:8]}"
    severity_map = {v.value: v for v in SeverityLevel}
    category_map = {v.value: v for v in ThreatCategory}

    alert = Alert(
        id=alert_id,
        title=scenario["title"],
        description=scenario["description"],
        source=scenario["source"],
        severity=severity_map[scenario["severity"]],
        category=category_map[scenario["category"]],
        affected_host=scenario["affected_host"],
        source_ip=f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
        risk_score={"critical": 95, "high": 80}[scenario["severity"]],
        tags=["demo", "auto-triggered"],
        mitre_tactics=[],
        mitre_techniques=[],
    )
    db.add(alert)

    # Create incident
    inc_id = f"inc-demo-{uuid.uuid4().hex[:8]}"
    incident = Incident(
        id=inc_id,
        title=scenario["title"],
        description=scenario["description"],
        severity=severity_map[scenario["severity"]],
        status=IncidentStatus.NEW,
        category=category_map[scenario["category"]],
        alert_id=alert_id,
        risk_score=alert.risk_score,
        affected_assets=[scenario["affected_host"]],
        iocs=[{"type": "ip", "value": alert.source_ip, "context": "source"}],
        mitre_tactics=[],
        mitre_techniques=[],
        tags=["demo"],
        timeline=[{
            "time": datetime.utcnow().isoformat(),
            "event": "Demo incident auto-created",
            "actor": "SENTINEL-X",
        }],
    )
    db.add(incident)
    _add_audit(db, "SENTINEL-X", "demo.incident_created", "incident", inc_id, scenario["title"], {}, "warning")
    db.commit()

    # Auto-trigger playbook
    context = {
        "severity": scenario["severity"],
        "category": scenario["category"],
        "demo": True,
    }
    exec_obj = await engine_module.start_execution(
        playbook_id=scenario["playbook_id"],
        incident_id=inc_id,
        alert_id=alert_id,
        triggered_by="auto",
        context=context,
        db=db,
        db_factory=SessionLocal,
    )

    await broadcast_fn({
        "type": "demo_started",
        "data": {
            "incident_id": inc_id,
            "alert_id": alert_id,
            "execution_id": exec_obj.id,
            "scenario": scenario["title"],
        },
        "timestamp": datetime.utcnow().isoformat(),
    })

    return {
        "message": "Demo scenario triggered",
        "scenario": scenario["title"],
        "alert_id": alert_id,
        "incident_id": inc_id,
        "execution_id": exec_obj.id,
    }


@app.post("/api/demo/reset")
def demo_reset(db: Session = Depends(get_db)):
    """Remove all demo-tagged data."""
    demo_incidents = db.query(Incident).filter(Incident.tags.contains(["demo"])).all()
    for i in demo_incidents:
        execs = db.query(PlaybookExecution).filter_by(incident_id=i.id).all()
        for e in execs:
            db.delete(e)
        db.delete(i)

    demo_alerts = db.query(Alert).filter(Alert.tags.contains(["demo"])).all()
    for a in demo_alerts:
        db.delete(a)

    db.commit()
    return {"message": "Demo data cleared"}


# ─────────────────────── Frontend ───────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    try:
        with open("sentinel_x/static/index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("<h1>SENTINEL-X</h1><p>Frontend not found. Run build step.</p>", status_code=500)
