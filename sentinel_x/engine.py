"""
SENTINEL-X — SOAR Workflow Engine
Executes playbook steps with realistic simulation, timing, and reporting.
"""
import asyncio
import uuid
import time
import random
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session
from sentinel_x.models import (
    PlaybookExecution, Playbook, Incident, AuditLog,
    ExecutionStatus, IncidentStatus
)

# Global registry of active execution tasks
_active_tasks: dict = {}

# WebSocket broadcast function (set by main.py)
_broadcast_fn = None


def set_broadcast_fn(fn):
    global _broadcast_fn
    _broadcast_fn = fn


async def _broadcast(event_type: str, data: dict):
    if _broadcast_fn:
        try:
            await _broadcast_fn({"type": event_type, "data": data, "timestamp": datetime.utcnow().isoformat()})
        except Exception:
            pass


# ─────────────────────── Step Simulators ───────────────────────

async def _sim_triage(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(1.5, 3.5))
    severity = context.get("severity", "medium")
    return {
        "severity": severity,
        "confidence": round(random.uniform(0.85, 0.99), 2),
        "auto_escalated": severity in ["critical", "high"],
        "verdict": "confirmed_malicious",
    }


async def _sim_threat_intel(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(2, 5))
    return {
        "iocs_checked": random.randint(2, 8),
        "malicious": random.randint(1, 3),
        "suspicious": random.randint(0, 2),
        "clean": random.randint(0, 2),
        "threat_actor": random.choice(["LockBit Group", "Lazarus Group", "FIN7", "Unknown APT", None]),
        "confidence": round(random.uniform(0.75, 0.98), 2),
    }


async def _sim_isolate_host(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(2, 5))
    host = context.get("affected_host", "UNKNOWN-HOST")
    return {
        "host": host,
        "isolated": True,
        "method": "EDR Network Isolation (simulated)",
        "isolation_id": f"iso-{uuid.uuid4().hex[:8]}",
        "note": "SIMULATED — No actual network changes made",
    }


async def _sim_forensics(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(5, 12))
    return {
        "files_collected": random.randint(80, 200),
        "processes_captured": random.randint(50, 120),
        "network_connections": random.randint(5, 30),
        "registry_keys": random.randint(200, 800),
        "storage_path": f"/forensics/{uuid.uuid4().hex[:8]}/",
        "collection_size_mb": round(random.uniform(150, 850), 1),
    }


async def _sim_lateral_movement(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(4, 10))
    spread = random.random() < 0.15
    return {
        "endpoints_scanned": random.randint(100, 300),
        "spread_detected": spread,
        "affected_additional": random.randint(1, 3) if spread else 0,
        "scan_duration_seconds": random.randint(30, 90),
    }


async def _sim_notify(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "recipients": ["soc@company.com", "ciso@company.com"],
        "channels": ["email", "slack"],
        "delivered": 2,
        "timestamp": datetime.utcnow().isoformat(),
    }


async def _sim_manual(context: dict, step: dict) -> dict:
    return {
        "status": "awaiting_analyst",
        "message": "Paused for analyst review.",
        "timeout_seconds": step.get("timeout", 3600),
    }


async def _sim_remediation(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(3, 8))
    return {
        "actions_taken": ["credential_reset", "system_scan", "restore_initiated"],
        "credentials_reset": random.randint(1, 5),
        "systems_cleaned": random.randint(1, 3),
        "note": "SIMULATED — No actual remediation performed",
    }


async def _sim_report(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(1, 4))
    return {
        "report_id": f"rpt-{uuid.uuid4().hex[:8]}",
        "sections": ["Executive Summary", "Timeline", "IOC List", "Recommendations", "Lessons Learned"],
        "pages": random.randint(6, 15),
        "format": "PDF + JSON",
    }


async def _sim_email_headers(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(1, 4))
    return {
        "spf_result": "fail",
        "dkim_result": "fail",
        "dmarc_result": "fail",
        "spoofed": True,
        "relay_hops": random.randint(2, 6),
    }


async def _sim_url_detonation(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(8, 15))
    return {
        "urls_submitted": random.randint(1, 5),
        "malicious": random.randint(1, 3),
        "clean": 0,
        "screenshot_captured": True,
        "credential_harvest_detected": True,
        "sandbox": "Joe Sandbox (simulated)",
    }


async def _sim_attachments(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(4, 10))
    return {
        "attachments_found": random.randint(0, 2),
        "malicious": 0,
        "file_types": ["pdf"],
    }


async def _sim_credential_check(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(2, 6))
    return {
        "accounts_checked": random.randint(3, 10),
        "exposed_accounts": random.randint(1, 4),
        "breach_sources": ["HaveIBeenPwned", "IntelligenceX"],
        "oldest_breach": "2023-08-14",
    }


async def _sim_block_rule(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "rule_created": True,
        "rule_id": f"blk-{uuid.uuid4().hex[:8]}",
        "note": "SIMULATED — No actual block rule created",
    }


async def _sim_distribute_iocs(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(1, 4))
    return {
        "iocs_distributed": random.randint(3, 10),
        "controls_updated": ["Firewall", "SIEM", "EDR", "Email Gateway"],
        "propagation_time_seconds": random.randint(2, 15),
    }


async def _sim_lockout(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "accounts_locked": random.randint(1, 3),
        "lockout_duration_minutes": 30,
        "note": "SIMULATED — No actual account changes",
    }


async def _sim_block_ip(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "ip_blocked": context.get("source_ip", "unknown"),
        "rule_id": f"fw-{uuid.uuid4().hex[:8]}",
        "firewall": "Perimeter Firewall (simulated)",
        "note": "SIMULATED — No actual firewall changes",
    }


async def _sim_mfa(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "mfa_enforced": True,
        "accounts_affected": random.randint(1, 5),
        "method": "TOTP (simulated)",
        "note": "SIMULATED — No actual MFA changes",
    }


async def _sim_network_traffic(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(3, 8))
    return {
        "connections_analyzed": random.randint(500, 5000),
        "anomalous_transfers": random.randint(1, 5),
        "largest_transfer_gb": round(random.uniform(2, 8), 2),
        "destination_countries": ["RU", "CN", "Unknown"],
    }


async def _sim_dlp(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(2, 6))
    return {
        "dlp_alerts_correlated": random.randint(1, 5),
        "data_categories": ["Financial Records", "PII", "Confidential"],
        "estimated_records": random.randint(1000, 50000),
    }


async def _sim_user_activity(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(3, 8))
    return {
        "logins_reviewed": random.randint(10, 50),
        "anomalous_logins": random.randint(1, 5),
        "file_access_events": random.randint(100, 2000),
        "privileged_actions": random.randint(0, 10),
    }


async def _sim_data_classify(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(4, 10))
    return {
        "classification": "CONFIDENTIAL",
        "contains_pii": True,
        "contains_financial": True,
        "regulatory_impact": ["GDPR", "PCI-DSS"],
        "estimated_records": random.randint(5000, 100000),
        "notification_required": True,
    }


async def _sim_terminate(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "connections_terminated": random.randint(1, 3),
        "processes_killed": random.randint(1, 5),
        "note": "SIMULATED — No actual process/connection termination",
    }


async def _sim_escalate(context: dict, step: dict) -> dict:
    await asyncio.sleep(random.uniform(0.5, 2))
    return {
        "escalated_to": "CISO",
        "escalation_id": f"esc-{uuid.uuid4().hex[:8]}",
        "priority": "P1",
    }


# Step action → simulator mapping
STEP_SIMULATORS = {
    "evaluate_alert_severity": _sim_triage,
    "lookup_threat_intel": _sim_threat_intel,
    "isolate_host": _sim_isolate_host,
    "collect_forensics": _sim_forensics,
    "check_lateral_movement": _sim_lateral_movement,
    "send_notifications": _sim_notify,
    "await_analyst_decision": _sim_manual,
    "execute_remediation": _sim_remediation,
    "generate_report": _sim_report,
    "analyze_email_headers": _sim_email_headers,
    "detonate_urls": _sim_url_detonation,
    "analyze_attachments": _sim_attachments,
    "check_credential_exposure": _sim_credential_check,
    "notify_affected_users": _sim_notify,
    "create_email_block_rule": _sim_block_rule,
    "distribute_iocs": _sim_distribute_iocs,
    "verify_brute_force": _sim_triage,
    "lockout_account": _sim_lockout,
    "check_ip_reputation": _sim_threat_intel,
    "block_ip": _sim_block_ip,
    "enforce_mfa": _sim_mfa,
    "notify_analyst": _sim_notify,
    "analyze_network_traffic": _sim_network_traffic,
    "correlate_dlp_alerts": _sim_dlp,
    "review_user_activity": _sim_user_activity,
    "classify_exfiltrated_data": _sim_data_classify,
    "terminate_connection": _sim_terminate,
    "suspend_account": _sim_lockout,
    "notify_legal": _sim_notify,
    "create_forensic_image": _sim_forensics,
    "lookup_file_hash": _sim_threat_intel,
    "analyze_behavior": _sim_forensics,
    "assess_severity": _sim_triage,
    "quarantine_file": _sim_block_ip,
    "terminate_process": _sim_terminate,
    "assess_scope": _sim_lateral_movement,
    "escalate": _sim_escalate,
}


# ─────────────────────── Execution Engine ───────────────────────

async def run_playbook_execution(execution_id: str, db_factory):
    """Main async execution loop for a playbook."""
    db: Session = db_factory()
    try:
        exec_obj = db.query(PlaybookExecution).filter_by(id=execution_id).first()
        if not exec_obj:
            return

        playbook = db.query(Playbook).filter_by(id=exec_obj.playbook_id).first()
        if not playbook:
            return

        steps = playbook.steps or []
        exec_obj.status = ExecutionStatus.RUNNING
        exec_obj.total_steps = len(steps)
        if exec_obj.step_results is None:
            exec_obj.step_results = []
        db.commit()

        await _broadcast("execution_started", {
            "execution_id": execution_id,
            "playbook_name": playbook.name,
            "total_steps": len(steps),
        })

        start_time = time.time()

        for i, step in enumerate(steps):
            exec_obj.current_step = i + 1
            db.commit()

            await _broadcast("step_started", {
                "execution_id": execution_id,
                "step_index": i,
                "step_name": step["name"],
                "step_type": step["type"],
            })

            step_start = time.time()
            context = dict(exec_obj.context or {})

            if exec_obj.incident_id:
                incident = db.query(Incident).filter_by(id=exec_obj.incident_id).first()
                if incident:
                    assets = incident.affected_assets or []
                    iocs = incident.iocs or []
                    context.update({
                        "affected_host": assets[0] if assets else "UNKNOWN",
                        "severity": incident.severity.value if incident.severity else "medium",
                        "source_ip": iocs[0].get("value") if iocs else None,
                    })

            action = step.get("action", "")
            sim_fn = STEP_SIMULATORS.get(action)

            try:
                if sim_fn:
                    output = await sim_fn(context, step)
                else:
                    await asyncio.sleep(random.uniform(1, 3))
                    output = {"status": "completed", "action": action}

                step_duration = round(time.time() - step_start, 2)
                result = {
                    "step_id": step["id"],
                    "name": step["name"],
                    "status": "success",
                    "duration": step_duration,
                    "output": output,
                    "timestamp": datetime.utcnow().isoformat(),
                    "simulated": step.get("simulated", False),
                }

            except Exception as e:
                step_duration = round(time.time() - step_start, 2)
                result = {
                    "step_id": step["id"],
                    "name": step["name"],
                    "status": "failed",
                    "duration": step_duration,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                current = list(exec_obj.step_results)
                current.append(result)
                exec_obj.step_results = current
                exec_obj.status = ExecutionStatus.FAILED
                exec_obj.error_message = str(e)
                exec_obj.completed_at = datetime.utcnow()
                exec_obj.execution_time = round(time.time() - start_time, 2)
                db.commit()
                await _broadcast("execution_failed", {"execution_id": execution_id, "error": str(e)})
                return

            current = list(exec_obj.step_results)
            current.append(result)
            exec_obj.step_results = current
            db.commit()

            await _broadcast("step_completed", {
                "execution_id": execution_id,
                "step_index": i,
                "step_name": step["name"],
                "result": result,
                "progress": round((i + 1) / len(steps) * 100),
            })

            # Manual step — pause execution
            if not step.get("automated", True):
                exec_obj.status = ExecutionStatus.PARTIAL
                db.commit()
                await _broadcast("execution_paused", {
                    "execution_id": execution_id,
                    "reason": "manual_step",
                    "step_name": step["name"],
                })
                return

        # All steps complete
        total_time = round(time.time() - start_time, 2)
        exec_obj.status = ExecutionStatus.SUCCESS
        exec_obj.execution_time = total_time
        exec_obj.completed_at = datetime.utcnow()
        exec_obj.current_step = len(steps)
        exec_obj.report = _generate_execution_report(exec_obj, playbook)

        # Update playbook stats
        n = (playbook.execution_count or 0) + 1
        old_avg = playbook.avg_execution_time or 0
        playbook.execution_count = n
        playbook.success_count = (playbook.success_count or 0) + 1
        playbook.avg_execution_time = round((old_avg * (n - 1) + total_time) / n, 2)

        # Update incident status
        if exec_obj.incident_id:
            incident = db.query(Incident).filter_by(id=exec_obj.incident_id).first()
            if incident and incident.status == IncidentStatus.NEW:
                incident.status = IncidentStatus.INVESTIGATING

        db.add(AuditLog(
            id=str(uuid.uuid4()),
            actor="SENTINEL-X",
            action="playbook.completed",
            resource_type="playbook_execution",
            resource_id=execution_id,
            resource_name=playbook.name,
            details={"execution_time": total_time, "steps": len(steps)},
            ip_address="127.0.0.1",
            severity="info",
        ))
        db.commit()

        await _broadcast("execution_completed", {
            "execution_id": execution_id,
            "playbook_name": playbook.name,
            "execution_time": total_time,
            "steps_completed": len(steps),
        })

    except Exception as e:
        print(f"Execution engine error for {execution_id}: {e}")
        try:
            exec_obj = db.query(PlaybookExecution).filter_by(id=execution_id).first()
            if exec_obj:
                exec_obj.status = ExecutionStatus.FAILED
                exec_obj.error_message = str(e)
                exec_obj.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
        _active_tasks.pop(execution_id, None)


def _generate_execution_report(exec_obj: PlaybookExecution, playbook: Playbook) -> dict:
    steps = exec_obj.step_results or []
    successful = sum(1 for s in steps if s.get("status") == "success")
    failed = sum(1 for s in steps if s.get("status") == "failed")
    simulated = sum(1 for s in steps if s.get("simulated"))
    return {
        "title": f"{playbook.name} — Execution Report",
        "execution_id": exec_obj.id,
        "generated_at": datetime.utcnow().isoformat(),
        "playbook_version": playbook.version,
        "total_steps": len(steps),
        "successful_steps": successful,
        "failed_steps": failed,
        "simulated_actions": simulated,
        "execution_time_seconds": exec_obj.execution_time,
        "triggered_by": exec_obj.triggered_by,
        "status": exec_obj.status.value,
        "step_summary": [
            {
                "step": s.get("name"),
                "status": s.get("status"),
                "duration": s.get("duration"),
                "simulated": s.get("simulated", False),
            }
            for s in steps
        ],
    }


async def start_execution(
    playbook_id: str,
    incident_id: Optional[str],
    alert_id: Optional[str],
    triggered_by: str,
    context: dict,
    db: Session,
    db_factory,
) -> PlaybookExecution:
    """Create and launch a playbook execution."""
    playbook = db.query(Playbook).filter_by(id=playbook_id).first()
    if not playbook:
        raise ValueError(f"Playbook {playbook_id} not found")

    exec_id = f"exec-{uuid.uuid4().hex[:12]}"
    exec_obj = PlaybookExecution(
        id=exec_id,
        playbook_id=playbook_id,
        incident_id=incident_id,
        alert_id=alert_id,
        status=ExecutionStatus.PENDING,
        triggered_by=triggered_by,
        context=context,
        step_results=[],
        current_step=0,
        total_steps=len(playbook.steps or []),
        started_at=datetime.utcnow(),
    )
    db.add(exec_obj)

    db.add(AuditLog(
        id=str(uuid.uuid4()),
        actor=triggered_by,
        action="playbook.triggered",
        resource_type="playbook_execution",
        resource_id=exec_id,
        resource_name=playbook.name,
        details={"incident_id": incident_id, "alert_id": alert_id},
        ip_address="127.0.0.1",
        severity="info",
    ))
    db.commit()

    task = asyncio.create_task(run_playbook_execution(exec_id, db_factory))
    _active_tasks[exec_id] = task

    return exec_obj
