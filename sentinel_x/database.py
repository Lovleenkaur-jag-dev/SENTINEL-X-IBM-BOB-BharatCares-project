"""
SENTINEL-X — Database Initialization & Seed Data
"""
import uuid
import json
from datetime import datetime, timedelta
import random

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

from sentinel_x.models import (
    Base, Alert, Incident, Playbook, PlaybookExecution,
    AuditLog, ThreatIntelFeed, MetricSnapshot,
    SeverityLevel, IncidentStatus, PlaybookStatus,
    ExecutionStatus, AlertStatus, ThreatCategory
)

DATABASE_URL = "sqlite:///./sentinel_x.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

# Enable WAL mode for better concurrent access
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


def seed_db():
    """Populate the database with realistic demo data."""
    db = SessionLocal()
    try:
        # Skip if already seeded
        if db.query(Alert).count() > 0:
            return
        _seed_threat_intel(db)
        _seed_playbooks(db)
        _seed_alerts_and_incidents(db)
        _seed_metrics(db)
        _seed_audit_logs(db)
        db.commit()
        print("[OK] Database seeded successfully.")
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Seed error: {e}")
        raise
    finally:
        db.close()


# ─────────────────────── Threat Intel ───────────────────────

def _seed_threat_intel(db: Session):
    iocs = [
        ("ip", "185.220.101.47", "malicious", 0.97, ["tor-exit", "botnet-c2"], ["AbuseIPDB", "VirusTotal"]),
        ("ip", "45.142.212.100", "malicious", 0.91, ["malware-dist", "ransomware"], ["Shodan", "AlienVault OTX"]),
        ("ip", "192.168.1.254", "suspicious", 0.45, ["internal-pivot"], ["SIEM"]),
        ("ip", "10.0.0.50", "suspicious", 0.30, ["anomalous-traffic"], ["SIEM"]),
        ("domain", "malware-delivery.xyz", "malicious", 0.99, ["phishing", "malware"], ["VirusTotal", "URLScan"]),
        ("domain", "update-security.net", "malicious", 0.88, ["c2-domain", "apt"], ["Recorded Future"]),
        ("domain", "docs-sharepoint-portal.com", "suspicious", 0.72, ["phishing"], ["PhishTank"]),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e", "clean", 0.02, [], ["VirusTotal"]),
        ("hash", "44d88612fea8a8f36de82e1278abb02f", "malicious", 0.96, ["eicar", "test-malware"], ["VirusTotal"]),
        ("hash", "e17a8a4e76a56a839c45bb6b29b18bca", "malicious", 0.93, ["ransomware", "lockbit"], ["CrowdStrike", "SentinelOne"]),
        ("hash", "b94c3f5e4aab2d9e56c7817c4b1d9f23", "malicious", 0.89, ["trojan", "banker"], ["Kaspersky"]),
        ("email", "phishing@secure-login-alert.com", "malicious", 0.95, ["phishing", "credential-harvest"], ["ProofPoint"]),
        ("url", "http://update-security.net/payload.exe", "malicious", 0.98, ["malware-download"], ["VirusTotal", "URLScan"]),
    ]
    for ioc_type, value, reputation, confidence, tags, sources in iocs:
        db.add(ThreatIntelFeed(
            id=str(uuid.uuid4()),
            ioc_type=ioc_type,
            ioc_value=value,
            reputation=reputation,
            confidence=confidence,
            tags=tags,
            sources=sources,
            context={"auto_seeded": True}
        ))


# ─────────────────────── Playbooks ───────────────────────

def _seed_playbooks(db: Session):
    playbooks = [
        {
            "id": "pb-ransomware-response",
            "name": "Ransomware Response",
            "description": "Automated containment and investigation workflow for detected ransomware activity. Isolates affected hosts, collects forensic artifacts, notifies stakeholders, and initiates recovery procedures.",
            "category": ThreatCategory.RANSOMWARE,
            "version": "2.3.1",
            "author": "SOC Team",
            "tags": ["ransomware", "containment", "critical", "auto-response"],
            "steps": [
                {"id": "s1", "name": "Alert Triage", "type": "triage", "action": "evaluate_alert_severity", "description": "Evaluate incoming alert and determine severity level.", "automated": True, "timeout": 30},
                {"id": "s2", "name": "Threat Intel Lookup", "type": "enrich", "action": "lookup_threat_intel", "description": "Query threat intelligence feeds for all IOCs extracted from the alert.", "automated": True, "timeout": 60},
                {"id": "s3", "name": "Host Isolation", "type": "contain", "action": "isolate_host", "description": "Quarantine affected endpoint from network access via EDR integration (simulated).", "automated": True, "timeout": 45, "simulated": True},
                {"id": "s4", "name": "Evidence Collection", "type": "investigate", "action": "collect_forensics", "description": "Collect running processes, network connections, registry hives, and memory snapshot.", "automated": True, "timeout": 120},
                {"id": "s5", "name": "Lateral Movement Check", "type": "investigate", "action": "check_lateral_movement", "description": "Scan for similar activity across other endpoints in the environment.", "automated": True, "timeout": 90},
                {"id": "s6", "name": "Stakeholder Notification", "type": "notify", "action": "send_notifications", "description": "Send incident notifications to CISO, IT Manager, and affected department heads.", "automated": True, "timeout": 30},
                {"id": "s7", "name": "Analyst Review", "type": "manual", "action": "await_analyst_decision", "description": "Pause for analyst review of collected evidence before proceeding to remediation.", "automated": False, "timeout": 3600},
                {"id": "s8", "name": "Remediation", "type": "remediate", "action": "execute_remediation", "description": "Execute remediation playbook: wipe & restore from backup, reset credentials.", "automated": False, "timeout": 7200},
                {"id": "s9", "name": "Post-Incident Report", "type": "report", "action": "generate_report", "description": "Generate comprehensive post-incident report with timeline, IOCs, and lessons learned.", "automated": True, "timeout": 60},
            ],
            "nodes": _build_nodes(9),
            "edges": _build_edges(9),
            "trigger_conditions": {"severity": ["critical", "high"], "category": ["ransomware"], "keywords": ["ransom", "encrypt", "bitcoin", ".locky", ".ryuk"]},
            "execution_count": 47,
            "success_count": 44,
            "avg_execution_time": 248.5,
        },
        {
            "id": "pb-phishing-investigation",
            "name": "Phishing Email Investigation",
            "description": "Comprehensive investigation workflow for reported phishing emails including header analysis, URL detonation, credential compromise assessment, and employee notification.",
            "category": ThreatCategory.PHISHING,
            "version": "1.8.0",
            "author": "SOC Team",
            "tags": ["phishing", "email", "credential-theft", "user-awareness"],
            "steps": [
                {"id": "s1", "name": "Header Analysis", "type": "investigate", "action": "analyze_email_headers", "description": "Extract and analyze email headers for spoofing, relay abuse, and authentication failures.", "automated": True, "timeout": 30},
                {"id": "s2", "name": "URL Sandboxing", "type": "enrich", "action": "detonate_urls", "description": "Submit extracted URLs to sandbox for dynamic analysis and screenshot capture.", "automated": True, "timeout": 120},
                {"id": "s3", "name": "Attachment Analysis", "type": "enrich", "action": "analyze_attachments", "description": "Scan email attachments in sandbox environment. Extract and hash all files.", "automated": True, "timeout": 90},
                {"id": "s4", "name": "Credential Exposure Check", "type": "investigate", "action": "check_credential_exposure", "description": "Check if targeted users have leaked credentials in breach databases.", "automated": True, "timeout": 45},
                {"id": "s5", "name": "User Notification", "type": "notify", "action": "notify_affected_users", "description": "Send security awareness notification to all employees who received the phishing email.", "automated": True, "timeout": 30},
                {"id": "s6", "name": "Email Block Rule", "type": "contain", "action": "create_email_block_rule", "description": "Create block rule for sender domain and subject pattern in email gateway.", "automated": True, "timeout": 30, "simulated": True},
                {"id": "s7", "name": "IOC Distribution", "type": "share", "action": "distribute_iocs", "description": "Push malicious URLs, domains, and hashes to all security controls.", "automated": True, "timeout": 60},
                {"id": "s8", "name": "Report Generation", "type": "report", "action": "generate_report", "description": "Generate phishing investigation report with indicators and user exposure metrics.", "automated": True, "timeout": 45},
            ],
            "nodes": _build_nodes(8),
            "edges": _build_edges(8),
            "trigger_conditions": {"severity": ["high", "medium"], "category": ["phishing"], "keywords": ["phishing", "suspicious email", "credential harvest"]},
            "execution_count": 183,
            "success_count": 179,
            "avg_execution_time": 95.3,
        },
        {
            "id": "pb-brute-force-response",
            "name": "Brute Force Attack Response",
            "description": "Automated response to brute force authentication attacks including account lockout, geo-anomaly detection, and attacker IP blocking.",
            "category": ThreatCategory.BRUTE_FORCE,
            "version": "1.5.2",
            "author": "SOC Team",
            "tags": ["brute-force", "authentication", "account-lockout"],
            "steps": [
                {"id": "s1", "name": "Attack Verification", "type": "triage", "action": "verify_brute_force", "description": "Confirm brute force pattern by analyzing authentication logs.", "automated": True, "timeout": 30},
                {"id": "s2", "name": "Account Lockout", "type": "contain", "action": "lockout_account", "description": "Temporarily lock targeted accounts to prevent unauthorized access (simulated).", "automated": True, "timeout": 15, "simulated": True},
                {"id": "s3", "name": "IP Reputation Check", "type": "enrich", "action": "check_ip_reputation", "description": "Query threat intel for attacker IP reputation and geolocation.", "automated": True, "timeout": 30},
                {"id": "s4", "name": "IP Block", "type": "contain", "action": "block_ip", "description": "Add attacker IP to firewall block list (simulated).", "automated": True, "timeout": 15, "simulated": True},
                {"id": "s5", "name": "MFA Enforcement", "type": "remediate", "action": "enforce_mfa", "description": "Force MFA re-enrollment for all affected accounts.", "automated": True, "timeout": 30, "simulated": True},
                {"id": "s6", "name": "Analyst Notification", "type": "notify", "action": "notify_analyst", "description": "Notify on-call analyst of brute force activity and containment actions taken.", "automated": True, "timeout": 15},
            ],
            "nodes": _build_nodes(6),
            "edges": _build_edges(6),
            "trigger_conditions": {"severity": ["high", "medium"], "category": ["brute_force"], "keywords": ["brute force", "failed login", "authentication failure"]},
            "execution_count": 312,
            "success_count": 308,
            "avg_execution_time": 42.1,
        },
        {
            "id": "pb-data-exfiltration",
            "name": "Data Exfiltration Detection & Response",
            "description": "Multi-stage investigation and containment for suspected data exfiltration. Identifies what data was accessed, by whom, and through which channel.",
            "category": ThreatCategory.DATA_EXFIL,
            "version": "2.0.0",
            "author": "SOC Team",
            "tags": ["data-loss", "dlp", "exfiltration", "critical"],
            "steps": [
                {"id": "s1", "name": "Traffic Analysis", "type": "investigate", "action": "analyze_network_traffic", "description": "Analyze network traffic logs for large outbound transfers and unusual destinations.", "automated": True, "timeout": 60},
                {"id": "s2", "name": "DLP Alert Correlation", "type": "investigate", "action": "correlate_dlp_alerts", "description": "Correlate with DLP system alerts to identify specific data assets involved.", "automated": True, "timeout": 45},
                {"id": "s3", "name": "User Activity Review", "type": "investigate", "action": "review_user_activity", "description": "Review all activity from the user account associated with the transfer.", "automated": True, "timeout": 60},
                {"id": "s4", "name": "Data Classification", "type": "investigate", "action": "classify_exfiltrated_data", "description": "Determine classification level of potentially exfiltrated data (PII, IP, confidential).", "automated": True, "timeout": 90},
                {"id": "s5", "name": "Connection Termination", "type": "contain", "action": "terminate_connection", "description": "Terminate active exfiltration connections (simulated).", "automated": True, "timeout": 15, "simulated": True},
                {"id": "s6", "name": "Account Suspension", "type": "contain", "action": "suspend_account", "description": "Suspend user account pending investigation (simulated).", "automated": False, "timeout": 300, "simulated": True},
                {"id": "s7", "name": "Legal Notification", "type": "notify", "action": "notify_legal", "description": "Notify legal and compliance team if PII or regulated data is involved.", "automated": True, "timeout": 30},
                {"id": "s8", "name": "Forensic Image", "type": "investigate", "action": "create_forensic_image", "description": "Create forensic image of user workstation for legal proceedings.", "automated": False, "timeout": 7200},
                {"id": "s9", "name": "Report & Escalation", "type": "report", "action": "generate_report", "description": "Generate executive-level incident report and escalate to CISO.", "automated": True, "timeout": 60},
            ],
            "nodes": _build_nodes(9),
            "edges": _build_edges(9),
            "trigger_conditions": {"severity": ["critical", "high"], "category": ["data_exfiltration"]},
            "execution_count": 28,
            "success_count": 25,
            "avg_execution_time": 412.0,
        },
        {
            "id": "pb-malware-triage",
            "name": "Malware Detection & Triage",
            "description": "First-response triage workflow for generic malware detections from endpoint security tools.",
            "category": ThreatCategory.MALWARE,
            "version": "3.1.0",
            "author": "SOC Team",
            "tags": ["malware", "triage", "edr", "automated"],
            "steps": [
                {"id": "s1", "name": "Hash Lookup", "type": "enrich", "action": "lookup_file_hash", "description": "Query VirusTotal and internal threat intel for detected file hash.", "automated": True, "timeout": 30},
                {"id": "s2", "name": "Behavior Analysis", "type": "investigate", "action": "analyze_behavior", "description": "Review EDR behavioral telemetry for suspicious process and file activity.", "automated": True, "timeout": 60},
                {"id": "s3", "name": "Severity Assessment", "type": "triage", "action": "assess_severity", "description": "Calculate dynamic severity score based on hash reputation, behavior, and blast radius.", "automated": True, "timeout": 20},
                {"id": "s4", "name": "File Quarantine", "type": "contain", "action": "quarantine_file", "description": "Quarantine malicious file via EDR integration (simulated).", "automated": True, "timeout": 30, "simulated": True},
                {"id": "s5", "name": "Process Termination", "type": "contain", "action": "terminate_process", "description": "Terminate malicious process and child processes (simulated).", "automated": True, "timeout": 15, "simulated": True},
                {"id": "s6", "name": "Scope Assessment", "type": "investigate", "action": "assess_scope", "description": "Determine if malware has spread to other endpoints.", "automated": True, "timeout": 90},
                {"id": "s7", "name": "Report", "type": "report", "action": "generate_report", "description": "Generate triage report with verdict and recommended next steps.", "automated": True, "timeout": 30},
            ],
            "nodes": _build_nodes(7),
            "edges": _build_edges(7),
            "trigger_conditions": {"severity": ["critical", "high", "medium"], "category": ["malware"]},
            "execution_count": 521,
            "success_count": 509,
            "avg_execution_time": 67.4,
        },
    ]

    for pb_data in playbooks:
        pb = Playbook(
            id=pb_data["id"],
            name=pb_data["name"],
            description=pb_data["description"],
            category=pb_data["category"],
            version=pb_data["version"],
            author=pb_data["author"],
            tags=pb_data["tags"],
            steps=pb_data["steps"],
            nodes=pb_data["nodes"],
            edges=pb_data["edges"],
            trigger_conditions=pb_data["trigger_conditions"],
            status=PlaybookStatus.ACTIVE,
            execution_count=pb_data["execution_count"],
            success_count=pb_data["success_count"],
            avg_execution_time=pb_data["avg_execution_time"],
        )
        db.add(pb)


def _build_nodes(count: int):
    node_types = ["triage", "enrich", "contain", "investigate", "notify", "manual", "remediate", "report", "share"]
    colors = {
        "triage": "#f59e0b", "enrich": "#3b82f6", "contain": "#ef4444",
        "investigate": "#8b5cf6", "notify": "#06b6d4", "manual": "#f97316",
        "remediate": "#10b981", "report": "#6b7280", "share": "#ec4899"
    }
    nodes = [{"id": "trigger", "type": "trigger", "position": {"x": 300, "y": 20}, "data": {"label": "Trigger", "type": "trigger", "color": "#22c55e"}}]
    x_positions = [100, 500, 100, 500, 100, 500, 100, 500, 100]
    for i in range(count):
        ntype = node_types[i % len(node_types)]
        nodes.append({
            "id": f"s{i+1}",
            "type": "step",
            "position": {"x": x_positions[i], "y": 120 + i * 100},
            "data": {"label": f"Step {i+1}", "type": ntype, "color": colors.get(ntype, "#6b7280")}
        })
    nodes.append({"id": "end", "type": "end", "position": {"x": 300, "y": 120 + count * 100}, "data": {"label": "Complete", "type": "end", "color": "#22c55e"}})
    return nodes


def _build_edges(count: int):
    edges = [{"id": "e-trigger-s1", "source": "trigger", "target": "s1", "type": "smoothstep", "animated": True}]
    for i in range(1, count):
        edges.append({"id": f"e-s{i}-s{i+1}", "source": f"s{i}", "target": f"s{i+1}", "type": "smoothstep", "animated": True})
    edges.append({"id": f"e-s{count}-end", "source": f"s{count}", "target": "end", "type": "smoothstep", "animated": False})
    return edges


# ─────────────────────── Alerts & Incidents ───────────────────────

def _seed_alerts_and_incidents(db: Session):
    now = datetime.utcnow()

    alerts_data = [
        {
            "id": "alert-001",
            "title": "Ransomware Activity Detected — LockBit 3.0",
            "description": "EDR detected mass file encryption matching LockBit 3.0 ransomware pattern on WORKSTATION-042. 847 files encrypted in 3 minutes. Ransom note dropped to desktop.",
            "source": "CrowdStrike Falcon",
            "source_ref": "CS-2024-88421",
            "severity": SeverityLevel.CRITICAL,
            "status": AlertStatus.ESCALATED,
            "category": ThreatCategory.RANSOMWARE,
            "affected_host": "WORKSTATION-042",
            "affected_user": "jsmith@company.com",
            "source_ip": "192.168.1.42",
            "dest_ip": "185.220.101.47",
            "risk_score": 98.5,
            "mitre_tactics": ["TA0040", "TA0010"],
            "mitre_techniques": ["T1486", "T1041"],
            "tags": ["ransomware", "critical", "lockbit", "auto-escalated"],
            "raw_data": {"process": "explorer.exe", "file_count": 847, "ransom_note": "README.lockbit", "extension": ".lockbit3"},
            "enrichment_data": {"ip_reputation": "malicious", "confidence": 0.97, "known_c2": True, "threat_actor": "LockBit Group"},
            "created_at": now - timedelta(hours=2),
        },
        {
            "id": "alert-002",
            "title": "Phishing Campaign — Credential Harvesting via Fake O365",
            "description": "Multiple employees received phishing emails impersonating Microsoft O365 login pages. 3 users clicked the link. Email gateway flagged 47 similar messages.",
            "source": "Proofpoint TAP",
            "source_ref": "PP-2024-15883",
            "severity": SeverityLevel.HIGH,
            "status": AlertStatus.ACKNOWLEDGED,
            "category": ThreatCategory.PHISHING,
            "affected_host": "MAIL-SERVER-01",
            "affected_user": "multiple",
            "source_ip": "45.142.212.100",
            "dest_ip": "10.0.0.25",
            "risk_score": 82.0,
            "mitre_tactics": ["TA0001", "TA0006"],
            "mitre_techniques": ["T1566", "T1078"],
            "tags": ["phishing", "o365", "credential-theft"],
            "raw_data": {"email_count": 47, "clicked_count": 3, "sender": "noreply@secure-login-alert.com"},
            "enrichment_data": {"domain_age_days": 3, "ssl_cert": "self-signed", "redirect_chain": 4},
            "created_at": now - timedelta(hours=5),
        },
        {
            "id": "alert-003",
            "title": "Brute Force Attack on RDP — 2,847 Failed Attempts",
            "description": "Sustained brute force attack targeting RDP service on SERVER-DC-01. 2,847 failed authentication attempts from single external IP in 15 minutes.",
            "source": "Splunk SIEM",
            "source_ref": "SPL-2024-99012",
            "severity": SeverityLevel.HIGH,
            "status": AlertStatus.NEW,
            "category": ThreatCategory.BRUTE_FORCE,
            "affected_host": "SERVER-DC-01",
            "affected_user": "administrator",
            "source_ip": "45.142.212.100",
            "dest_ip": "10.0.0.1",
            "risk_score": 75.0,
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"],
            "tags": ["brute-force", "rdp", "windows-auth"],
            "raw_data": {"attempt_count": 2847, "duration_minutes": 15, "protocol": "RDP", "port": 3389},
            "enrichment_data": {"geo": "Russia", "asn": "AS62282", "tor_exit": False},
            "created_at": now - timedelta(hours=1),
        },
        {
            "id": "alert-004",
            "title": "Suspicious Data Transfer — 4.2GB to External IP",
            "description": "Anomalous outbound transfer of 4.2GB detected from internal file server to unknown external IP. Transfer occurred outside business hours at 02:14 AM.",
            "source": "Darktrace",
            "source_ref": "DT-2024-77123",
            "severity": SeverityLevel.CRITICAL,
            "status": AlertStatus.ESCALATED,
            "category": ThreatCategory.DATA_EXFIL,
            "affected_host": "FILE-SERVER-03",
            "affected_user": "svc_backup",
            "source_ip": "10.0.0.30",
            "dest_ip": "45.142.212.100",
            "risk_score": 94.0,
            "mitre_tactics": ["TA0010"],
            "mitre_techniques": ["T1048", "T1041"],
            "tags": ["data-exfil", "after-hours", "large-transfer"],
            "raw_data": {"bytes_transferred": 4509715456, "duration_seconds": 847, "protocol": "HTTPS", "port": 443},
            "enrichment_data": {"dest_country": "Unknown", "dest_asn": "AS62282", "data_type_guess": "Archive files"},
            "created_at": now - timedelta(hours=8),
        },
        {
            "id": "alert-005",
            "title": "Malware Detected — Trojan.GenericKD",
            "description": "Antivirus detected Trojan.GenericKD.47892341 in email attachment opened by finance department user. Malware family associated with banking credential theft.",
            "source": "Microsoft Defender",
            "source_ref": "MSD-2024-34561",
            "severity": SeverityLevel.HIGH,
            "status": AlertStatus.NEW,
            "category": ThreatCategory.MALWARE,
            "affected_host": "FINANCE-WS-07",
            "affected_user": "mwilson@company.com",
            "source_ip": "192.168.5.17",
            "dest_ip": "185.220.101.47",
            "risk_score": 88.0,
            "mitre_tactics": ["TA0002", "TA0006"],
            "mitre_techniques": ["T1059", "T1005"],
            "tags": ["malware", "trojan", "banking", "finance-dept"],
            "raw_data": {"file": "invoice_2024.pdf.exe", "hash": "e17a8a4e76a56a839c45bb6b29b18bca", "detection": "Trojan.GenericKD.47892341"},
            "enrichment_data": {"vt_detections": 54, "vt_total": 72, "first_seen": "2024-01-15", "malware_family": "Dridex"},
            "created_at": now - timedelta(minutes=45),
        },
        {
            "id": "alert-006",
            "title": "Lateral Movement — Pass-the-Hash Attack",
            "description": "Security monitoring detected pass-the-hash authentication pattern. Compromised NTLM hash used to authenticate to 8 internal systems within 20 minutes.",
            "source": "Microsoft Defender for Identity",
            "source_ref": "MDI-2024-21098",
            "severity": SeverityLevel.CRITICAL,
            "status": AlertStatus.NEW,
            "category": ThreatCategory.LATERAL_MOVE,
            "affected_host": "WORKSTATION-019",
            "affected_user": "admin.svc",
            "source_ip": "192.168.2.19",
            "dest_ip": "10.0.0.1",
            "risk_score": 96.0,
            "mitre_tactics": ["TA0008", "TA0006"],
            "mitre_techniques": ["T1550.002", "T1021"],
            "tags": ["lateral-movement", "pass-the-hash", "privilege"],
            "raw_data": {"systems_accessed": 8, "hash_type": "NTLM", "timeframe_minutes": 20},
            "enrichment_data": {"account_type": "service_account", "last_password_change": "2022-03-01"},
            "created_at": now - timedelta(minutes=20),
        },
        {
            "id": "alert-007",
            "title": "Privilege Escalation via UAC Bypass",
            "description": "EDR detected UAC bypass technique (T1548.002) executed by unprivileged user process. Process now running with SYSTEM privileges.",
            "source": "CrowdStrike Falcon",
            "source_ref": "CS-2024-55678",
            "severity": SeverityLevel.HIGH,
            "status": AlertStatus.ACKNOWLEDGED,
            "category": ThreatCategory.PRIVILEGE_ESC,
            "affected_host": "WORKSTATION-033",
            "affected_user": "bthompson@company.com",
            "source_ip": "192.168.3.33",
            "dest_ip": None,
            "risk_score": 79.0,
            "mitre_tactics": ["TA0004"],
            "mitre_techniques": ["T1548.002"],
            "tags": ["privilege-escalation", "uac-bypass", "windows"],
            "raw_data": {"process": "cmd.exe", "parent": "winword.exe", "privilege": "SYSTEM"},
            "enrichment_data": {"uac_level": "default", "user_role": "standard"},
            "created_at": now - timedelta(hours=3),
        },
        {
            "id": "alert-008",
            "title": "Reconnaissance — Internal Network Scan",
            "description": "Internal host initiated network scan of entire /16 subnet. 65,535 hosts scanned using Nmap-like pattern. Likely post-compromise reconnaissance.",
            "source": "Splunk SIEM",
            "source_ref": "SPL-2024-66789",
            "severity": SeverityLevel.MEDIUM,
            "status": AlertStatus.NEW,
            "category": ThreatCategory.RECON,
            "affected_host": "WORKSTATION-055",
            "affected_user": "dlee@company.com",
            "source_ip": "192.168.4.55",
            "dest_ip": "192.168.0.0/16",
            "risk_score": 62.0,
            "mitre_tactics": ["TA0007"],
            "mitre_techniques": ["T1046"],
            "tags": ["recon", "network-scan", "internal"],
            "raw_data": {"scan_type": "SYN", "ports_scanned": [22, 80, 443, 3389, 445], "hosts_scanned": 65535},
            "enrichment_data": {"tool_signature": "nmap", "previous_alerts": 0},
            "created_at": now - timedelta(hours=6),
        },
    ]

    incidents_data = [
        {
            "id": "inc-001",
            "title": "CRITICAL: LockBit 3.0 Ransomware Active on WORKSTATION-042",
            "description": "Active ransomware infection detected and contained on WORKSTATION-042. LockBit 3.0 variant confirmed by EDR and threat intel enrichment. Host isolated, forensics collected.",
            "severity": SeverityLevel.CRITICAL,
            "status": IncidentStatus.INVESTIGATING,
            "category": ThreatCategory.RANSOMWARE,
            "alert_id": "alert-001",
            "assigned_to": "Sarah Chen",
            "risk_score": 98.5,
            "affected_assets": ["WORKSTATION-042", "jsmith@company.com"],
            "iocs": [
                {"type": "ip", "value": "185.220.101.47", "context": "C2 server"},
                {"type": "hash", "value": "e17a8a4e76a56a839c45bb6b29b18bca", "context": "LockBit payload"},
                {"type": "domain", "value": "update-security.net", "context": "initial delivery"},
                {"type": "file", "value": "README.lockbit", "context": "ransom note"},
            ],
            "mitre_tactics": ["TA0040", "TA0010", "TA0002"],
            "mitre_techniques": ["T1486", "T1041", "T1059"],
            "tags": ["ransomware", "critical", "lockbit", "p1"],
            "timeline": [
                {"time": (now - timedelta(hours=2, minutes=30)).isoformat(), "event": "Initial access via phishing email attachment", "actor": "system"},
                {"time": (now - timedelta(hours=2, minutes=15)).isoformat(), "event": "Malicious macro executed in Word document", "actor": "system"},
                {"time": (now - timedelta(hours=2)).isoformat(), "event": "CrowdStrike Falcon detected ransomware activity", "actor": "CrowdStrike"},
                {"time": (now - timedelta(hours=1, minutes=55)).isoformat(), "event": "Alert auto-escalated to incident", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=1, minutes=50)).isoformat(), "event": "Ransomware Response playbook triggered automatically", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=1, minutes=45)).isoformat(), "event": "Threat intel enrichment completed — LockBit 3.0 confirmed", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=1, minutes=40)).isoformat(), "event": "Host WORKSTATION-042 isolated from network", "actor": "SENTINEL-X (simulated)"},
                {"time": (now - timedelta(hours=1, minutes=20)).isoformat(), "event": "Forensic artifacts collected and stored", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=1)).isoformat(), "event": "Lateral movement check completed — no spread detected", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(minutes=45)).isoformat(), "event": "Incident assigned to Sarah Chen for analyst review", "actor": "system"},
            ],
            "notes": "Awaiting analyst review of forensic artifacts. Host remains isolated. IT preparing clean image restore. No evidence of lateral movement or data exfiltration at this time.",
            "created_at": now - timedelta(hours=2),
        },
        {
            "id": "inc-002",
            "title": "HIGH: O365 Phishing Campaign — 3 Users Compromised",
            "description": "Coordinated phishing campaign targeting O365 credentials. 47 emails delivered, 3 users clicked malicious links. Password reset enforced for affected accounts.",
            "severity": SeverityLevel.HIGH,
            "status": IncidentStatus.CONTAINED,
            "category": ThreatCategory.PHISHING,
            "alert_id": "alert-002",
            "assigned_to": "Marcus Rivera",
            "risk_score": 82.0,
            "affected_assets": ["MAIL-SERVER-01", "jdoe@company.com", "asmith@company.com", "kpatel@company.com"],
            "iocs": [
                {"type": "domain", "value": "docs-sharepoint-portal.com", "context": "phishing domain"},
                {"type": "email", "value": "phishing@secure-login-alert.com", "context": "sender"},
                {"type": "url", "value": "http://docs-sharepoint-portal.com/login", "context": "credential harvest page"},
            ],
            "mitre_tactics": ["TA0001", "TA0006"],
            "mitre_techniques": ["T1566", "T1078"],
            "tags": ["phishing", "o365", "user-training-needed"],
            "timeline": [
                {"time": (now - timedelta(hours=5, minutes=30)).isoformat(), "event": "Phishing emails delivered to 47 mailboxes", "actor": "attacker"},
                {"time": (now - timedelta(hours=5)).isoformat(), "event": "Proofpoint TAP alert triggered", "actor": "Proofpoint"},
                {"time": (now - timedelta(hours=4, minutes=50)).isoformat(), "event": "3 users clicked phishing link", "actor": "users"},
                {"time": (now - timedelta(hours=4, minutes=45)).isoformat(), "event": "Phishing Investigation playbook executed", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=4, minutes=30)).isoformat(), "event": "Malicious URLs blocked at email gateway", "actor": "SENTINEL-X (simulated)"},
                {"time": (now - timedelta(hours=4)).isoformat(), "event": "Affected user credentials reset", "actor": "Marcus Rivera"},
                {"time": (now - timedelta(hours=3)).isoformat(), "event": "Security awareness notification sent to all staff", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=2)).isoformat(), "event": "Incident status updated to Contained", "actor": "Marcus Rivera"},
            ],
            "notes": "Three affected users had passwords reset. MFA re-enrollment enforced. Email block rule created for sender domain. Security awareness training scheduled.",
            "created_at": now - timedelta(hours=5),
        },
        {
            "id": "inc-003",
            "title": "CRITICAL: Suspected Data Exfiltration — Finance Server",
            "description": "4.2GB of data transferred from finance file server to unknown external IP during off-hours. Data classification in progress. Legal team notified.",
            "severity": SeverityLevel.CRITICAL,
            "status": IncidentStatus.INVESTIGATING,
            "category": ThreatCategory.DATA_EXFIL,
            "alert_id": "alert-004",
            "assigned_to": "Elena Vasquez",
            "risk_score": 94.0,
            "affected_assets": ["FILE-SERVER-03", "svc_backup", "Finance Department"],
            "iocs": [
                {"type": "ip", "value": "45.142.212.100", "context": "exfiltration destination"},
                {"type": "user", "value": "svc_backup", "context": "compromised service account"},
            ],
            "mitre_tactics": ["TA0010"],
            "mitre_techniques": ["T1048", "T1041"],
            "tags": ["data-exfil", "finance", "regulatory-concern", "p1"],
            "timeline": [
                {"time": (now - timedelta(hours=8, minutes=14)).isoformat(), "event": "Data transfer initiated from FILE-SERVER-03", "actor": "svc_backup"},
                {"time": (now - timedelta(hours=7, minutes=55)).isoformat(), "event": "Darktrace anomaly detection triggered", "actor": "Darktrace"},
                {"time": (now - timedelta(hours=7, minutes=50)).isoformat(), "event": "Alert escalated to incident", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=7, minutes=45)).isoformat(), "event": "Data Exfiltration playbook triggered", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=7, minutes=30)).isoformat(), "event": "Active connection terminated", "actor": "SENTINEL-X (simulated)"},
                {"time": (now - timedelta(hours=7)).isoformat(), "event": "Legal and compliance team notified", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=6)).isoformat(), "event": "Incident assigned to Elena Vasquez", "actor": "system"},
                {"time": (now - timedelta(hours=4)).isoformat(), "event": "Data classification assessment started", "actor": "Elena Vasquez"},
            ],
            "notes": "Service account svc_backup credentials appear compromised. Forensic investigation ongoing to determine initial access vector. Regulatory notification may be required if PII confirmed.",
            "created_at": now - timedelta(hours=8),
        },
        {
            "id": "inc-004",
            "title": "HIGH: Brute Force Attack on Domain Controller",
            "description": "Sustained brute force attack on SERVER-DC-01. Attacker IP blocked. No successful authentications confirmed. Monitoring continues.",
            "severity": SeverityLevel.HIGH,
            "status": IncidentStatus.RESOLVED,
            "category": ThreatCategory.BRUTE_FORCE,
            "alert_id": "alert-003",
            "assigned_to": "James Park",
            "risk_score": 75.0,
            "affected_assets": ["SERVER-DC-01"],
            "iocs": [
                {"type": "ip", "value": "45.142.212.100", "context": "attacker source IP"},
            ],
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"],
            "tags": ["brute-force", "rdp", "resolved"],
            "timeline": [
                {"time": (now - timedelta(hours=3, minutes=30)).isoformat(), "event": "Brute force attack commenced on SERVER-DC-01:3389", "actor": "attacker"},
                {"time": (now - timedelta(hours=3, minutes=15)).isoformat(), "event": "SIEM alert triggered after 500 failed attempts", "actor": "Splunk"},
                {"time": (now - timedelta(hours=3)).isoformat(), "event": "Brute Force playbook auto-executed", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(hours=2, minutes=55)).isoformat(), "event": "Source IP 45.142.212.100 blocked at perimeter firewall", "actor": "SENTINEL-X (simulated)"},
                {"time": (now - timedelta(hours=2, minutes=50)).isoformat(), "event": "All targeted accounts locked and MFA enforced", "actor": "SENTINEL-X (simulated)"},
                {"time": (now - timedelta(hours=2, minutes=30)).isoformat(), "event": "Confirmed no successful authentication achieved", "actor": "James Park"},
                {"time": (now - timedelta(hours=2)).isoformat(), "event": "Incident resolved — attack fully blocked", "actor": "James Park"},
            ],
            "notes": "Attack blocked before any successful authentication. Attacker IP added to permanent blocklist. RDP access restricted to VPN-only going forward.",
            "resolution_summary": "Brute force attack successfully blocked. No compromise achieved. Firewall rules updated and RDP access policy hardened.",
            "created_at": now - timedelta(hours=3),
            "resolved_at": now - timedelta(hours=2),
        },
        {
            "id": "inc-005",
            "title": "CRITICAL: Pass-the-Hash Lateral Movement Detected",
            "description": "Service account hash compromised and used for lateral movement across 8 internal systems. Immediate credential reset and investigation required.",
            "severity": SeverityLevel.CRITICAL,
            "status": IncidentStatus.TRIAGING,
            "category": ThreatCategory.LATERAL_MOVE,
            "alert_id": "alert-006",
            "assigned_to": None,
            "risk_score": 96.0,
            "affected_assets": ["WORKSTATION-019", "admin.svc", "8 internal systems"],
            "iocs": [
                {"type": "ip", "value": "192.168.2.19", "context": "compromised host"},
                {"type": "user", "value": "admin.svc", "context": "compromised service account"},
            ],
            "mitre_tactics": ["TA0008", "TA0006"],
            "mitre_techniques": ["T1550.002", "T1021"],
            "tags": ["lateral-movement", "urgent", "unassigned"],
            "timeline": [
                {"time": (now - timedelta(minutes=25)).isoformat(), "event": "Pass-the-hash lateral movement pattern detected", "actor": "Microsoft Defender for Identity"},
                {"time": (now - timedelta(minutes=20)).isoformat(), "event": "Alert created and escalated to incident", "actor": "SENTINEL-X"},
                {"time": (now - timedelta(minutes=15)).isoformat(), "event": "Automated triage initiated", "actor": "SENTINEL-X"},
            ],
            "notes": "Incident requires immediate analyst assignment. Service account admin.svc appears compromised. High risk of further spread.",
            "created_at": now - timedelta(minutes=20),
        },
    ]

    for a_data in alerts_data:
        alert = Alert(**{k: v for k, v in a_data.items()})
        db.add(alert)

    for i_data in incidents_data:
        inc = Incident(**{k: v for k, v in i_data.items() if k != "resolved_at"})
        if "resolved_at" in i_data:
            inc.resolved_at = i_data["resolved_at"]
        db.add(inc)

    # Add historical playbook executions
    executions = [
        {
            "id": "exec-001",
            "playbook_id": "pb-ransomware-response",
            "incident_id": "inc-001",
            "alert_id": "alert-001",
            "status": ExecutionStatus.RUNNING,
            "triggered_by": "auto",
            "current_step": 6,
            "total_steps": 9,
            "execution_time": None,
            "step_results": [
                {"step_id": "s1", "name": "Alert Triage", "status": "success", "duration": 2.1, "output": {"severity": "critical", "confidence": 0.98, "auto_escalated": True}, "timestamp": (now - timedelta(hours=1, minutes=50)).isoformat()},
                {"step_id": "s2", "name": "Threat Intel Lookup", "status": "success", "duration": 8.3, "output": {"iocs_found": 3, "malicious": 2, "threat_actor": "LockBit Group"}, "timestamp": (now - timedelta(hours=1, minutes=45)).isoformat()},
                {"step_id": "s3", "name": "Host Isolation", "status": "success", "duration": 3.7, "output": {"host": "WORKSTATION-042", "isolated": True, "method": "EDR (simulated)"}, "timestamp": (now - timedelta(hours=1, minutes=40)).isoformat(), "simulated": True},
                {"step_id": "s4", "name": "Evidence Collection", "status": "success", "duration": 45.2, "output": {"files_collected": 127, "processes": 89, "connections": 14}, "timestamp": (now - timedelta(hours=1, minutes=20)).isoformat()},
                {"step_id": "s5", "name": "Lateral Movement Check", "status": "success", "duration": 38.6, "output": {"endpoints_scanned": 156, "spread_detected": False}, "timestamp": (now - timedelta(hours=1)).isoformat()},
                {"step_id": "s6", "name": "Stakeholder Notification", "status": "success", "duration": 1.8, "output": {"recipients": ["ciso@company.com", "it-manager@company.com"], "delivered": 2}, "timestamp": (now - timedelta(minutes=55)).isoformat()},
            ],
            "context": {"alert_id": "alert-001", "severity": "critical", "category": "ransomware"},
            "started_at": now - timedelta(hours=1, minutes=50),
        },
        {
            "id": "exec-002",
            "playbook_id": "pb-phishing-investigation",
            "incident_id": "inc-002",
            "alert_id": "alert-002",
            "status": ExecutionStatus.SUCCESS,
            "triggered_by": "auto",
            "current_step": 8,
            "total_steps": 8,
            "execution_time": 87.4,
            "step_results": [
                {"step_id": "s1", "name": "Header Analysis", "status": "success", "duration": 4.2, "output": {"spf_fail": True, "dkim_fail": True, "spoofed": True}, "timestamp": (now - timedelta(hours=4, minutes=45)).isoformat()},
                {"step_id": "s2", "name": "URL Sandboxing", "status": "success", "duration": 28.5, "output": {"urls_detonated": 3, "malicious": 3, "phishing_confirmed": True}, "timestamp": (now - timedelta(hours=4, minutes=40)).isoformat()},
                {"step_id": "s3", "name": "Attachment Analysis", "status": "success", "duration": 15.3, "output": {"attachments": 0, "malicious": 0}, "timestamp": (now - timedelta(hours=4, minutes=35)).isoformat()},
                {"step_id": "s4", "name": "Credential Exposure Check", "status": "success", "duration": 6.7, "output": {"exposed_accounts": 3, "breach_databases": 2}, "timestamp": (now - timedelta(hours=4, minutes=30)).isoformat()},
                {"step_id": "s5", "name": "User Notification", "status": "success", "duration": 2.1, "output": {"notified": 47, "delivery_rate": "100%"}, "timestamp": (now - timedelta(hours=4, minutes=25)).isoformat()},
                {"step_id": "s6", "name": "Email Block Rule", "status": "success", "duration": 1.5, "output": {"rule_created": True, "blocked_domain": "secure-login-alert.com"}, "timestamp": (now - timedelta(hours=4, minutes=20)).isoformat(), "simulated": True},
                {"step_id": "s7", "name": "IOC Distribution", "status": "success", "duration": 3.8, "output": {"iocs_pushed": 5, "controls_updated": 4}, "timestamp": (now - timedelta(hours=4, minutes=15)).isoformat()},
                {"step_id": "s8", "name": "Report Generation", "status": "success", "duration": 12.1, "output": {"report_id": "rpt-phish-002", "pages": 8}, "timestamp": (now - timedelta(hours=4, minutes=10)).isoformat()},
            ],
            "context": {"alert_id": "alert-002", "severity": "high", "category": "phishing"},
            "started_at": now - timedelta(hours=4, minutes=45),
            "completed_at": now - timedelta(hours=4, minutes=10),
        },
    ]

    for e_data in executions:
        exec_obj = PlaybookExecution(
            id=e_data["id"],
            playbook_id=e_data["playbook_id"],
            incident_id=e_data["incident_id"],
            alert_id=e_data["alert_id"],
            status=e_data["status"],
            triggered_by=e_data["triggered_by"],
            current_step=e_data["current_step"],
            total_steps=e_data["total_steps"],
            execution_time=e_data["execution_time"],
            step_results=e_data["step_results"],
            context=e_data["context"],
            started_at=e_data["started_at"],
            completed_at=e_data.get("completed_at"),
        )
        db.add(exec_obj)


# ─────────────────────── Metrics ───────────────────────

def _seed_metrics(db: Session):
    now = datetime.utcnow()
    random.seed(42)
    for i in range(30):
        day = now - timedelta(days=29 - i)
        for metric_type, base, variance in [
            ("daily_alerts", 23, 15),
            ("mttd_minutes", 18, 12),
            ("mttr_hours", 4.2, 2.5),
            ("false_positive_rate", 8.5, 4),
            ("playbook_executions", 31, 20),
        ]:
            db.add(MetricSnapshot(
                id=str(uuid.uuid4()),
                timestamp=day,
                metric_type=metric_type,
                value=max(0, base + random.gauss(0, variance)),
                labels={"day": day.strftime("%Y-%m-%d")}
            ))


# ─────────────────────── Audit Logs ───────────────────────

def _seed_audit_logs(db: Session):
    now = datetime.utcnow()
    logs = [
        ("SENTINEL-X", "incident.created", "incident", "inc-001", "CRITICAL: LockBit 3.0 Ransomware", "info", now - timedelta(hours=2)),
        ("SENTINEL-X", "playbook.triggered", "playbook_execution", "exec-001", "Ransomware Response", "info", now - timedelta(hours=1, minutes=50)),
        ("SENTINEL-X", "host.isolated", "host", "WORKSTATION-042", "WORKSTATION-042", "warning", now - timedelta(hours=1, minutes=40)),
        ("Sarah Chen", "incident.assigned", "incident", "inc-001", "CRITICAL: LockBit 3.0 Ransomware", "info", now - timedelta(minutes=45)),
        ("SENTINEL-X", "incident.created", "incident", "inc-002", "HIGH: O365 Phishing Campaign", "info", now - timedelta(hours=5)),
        ("SENTINEL-X", "playbook.triggered", "playbook_execution", "exec-002", "Phishing Email Investigation", "info", now - timedelta(hours=4, minutes=45)),
        ("Marcus Rivera", "incident.status_changed", "incident", "inc-002", "HIGH: O365 Phishing Campaign", "info", now - timedelta(hours=2)),
        ("SENTINEL-X", "alert.escalated", "alert", "alert-006", "Pass-the-Hash Lateral Movement", "warning", now - timedelta(minutes=20)),
        ("SENTINEL-X", "incident.created", "incident", "inc-005", "CRITICAL: Pass-the-Hash Lateral Movement", "warning", now - timedelta(minutes=20)),
        ("admin", "user.login", "session", "sess-001", "admin", "info", now - timedelta(hours=1)),
        ("Sarah Chen", "incident.notes_updated", "incident", "inc-001", "CRITICAL: LockBit 3.0 Ransomware", "info", now - timedelta(minutes=30)),
        ("SENTINEL-X", "ip.blocked", "firewall_rule", "rule-001", "45.142.212.100", "warning", now - timedelta(hours=3)),
    ]

    for actor, action, resource_type, resource_id, resource_name, severity, ts in logs:
        db.add(AuditLog(
            id=str(uuid.uuid4()),
            timestamp=ts,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            details={"auto_seeded": True},
            ip_address="10.0.0.1",
            session_id="sess-001",
            severity=severity,
        ))
