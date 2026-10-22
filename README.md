# SENTINEL-X — Intelligent SOAR Platform

> **Intelligent Security Orchestration, Automation and Response**
>
> A complete, production-inspired cybersecurity platform demonstrating automated incident response, threat intelligence enrichment, and playbook-driven security operations.

---

## Overview

SENTINEL-X is a full-stack SOAR (Security Orchestration, Automation and Response) platform built for university showcase, portfolio demonstration, and technical evaluation. It implements the complete security incident lifecycle:

```
Alert Ingestion → Normalization → Threat Intel Enrichment → Risk Scoring
     → Playbook Selection → Automated Response → Analyst Review
          → Incident Resolution → Audit & Reporting
```

The platform ships with **realistic simulated data**, **5 pre-built response playbooks**, and a **live demo mode** that triggers a full incident + playbook execution you can watch in real time.

---

## Architecture

```
sentinel_x/
├── __init__.py
├── main.py          # FastAPI app, API routes, WebSocket
├── models.py        # SQLAlchemy ORM models
├── database.py      # DB init, SessionLocal, seed data
├── engine.py        # SOAR playbook execution engine
└── static/
    └── index.html   # Complete SPA frontend (no build step)

run.py               # Application entry point
sentinel_x.db        # SQLite database (auto-created)
```

**Backend:** Python 3.13 · FastAPI · SQLAlchemy · SQLite · WebSockets

**Frontend:** Single-file SPA · Pure HTML/CSS/JavaScript · No build step required

---

## Quick Start

### Requirements
- Python 3.10+
- pip

### Setup & Run

```bash
# 1. Install dependencies (if not already done)
pip install fastapi "uvicorn[standard]" sqlalchemy pydantic python-multipart

# 2. Start the application
python run.py
```

The server starts at **http://localhost:8000**

The database is automatically created and seeded with demo data on first run.

### Alternative (uvicorn direct)
```bash
python -m uvicorn sentinel_x.main:app --host 0.0.0.0 --port 8000
```

---

## Features

### 🚨 Incident Management
- Full incident lifecycle tracking (New → Triaging → Investigating → Contained → Resolved)
- Risk scoring (0–100), severity classification, MITRE ATT&CK mapping
- Analyst assignment, timeline tracking, IOC management
- Filter by status, severity, category

### ⚠️ Alert Feed
- Multi-source alert ingestion (manual + simulated feeds)
- One-click escalation to incident
- Alert enrichment with threat intelligence data
- Acknowledge / Escalate / Suppress workflows

### ▶️ SOAR Playbooks
- 5 pre-built playbooks: Ransomware Response, Phishing Investigation, Brute Force Response, Data Exfiltration, Malware Triage
- Visual workflow flow viewer
- Step-by-step execution with live progress via WebSocket
- Per-step output logging, timing, and simulation markers

### ⚙️ Playbook Execution Engine
- Async execution engine with realistic step simulation
- Live progress updates via WebSocket
- Simulated containment actions (clearly labeled — no real system changes)
- Auto-trigger on incident creation
- Execution reports with summary and recommendations

### 🔍 Threat Intelligence
- IOC database (IP, domain, hash, URL, email)
- Real-time IOC lookup
- Reputation scoring with confidence levels
- Source attribution (VirusTotal, CrowdStrike, etc.)

### 📋 Audit Trail
- Complete action log for all system and analyst actions
- Severity-filtered view (Info / Warning / Critical)
- Actor tracking (SENTINEL-X system vs. analysts)

### 📊 Dashboard
- Live KPI metrics: critical incidents, MTTR, alert volume, playbook success rate
- 30-day alert volume chart
- Incident category donut chart
- Recent incidents table
- Playbook activity panel

---

## Demo Walkthrough

### Live Demo (Recommended)

1. Open **http://localhost:8000**
2. Click **⚡ Run Demo** in the top-right corner
3. This will:
   - Create a new alert from a random threat scenario
   - Automatically create a linked incident
   - Auto-trigger the appropriate response playbook
   - Show live step execution in the progress panel
4. Navigate to **Incidents** to see the new incident
5. Navigate to **Executions** to watch the playbook run in real time
6. Click any execution to see step-by-step results and output

### Manual Exploration

| Page | Key Actions |
|------|------------|
| Dashboard | View live metrics, click incidents in the table |
| Incidents | Click any row → Tabs: Overview / Timeline / IOCs / Playbooks / Notes |
| Incidents | Use the **▶** button to run a matching playbook on an incident |
| Alerts | Click "Escalate" to promote an alert to a full incident |
| Alerts | Click "+ Ingest Alert" to create a new manual alert |
| Playbooks | Click any playbook card → "Execute Now" to run it |
| Executions | Click any row for step-by-step output with JSON results |
| Threat Intel | Enter IOCs in the lookup form (see quick reference on the page) |
| Audit Trail | Review complete system action log |

### IOC Quick Lookups

| IOC | Expected Result |
|-----|----------------|
| `185.220.101.47` | Malicious — Tor exit / Botnet C2 |
| `malware-delivery.xyz` | Malicious — Phishing / Malware |
| `e17a8a4e76a56a839c45bb6b29b18bca` | Malicious — Ransomware (LockBit) |
| `phishing@secure-login-alert.com` | Malicious — Credential harvest |
| `d41d8cd98f00b204e9800998ecf8427e` | Clean — Empty file MD5 |

---

## API Reference

Interactive API documentation available at: **http://localhost:8000/docs**

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Dashboard KPI metrics |
| GET | `/api/incidents` | List incidents (filters: status, severity, category) |
| GET | `/api/incidents/{id}` | Incident detail with executions |
| PATCH | `/api/incidents/{id}` | Update status, assignee, notes |
| GET | `/api/alerts` | List alerts |
| POST | `/api/alerts` | Ingest new alert |
| POST | `/api/alerts/{id}/escalate` | Escalate alert to incident |
| GET | `/api/playbooks` | List playbooks |
| POST | `/api/executions` | Trigger playbook execution |
| GET | `/api/executions/{id}` | Execution detail with step results |
| POST | `/api/threat-intel/lookup` | IOC reputation lookup |
| GET | `/api/audit` | Audit log |
| POST | `/api/demo/trigger-incident` | Trigger live demo scenario |
| WS | `/ws` | WebSocket for live execution updates |

---

## Pre-Seeded Data

On first run, the database is populated with:

**Incidents (5):**
- CRITICAL: LockBit 3.0 Ransomware — Investigating
- HIGH: O365 Phishing Campaign — Contained
- CRITICAL: Data Exfiltration (Finance) — Investigating
- HIGH: Brute Force on Domain Controller — Resolved
- CRITICAL: Pass-the-Hash Lateral Movement — Triaging

**Alerts (8):** Ransomware, Phishing, Brute Force, Data Exfil, Malware, Lateral Movement, Privilege Escalation, Recon

**Playbooks (5):** Ransomware Response, Phishing Investigation, Brute Force Response, Data Exfiltration, Malware Triage

**Threat Intel (13 IOCs):** Malicious IPs, domains, hashes, email addresses

**Metrics:** 30 days of simulated metric history (alert volume, MTTR, MTTD)

---

## Design Principles

### Simulated vs. Real Actions
All containment, isolation, blocking, and remediation actions are **clearly marked as SIMULATED**. The platform:
- Never makes actual network changes
- Never modifies real firewall rules
- Never locks real accounts
- Clearly labels every simulated action in the UI, step output, and execution reports

This makes the platform safe to demonstrate in any environment.

### Architecture Decisions
- **Single-file frontend**: No Node.js or build tools required. The entire frontend is a ~1000-line HTML file served directly by FastAPI.
- **Async execution engine**: Playbook steps run asynchronously, allowing realistic timing without blocking the API.
- **WebSocket updates**: Real-time step progress, completion events, and incident updates pushed to all connected clients.
- **SQLite with WAL mode**: Concurrent read/write performance sufficient for demo loads, with easy migration path to PostgreSQL.

---

## Troubleshooting

**Port 8000 already in use:**
```bash
python -m uvicorn sentinel_x.main:app --port 8001
```

**Database issues (re-seed):**
```bash
del sentinel_x.db  # Windows
python run.py
```

**Dependencies not found:**
```bash
pip install --user fastapi "uvicorn[standard]" sqlalchemy pydantic python-multipart
```

**WebSocket not connecting:** The live indicator in the sidebar will show "Reconnecting..." — this is cosmetic and the application works fully without WebSocket. Auto-reconnect will retry every 3 seconds.

---

## Limitations

- **No real threat intelligence APIs**: IOC lookups use the local seeded database only. No VirusTotal/Shodan/OTX API keys required.
- **Simulated actions only**: No actual EDR, SIEM, or firewall integrations. All containment is clearly simulated.
- **Single-user**: No authentication, multi-user roles, or session management. Suitable for demo, not production.
- **SQLite**: Suitable for demos up to ~100 concurrent users. Production would require PostgreSQL.
- **No email notifications**: Notification steps are simulated in the workflow engine.

---

## MITRE ATT&CK Coverage

The pre-seeded incidents and alerts map to the following ATT&CK tactics:

| Tactic | Incidents |
|--------|-----------|
| TA0001 — Initial Access | Phishing Campaign |
| TA0002 — Execution | Malware (Trojan) |
| TA0004 — Privilege Escalation | UAC Bypass |
| TA0006 — Credential Access | Brute Force, Pass-the-Hash |
| TA0007 — Discovery | Internal Network Scan |
| TA0008 — Lateral Movement | Pass-the-Hash |
| TA0010 — Exfiltration | Data Exfiltration |
| TA0040 — Impact | Ransomware |

---

*SENTINEL-X — Built with FastAPI · SQLAlchemy · Pure JavaScript*
*© 2024 — Competition & Portfolio Use*
