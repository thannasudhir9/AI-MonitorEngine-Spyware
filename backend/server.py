"""
AegisShield - FastAPI Server & Cyber SOC Dashboard Backend
Provides RESTful APIs, WebSockets telemetry, and serves the frontend dashboard.
"""

import os
import sys
import psutil
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .config import SERVER_HOST, SERVER_PORT, APP_ROOT, SCORE_MEDIUM
from .detector import ThreatDetector
from .remediator import ThreatRemediator
from .persistence_hunter import get_all_persistence_entries, disable_persistence_item
from .network_monitor import scan_network_connections
from .simulator import spawn_simulated_threat, stop_all_simulations
from .policy_engine import PolicyEngine
from .network_tracer import NetworkTracer
from .email_notifier import EmailNotifier
from .adblock_proxy import AdBlockProxyServer
from .web_traffic_logger import WebTrafficLogger
from .web_analytics import WebAnalytics
from .proxy_controller import ProxyController

app = FastAPI(title="AegisShield Cyber Threat & Process Monitor", version="2.0.0")

# Enable CORS for local access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

policy_engine = PolicyEngine()
detector = ThreatDetector()
detector.policy_engine = policy_engine
remediator = ThreatRemediator()
network_tracer = NetworkTracer()
email_notifier = EmailNotifier()

# AdBlock & Web Traffic Interception
adblock_proxy = AdBlockProxyServer(host="127.0.0.1", port=8080)
adblock_proxy.start()
web_traffic_logger = WebTrafficLogger()
web_analytics = WebAnalytics()
proxy_controller = ProxyController(proxy_host="127.0.0.1", proxy_port=8080)

FRONTEND_DIR = APP_ROOT / "frontend"


# Request Models
class KillRequest(BaseModel):
    pid: int
    force: bool = True
    reason: Optional[str] = "Manual Dashboard Eradication"


class KillAllRequest(BaseModel):
    min_score: int = SCORE_MEDIUM


class QuarantineRequest(BaseModel):
    file_path: str
    reason: Optional[str] = "Suspicious Executable"


class PersistenceDisableRequest(BaseModel):
    id: str
    target_path: str
    location_type: str


class SimulateRequest(BaseModel):
    type: str = "temp_trojan"


class PolicyRuleRequest(BaseModel):
    type: str  # 'name', 'path', 'hash', 'ip'
    value: str
    comment: Optional[str] = ""


class IPBlockRequest(BaseModel):
    ip: str
    comment: Optional[str] = ""
    apply_firewall: bool = True


class EmailConfigRequest(BaseModel):
    smtp_server: str
    smtp_port: int
    use_tls: bool = True
    sender_email: str
    sender_password: Optional[str] = ""
    recipient_email: str
    auto_email_on_critical: bool = False


class EmailSendReportRequest(BaseModel):
    recipient: Optional[str] = None


class TraceIPRequest(BaseModel):
    ip: str


class ProxyToggleRequest(BaseModel):
    enable: bool


# ==============================================================
# REST API Endpoints
# ==============================================================

@app.get("/api/status")
def get_system_status():
    """Retrieve overall system health, resource consumption, and detector metrics."""
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

    return {
        "status": "ONLINE",
        "timestamp": datetime.now().isoformat(),
        "cpu_percent": cpu_percent,
        "memory_percent": mem.percent,
        "memory_used_gb": round(mem.used / (1024 ** 3), 2),
        "memory_total_gb": round(mem.total / (1024 ** 3), 2),
        "platform": sys.platform,
        "process_count": len(psutil.pids())
    }


@app.get("/api/scan")
def run_scan(detailed: bool = False):
    """
    Execute full process scan across all active processes.
    Identifies threats, calculates scores, and returns categorized telemetry.
    """
    procs = detector.scan_all_processes(detailed_pe=detailed)

    threats = [p for p in procs if p.get("is_threat")]
    critical_threats = [p for p in threats if p.get("severity") == "CRITICAL"]
    high_threats = [p for p in threats if p.get("severity") == "HIGH"]
    rmm_tools = [p for p in procs if "REMOTE CONTROL" in p.get("primary_category", "") or any("Remote Desktop" in r.get("vector", "") for r in p.get("reasons", []))]

    # System Health Index (100 = safe, 0 = critical breach)
    threat_index = 100 - min(len(critical_threats) * 35 + len(high_threats) * 15, 100)

    # Auto-dispatch email alert if configured and critical threats exist
    if len(critical_threats) > 0 and email_notifier.get_config().get("auto_email_on_critical"):
        try:
            # Check if recently sent to prevent spamming (e.g. cooldown of 5 minutes)
            last_sent = email_notifier.get_config().get("last_sent")
            should_send = True
            if last_sent:
                dt_last = datetime.fromisoformat(last_sent)
                if (datetime.now() - dt_last).total_seconds() < 300:
                    should_send = False
            if should_send:
                asyncio.create_task(asyncio.to_thread(
                    email_notifier.send_email,
                    f"🚨 CRITICAL THREAT ALERT: {len(critical_threats)} Severe Threats Detected!",
                    email_notifier.generate_html_report({
                        "threats": threats,
                        "rmm_tools": rmm_tools,
                        "total_processes": len(procs),
                        "system_health_index": threat_index
                    })
                ))
        except Exception:
            pass

    return {
        "scan_time": datetime.now().isoformat(),
        "total_processes": len(procs),
        "total_threats": len(threats),
        "critical_count": len(critical_threats),
        "high_count": len(high_threats),
        "rmm_count": len(rmm_tools),
        "system_health_index": threat_index,
        "threats": threats,
        "rmm_tools": rmm_tools,
        "processes": procs
    }


@app.get("/api/process/{pid}")
def inspect_single_process(pid: int):
    """Deep inspect a single process with full PE analysis, sockets, and metadata."""
    if not psutil.pid_exists(pid):
        raise HTTPException(status_code=404, detail="Process not found")

    try:
        proc = psutil.Process(pid)
        analyzed = detector.evaluate_process(proc, detailed_pe=True)
        if not analyzed:
            raise HTTPException(status_code=404, detail="Process could not be analyzed")
        return analyzed
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/kill")
def kill_process(req: KillRequest):
    """Terminate a single process by PID."""
    result = remediator.kill_process(req.pid, force=req.force, reason=req.reason)
    return result


@app.post("/api/kill-tree")
def kill_process_tree(req: KillRequest):
    """Terminate a parent process and all child processes recursively."""
    result = remediator.kill_process_tree(req.pid, reason=req.reason)
    return result


@app.post("/api/kill-all-threats")
def kill_all_threats(req: KillAllRequest):
    """Emergency bulk kill for all detected threats exceeding threshold."""
    procs = detector.scan_all_processes(detailed_pe=False)
    threats = [p for p in procs if p.get("is_threat")]
    result = remediator.kill_all_threats(threats, min_score=req.min_score)
    return result


@app.post("/api/quarantine")
def quarantine_binary(req: QuarantineRequest):
    """Quarantine a suspicious executable file."""
    result = remediator.quarantine_file(req.file_path, reason=req.reason)
    return result


@app.get("/api/rmm")
def get_rmm_overview():
    """Retrieve dedicated overview of remote desktop & RMM tools and sockets."""
    procs = detector.scan_all_processes(detailed_pe=False)
    rmm_procs = [
        p for p in procs
        if "REMOTE CONTROL" in p.get("primary_category", "")
        or any("Remote Desktop" in r.get("vector", "") for r in p.get("reasons", []))
    ]
    return {
        "timestamp": datetime.now().isoformat(),
        "total_active_rmm": len(rmm_procs),
        "rmm_processes": rmm_procs
    }


@app.get("/api/persistence")
def get_persistence():
    """Scan and retrieve startup folders, registry keys, and scheduled tasks."""
    entries = get_all_persistence_entries()
    suspicious = [e for e in entries if e.get("is_suspicious")]
    return {
        "total": len(entries),
        "suspicious_count": len(suspicious),
        "entries": entries
    }


@app.post("/api/persistence/disable")
def disable_persistence(req: PersistenceDisableRequest):
    """Disable or remove an autorun persistence mechanism."""
    result = disable_persistence_item(req.id, req.target_path, req.location_type)
    return result


@app.get("/api/audit-log")
def get_audit_log(limit: int = 100):
    """Retrieve recent remediation actions, kills, and scan audit logs."""
    return remediator.get_audit_log(limit=limit)


@app.post("/api/simulator/spawn")
def spawn_test_threat(req: SimulateRequest):
    """Spawn a harmless test process mimicking threat behavior for safe verification."""
    result = spawn_simulated_threat(req.type)
    return result


@app.post("/api/simulator/cleanup")
def cleanup_simulations():
    """Clean up any active test simulations."""
    result = stop_all_simulations()
    return result


# ==============================================================
# Access Control & Allow/Block Policy Endpoints
# ==============================================================

@app.get("/api/policy/rules")
def get_policy_rules():
    """Retrieve all whitelist and blacklist policy rules."""
    return policy_engine.get_all_rules()


@app.post("/api/policy/allow")
def add_allowlist_rule(req: PolicyRuleRequest):
    """Add a process, path, or hash to the trusted allowlist."""
    result = policy_engine.add_allow_rule(req.type, req.value, req.comment)
    remediator.log_event("POLICY_ALLOW_ADDED", req.value, None, f"Added to whitelist [{req.type}]: {req.comment}")
    return result


@app.post("/api/policy/block")
def add_blocklist_rule(req: PolicyRuleRequest):
    """Add a process, path, or hash to the blacklist."""
    if req.type == "ip":
        result = policy_engine.add_ip_block_rule(req.value, req.comment, apply_firewall=True)
    else:
        result = policy_engine.add_block_rule(req.type, req.value, req.comment)
    remediator.log_event("POLICY_BLOCK_ADDED", req.value, None, f"Added to blacklist [{req.type}]: {req.comment}")
    return result


@app.delete("/api/policy/rule/{rule_id}")
def delete_policy_rule(rule_id: str):
    """Remove a rule by ID."""
    result = policy_engine.delete_rule(rule_id)
    remediator.log_event("POLICY_RULE_DELETED", rule_id, None, "Rule removed from security policy.")
    return result


# ==============================================================
# Email Notification & Security Report Endpoints
# ==============================================================

@app.get("/api/email/config")
def get_email_config():
    """Retrieve SMTP settings with password masked."""
    return email_notifier.get_config(mask_password=True)


@app.post("/api/email/config")
def save_email_config(req: EmailConfigRequest):
    """Save SMTP configuration."""
    return email_notifier.update_config(req.dict())


@app.post("/api/email/send-test")
def send_test_email():
    """Dispatch verification test email."""
    result = email_notifier.send_test_email()
    remediator.log_event("EMAIL_TEST", "SMTP Server", None, result.get("message", ""), "SUCCESS" if result.get("success") else "FAILED")
    return result


@app.post("/api/email/send-report")
def send_security_report(req: EmailSendReportRequest):
    """Generate and dispatch comprehensive HTML security report via email."""
    # Gather system state
    scan_res = run_scan(detailed=False)
    net_res = network_tracer.audit_all_network_processes()
    audit_events = remediator.get_audit_log(limit=20)

    report_payload = {
        **scan_res,
        "network": net_res,
        "audit_log": audit_events
    }

    html = email_notifier.generate_html_report(report_payload)
    subject = f"🛡️ AegisShield Security Report - {len(scan_res.get('threats', []))} Threats | Health: {scan_res.get('system_health_index')}%"
    result = email_notifier.send_email(subject, html, recipient=req.recipient)

    remediator.log_event("EMAIL_REPORT_SENT", req.recipient or "Default Recipient", None, result.get("message", ""), "SUCCESS" if result.get("success") else "FAILED")
    return result


# ==============================================================
# Network Process Audit & IP Origin Tracer Endpoints
# ==============================================================

@app.get("/api/network/tracer")
def get_network_tracer():
    """Audit all processes using the network, trace remote IP origins, and evaluate genuineness."""
    return network_tracer.audit_all_network_processes()


@app.post("/api/network/trace-ip")
def trace_single_ip(req: TraceIPRequest):
    """Deep trace lookup for a specific IP address."""
    return network_tracer.trace_ip(req.ip)


@app.post("/api/network/block-ip")
def block_ip_endpoint(req: IPBlockRequest):
    """Block an IP address via policy engine and Windows Firewall."""
    result = policy_engine.add_ip_block_rule(req.ip, comment=req.comment, apply_firewall=req.apply_firewall)
    remediator.log_event("IP_BLOCKED", req.ip, None, f"Blocked remote IP. Firewall applied: {req.apply_firewall}")
    return result


# ==============================================================
# Ad Blocker, Web Traffic Tracking & Analytics Endpoints
# ==============================================================

@app.get("/api/adblock/status")
def get_adblock_status():
    """Retrieve ad-blocking proxy status, active port, system proxy state, and summary metrics."""
    analytics = web_analytics.get_analytics()
    return {
        "proxy_running": adblock_proxy.is_running(),
        "proxy_port": adblock_proxy.port,
        "system_proxy_enabled": proxy_controller.is_proxy_enabled(),
        "total_requests": analytics["total_requests"],
        "total_blocked": analytics["total_blocked"],
        "total_allowed": analytics["total_allowed"],
        "block_rate_percent": analytics["block_rate_percent"],
        "estimated_mb_saved": analytics["estimated_mb_saved"]
    }


@app.post("/api/adblock/toggle-proxy")
def toggle_system_proxy(req: ProxyToggleRequest):
    """Enable or disable Windows system-wide proxy routing for all browsers."""
    if req.enable:
        res = proxy_controller.enable_proxy()
    else:
        res = proxy_controller.disable_proxy()
    remediator.log_event(
        "SYSTEM_PROXY_TOGGLED",
        "127.0.0.1:8080",
        None,
        f"System proxy {'Activated' if req.enable else 'Deactivated'}"
    )
    return res


@app.get("/api/adblock/traffic")
def get_web_traffic_feed(limit: int = 150, status: Optional[str] = None, q: Optional[str] = None):
    """Retrieve chronological browsing history with domain, timestamp, and blocking status."""
    return web_traffic_logger.get_logs(limit=limit, status_filter=status, search_query=q)


@app.get("/api/adblock/analytics")
def get_web_analytics_data():
    """Retrieve aggregated browsing metrics, top visited sites, blocked ads, and activity timelines."""
    return web_analytics.get_analytics()


@app.post("/api/adblock/clear-logs")
def clear_web_traffic_logs():
    """Clear recorded web browsing history."""
    res = web_traffic_logger.clear_logs()
    remediator.log_event("TRAFFIC_LOGS_CLEARED", "WebTrafficLogger", None, "User cleared web history.")
    return res


# ==============================================================
# WebSockets Real-Time Telemetry Stream
# ==============================================================

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """High-frequency telemetry stream pushing CPU, RAM, and quick threat stats."""
    await websocket.accept()
    try:
        while True:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            pids_count = len(psutil.pids())

            data = {
                "timestamp": datetime.now().isoformat(),
                "time_display": datetime.now().strftime("%H:%M:%S"),
                "cpu_percent": cpu,
                "memory_percent": mem.percent,
                "process_count": pids_count
            }
            await websocket.send_json(data)
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ==============================================================
# Mount Static Frontend
# ==============================================================

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_dashboard():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return JSONResponse({"status": "AegisShield Backend Running", "message": "Frontend UI file missing"})

