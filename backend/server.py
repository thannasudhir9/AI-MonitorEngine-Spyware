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
from fastapi.responses import FileResponse, JSONResponse, Response
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
from .system_info import SystemInfoEngine
from .drive_analyzer import DriveAnalyzerEngine
from .threat_ledger import ThreatTrackingLedger
from .services_manager import WindowsServicesManager

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

# System Diagnostics, Drive Analyzer & Threat Ledger
system_info_engine = SystemInfoEngine()
drive_analyzer_engine = DriveAnalyzerEngine()
threat_ledger = ThreatTrackingLedger()
services_manager = WindowsServicesManager()

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


class ServiceConfigRequest(BaseModel):
    startup_type: str  # 'auto' | 'demand' (manual) | 'disabled'


class PolicyRuleRequest(BaseModel):
    type: str  # 'name', 'path', 'hash', 'ip'
    value: str
    comment: Optional[str] = ""


class IPBlockRequest(BaseModel):
    ip: str
    comment: Optional[str] = ""
    apply_firewall: bool = True


class EmailConfigRequest(BaseModel):
    provider: Optional[str] = "resend"  # "resend" or "smtp"
    resend_api_key: Optional[str] = None
    smtp_server: Optional[str] = "smtp.gmail.com"
    smtp_port: Optional[int] = 587
    use_tls: bool = True
    sender_email: Optional[str] = "onboarding@resend.dev"
    sender_password: Optional[str] = ""
    recipient_email: str = "ethstk911@gmail.com"
    auto_email_on_critical: bool = True


class EmailSendReportRequest(BaseModel):
    recipient: Optional[str] = None


class TraceIPRequest(BaseModel):
    ip: str


class ProxyToggleRequest(BaseModel):
    enable: bool


class PrivacyToggleRequest(BaseModel):
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
    critical_threats = [p for p in threats if p.get("is_critical") or p.get("severity") in ("CRITICAL", "HIGH")]
    suspicious_threats = [p for p in threats if p.get("is_suspicious") or (p.get("severity") in ("MEDIUM", "LOW") and p.get("threat_score", 0) >= 20)]
    rmm_tools = [p for p in procs if "REMOTE CONTROL" in p.get("primary_category", "") or any("Remote Desktop" in r.get("vector", "") for r in p.get("reasons", []))]

    # Track in persistent threat ledger
    if threats:
        threat_ledger.record_threats(threats)

    # System Health Index (100 = safe, 0 = critical breach)
    threat_index = 100 - min(len(critical_threats) * 35 + len(suspicious_threats) * 10, 100)

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
        "suspicious_count": len(suspicious_threats),
        "high_count": len(critical_threats),
        "rmm_count": len(rmm_tools),
        "system_health_index": threat_index,
        "threats": threats,
        "critical_threats": critical_threats,
        "suspicious_threats": suspicious_threats,
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
    if result.get("success"):
        threat_ledger.record_remediation(req.pid, str(req.pid), "PROCESS_KILLED", result.get("message", "Terminated"))
    return result


@app.get("/api/app-info")
def get_app_info():
    """Retrieve full application metadata, active engines, ports, and execution environment."""
    is_admin = False
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass

    return {
        "app_name": "AI Monitoring Engine • AdBlocker Engine • Web Tracker • Proc Mon Engine",
        "short_name": "AegisShield EDR",
        "tagline": "AI Autonomous Threat Hunter, Deep Process Monitor & Web Privacy Guardian",
        "process_name": "python.exe",
        "server_pid": os.getpid(),
        "is_admin": is_admin,
        "ports": {
            "dashboard_and_api": 8888,
            "adblock_proxy": 8080,
            "websocket_telemetry": 8888
        },
        "sub_apps": [
            {"name": "AI Monitoring Engine", "status": "ONLINE", "type": "Behavioral Heuristics & Signature Hunter"},
            {"name": "AdBlocker Engine", "status": "ONLINE", "type": "System-Wide DNS / HTTP Network Blocker"},
            {"name": "Web Tracker Proxy", "status": "ONLINE", "type": "127.0.0.1:8080 Intercepting Telemetry Engine"},
            {"name": "Proc Mon Engine", "status": "ONLINE", "type": "Real-time Kernel Process Auditor & Remediator"},
            {"name": "Threat Eradicator", "status": "ONLINE", "type": "Multi-tier Force Kill & Quarantine"},
            {"name": "Firewall Access Controller", "status": "ONLINE", "type": "Windows Netsh Policy Enforcement"},
            {"name": "System Diagnostics Engine", "status": "ONLINE", "type": "Hardware, OS Kernel & Security Baseline (SystemInfoCheck)"},
            {"name": "Drive & Dropper Analyzer", "status": "ONLINE", "type": "Partitions & %TEMP% Dropper Hunter (DriveOrganiser)"},
            {"name": "Threat Tracking Ledger", "status": "ONLINE", "type": "Persistent Anomaly & Threat Chronicle"}
        ],
        "author": "Sudhir Kumar Thanna",
        "support_message": "Built with ❤️ by Sudhir Kumar Thanna",
        "version": "v2.5.0-SOC-Enterprise (Build 2026.11.07-STABLE)",
        "deployed_time": "2026-11-07 08:25:00",
        "default_email_recipient": "ethstk911@gmail.com",
        "email_provider": email_notifier.get_config().get("provider", "resend")
    }


@app.post("/api/admin/elevate-kill/{pid}")
def elevate_kill_process(pid: int):
    """Trigger Windows Administrator UAC elevation dialog to terminate a protected/SYSTEM process."""
    # Check if target PID belongs to a service first
    svc = remediator.get_service_for_pid(pid)
    if svc:
        try:
            subprocess.run(["sc", "stop", svc], capture_output=True, text=True, timeout=2.5)
        except Exception:
            pass

    cmd = f"Start-Process taskkill -ArgumentList '/F /T /PID {pid}' -Verb RunAs -Wait -WindowStyle Hidden"
    subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    time.sleep(0.8)
    is_dead = not psutil.pid_exists(pid)
    remediator.log_event(
        "ELEVATED_KILL_ATTEMPT",
        str(pid),
        pid,
        f"Admin UAC kill triggered for PID {pid} (Service: {svc or 'None'}). Dead: {is_dead}",
        "SUCCESS" if is_dead else "PENDING_UAC"
    )
    return {
        "success": is_dead,
        "pid": pid,
        "service_name": svc,
        "admin_command": f"taskkill /F /PID {pid}",
        "message": f"UAC Administrator elevation triggered for PID {pid}." if not is_dead else f"PID {pid} successfully eradicated via Administrator UAC."
    }


@app.post("/api/admin/stop-service/{service_name}")
def stop_windows_service(service_name: str):
    """Attempt to stop a specific Windows Service via Service Control (sc.exe)."""
    try:
        res = subprocess.run(["sc", "stop", service_name], capture_output=True, text=True, timeout=3.0)
        remediator.log_event("SERVICE_STOP_ATTEMPT", service_name, None, f"sc stop {service_name}: {res.stdout.strip()}", "SUCCESS" if res.returncode == 0 else "FAILED")
        return {"success": res.returncode == 0, "output": res.stdout.strip()}
    except Exception as e:
        return {"success": False, "message": str(e)}


@app.post("/api/admin/restart-as-admin")
def restart_as_admin():
    """Trigger Windows UAC prompt to relaunch AegisShield server with full Administrator privileges."""
    script_path = str(Path(__file__).parent.parent / "start_all_admin.bat")
    cmd = f"Start-Process cmd -ArgumentList '/c \"{script_path}\"' -Verb RunAs"
    subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd], shell=True)
    return {
        "success": True,
        "message": "Elevated Administrator launch triggered. Please accept the Windows UAC security prompt on your screen."
    }


@app.get("/api/blocked-history")
def get_blocked_history(limit: int = 150):
    """Retrieve full persistent tracking history of all previously blocked threats, killed processes, and quarantined files."""
    return remediator.get_blocked_history(limit=limit)


@app.post("/api/kill-tree")
def kill_process_tree(req: KillRequest):
    """Terminate a parent process and all child processes recursively."""
    result = remediator.kill_process_tree(req.pid, reason=req.reason)
    if result.get("success"):
        threat_ledger.record_remediation(req.pid, str(req.pid), "PROCESS_TREE_KILLED", result.get("message", "Process tree eradicated."))
    return result


@app.post("/api/kill-all-threats")
def kill_all_threats(req: KillAllRequest):
    """Emergency bulk kill for all detected threats exceeding threshold."""
    procs = detector.scan_all_processes(detailed_pe=False)
    threats = [p for p in procs if p.get("is_threat")]
    result = remediator.kill_all_threats(threats, min_score=req.min_score)
    for killed in result.get("killed", []):
        threat_ledger.record_remediation(killed.get("pid"), killed.get("name"), "BULK_KILLED", "Terminated during bulk eradication.")
    return result


@app.post("/api/quarantine")
def quarantine_binary(req: QuarantineRequest):
    """Quarantine a suspicious executable file."""
    result = remediator.quarantine_file(req.file_path, reason=req.reason)
    if result.get("success"):
        threat_ledger.record_remediation(None, req.file_path, "FILE_QUARANTINED", result.get("message", "File quarantined."))
    return result
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
# System Diagnostics & Hardware Baseline (SystemInfoCheck)
# ==============================================================

@app.get("/api/system-info")
def get_system_info():
    """Retrieve full hardware specs, OS kernel, CPU, RAM, network adapters, and security baseline."""
    return system_info_engine.get_full_system_info()


# ==============================================================
# Drive & Dropper Staging Analyzer (DriveOrganiserAndAnalyzer-AG2.0)
# ==============================================================

@app.get("/api/drives")
def get_drives_overview():
    """Retrieve all physical and logical drive partitions, capacities, and space utilization."""
    return drive_analyzer_engine.get_drives_overview()


@app.get("/api/drives/dropper-zones")
def scan_dropper_zones(max_items: int = 50):
    """Audit high-risk directories (%TEMP%, AppData, Windows Temp) for dropped executables and scripts."""
    return drive_analyzer_engine.scan_dropper_staging_zones(max_items=max_items)


@app.post("/api/drives/clean-temp")
def clean_temp_droppers():
    """Clean temporary files and dropper staging artifacts in user %TEMP%."""
    res = drive_analyzer_engine.clean_temp_droppers()
    remediator.log_event("TEMP_DROPPERS_CLEANED", "%TEMP%", None, res.get("message", "Temp cleanup executed."))
    return res


# ==============================================================
# Threat Tracking Ledger (Persistent Chronological Anomaly History)
# ==============================================================

@app.get("/api/threats/tracking-ledger")
def get_threat_tracking_ledger(limit: int = 200, severity: Optional[str] = None, status: Optional[str] = None, q: Optional[str] = None):
    """Retrieve persistent chronological ledger of all suspicious and critical threats, lifecycles, and scores."""
    return threat_ledger.get_ledger(limit=limit, severity=severity, status=status, search=q)


@app.post("/api/threats/tracking-ledger/clear")
def clear_threat_tracking_ledger():
    """Reset persistent threat tracking ledger."""
    res = threat_ledger.clear_ledger()
    remediator.log_event("LEDGER_CLEARED", "ThreatTrackingLedger", None, "User cleared threat tracking ledger.")
    return res


# ==============================================================
# Windows Services Management (services.msc)
# ==============================================================

@app.get("/api/services")
def list_windows_services(status: Optional[str] = None, q: Optional[str] = None, force: bool = False):
    """Retrieve full catalog of installed Windows Services, states, PIDs, startup modes, and threat associations."""
    services = services_manager.get_services(force_refresh=force)
    if status and status.lower() != "all":
        st = status.upper()
        if st in ("RUNNING", "STOPPED", "PAUSED"):
            services = [s for s in services if s["status"] == st]
        elif st in ("AUTOMATIC", "AUTO"):
            services = [s for s in services if s["start_type"].lower() in ("auto", "automatic")]
        elif st in ("MANUAL", "DEMAND"):
            services = [s for s in services if s["start_type"].lower() in ("manual", "demand")]
        elif st == "DISABLED":
            services = [s for s in services if s["start_type"].lower() == "disabled"]
        elif st in ("RMM", "THREAT"):
            services = [s for s in services if s.get("is_rmm") or s.get("threat_score", 0) > 0]

    if q and q.strip():
        query = q.strip().lower()
        services = [
            s for s in services if
            query in s["name"].lower() or
            query in s["display_name"].lower() or
            query in str(s["pid"]) or
            query in s["binpath"].lower() or
            query in s["description"].lower()
        ]
    return {
        "total_count": len(services),
        "running_count": sum(1 for s in services if s["is_running"]),
        "stopped_count": sum(1 for s in services if not s["is_running"]),
        "rmm_count": sum(1 for s in services if s.get("is_rmm")),
        "services": services
    }


@app.get("/api/services/{name}")
def get_service_details(name: str):
    """Retrieve metadata and runtime state for a specific Windows service."""
    svc = services_manager.get_service(name)
    if not svc:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found.")
    return svc


@app.post("/api/services/{name}/start")
def start_windows_service(name: str):
    """Start an installed Windows service."""
    res = services_manager.start_service(name)
    remediator.log_event("SERVICE_START", name, None, res["message"], "SUCCESS" if res["success"] else "FAILED")
    return res


@app.post("/api/services/{name}/stop")
def stop_windows_service(name: str):
    """Stop an active Windows service."""
    res = services_manager.stop_service(name)
    remediator.log_event("SERVICE_STOP", name, None, res["message"], "SUCCESS" if res["success"] else "FAILED")
    return res


@app.post("/api/services/{name}/restart")
def restart_windows_service(name: str):
    """Restart a Windows service."""
    res = services_manager.restart_service(name)
    remediator.log_event("SERVICE_RESTART", name, None, res["message"], "SUCCESS" if res["success"] else "FAILED")
    return res


@app.post("/api/services/{name}/config")
def configure_windows_service_startup(name: str, req: ServiceConfigRequest):
    """Configure startup mode ('auto', 'demand' (manual), or 'disabled') for a Windows service."""
    res = services_manager.set_startup_type(name, req.startup_type)
    remediator.log_event("SERVICE_CONFIG", name, None, res["message"], "SUCCESS" if res["success"] else "FAILED")
    return res


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
        "private_mode": web_traffic_logger.is_private_mode(),
        "total_requests": analytics["total_requests"],
        "total_blocked": analytics["total_blocked"],
        "total_allowed": analytics["total_allowed"],
        "block_rate_percent": analytics["block_rate_percent"],
        "estimated_mb_saved": analytics["estimated_mb_saved"]
    }


# ==============================================================
# Stealth & Private Browsing Endpoints
# ==============================================================

@app.get("/api/privacy/status")
def get_privacy_status():
    """Retrieve Private Stealth Mode configuration and volatile buffer telemetry."""
    is_private = web_traffic_logger.is_private_mode()
    return {
        "private_mode": is_private,
        "zero_disk_footprint": is_private,
        "anti_tracking_headers": is_private,
        "anonymize_client_ip": is_private,
        "volatile_entries_count": len(web_traffic_logger.volatile_private_logs)
    }


@app.post("/api/privacy/toggle")
def toggle_privacy_mode(req: PrivacyToggleRequest):
    """Enable or disable zero-disk footprint Private Mode."""
    is_active = web_traffic_logger.set_private_mode(req.enable)
    remediator.log_event(
        "PRIVATE_MODE_TOGGLED",
        "PrivacyEngine",
        None,
        f"Private Stealth Mode {'ACTIVATED (Zero Disk Logging)' if is_active else 'DEACTIVATED'}"
    )
    return {
        "success": True,
        "private_mode": is_active,
        "message": f"Private Stealth Mode successfully {'enabled' if is_active else 'disabled'}."
    }


@app.post("/api/privacy/panic-wipe")
def panic_wipe():
    """Emergency panic wipe: immediately purges all browsing logs, volatile memory, and DNS caches."""
    wipe_res = web_traffic_logger.panic_wipe()
    network_tracer.clear_cache()
    remediator.log_event(
        "PANIC_WIPE_EXECUTED",
        "PrivacyEngine",
        None,
        "Zero-footprint purge executed: cleared browsing history, memory buffers, and DNS cache."
    )
    return {
        "success": True,
        "message": "Stealth Panic Wipe complete: All web history, volatile memory, and DNS caches purged."
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
                "process_count": pids_count,
                "private_mode": web_traffic_logger.is_private_mode()
            }
            await websocket.send_json(data)
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ==============================================================
# Mount Static Frontend & Screenshots
# ==============================================================

screenshots_dir = Path(__file__).parent.parent / "screenshots"
if screenshots_dir.exists():
    app.mount("/screenshots", StaticFiles(directory=str(screenshots_dir)), name="screenshots")

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_dashboard():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return JSONResponse({"status": "AegisShield Backend Running", "message": "Frontend UI file missing"})

    @app.get("/docs.html")
    def serve_docs():
        docs_file = FRONTEND_DIR / "docs.html"
        if docs_file.exists():
            return FileResponse(docs_file)
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/favicon.ico")
    def serve_favicon():
        svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>"""
        return Response(content=svg, media_type="image/svg+xml")

