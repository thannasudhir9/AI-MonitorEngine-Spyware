"""
AegisShield - Email Incident & Security Posture Notifier
Configurable SMTP dispatcher that generates and sends rich HTML security reports,
critical threat alerts, and network telemetry audits.
"""

import os
import json
import smtplib
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import DATABASE_DIR

EMAIL_CONFIG_FILE = DATABASE_DIR / "email_config.json"


class EmailNotifier:
    """Handles Resend HTTP API and SMTP configuration, HTML report formatting, and email dispatch."""

    def __init__(self):
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load Email dispatch settings from disk."""
        default_config = {
            "provider": "resend",  # "resend" or "smtp"
            "resend_api_key": os.environ.get("RESEND_API_KEY", ""),
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "use_tls": True,
            "sender_email": "onboarding@resend.dev",
            "sender_password": "",
            "recipient_email": "ethstk911@gmail.com",
            "auto_email_on_critical": True,
            "last_sent": None
        }

        if EMAIL_CONFIG_FILE.exists():
            try:
                with open(EMAIL_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k in default_config:
                        if k not in data:
                            data[k] = default_config[k]
                    return data
            except Exception:
                return default_config
        return default_config

    def _save_config(self):
        """Persist Email configuration to disk."""
        try:
            with open(EMAIL_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2)
        except Exception:
            pass

    def get_config(self, mask_password: bool = True) -> Dict[str, Any]:
        """Retrieve current configuration."""
        cfg = dict(self._config)
        if mask_password and cfg.get("sender_password"):
            cfg["sender_password"] = "••••••••••••"
        if mask_password and cfg.get("resend_api_key"):
            key = cfg["resend_api_key"]
            if len(key) > 8:
                cfg["resend_api_key_masked"] = key[:6] + "••••••••" + key[-4:]
        return cfg

    def update_config(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Update Email settings."""
        for key in ["provider", "resend_api_key", "smtp_server", "smtp_port", "use_tls", "sender_email", "recipient_email", "auto_email_on_critical"]:
            if key in new_settings and new_settings[key] is not None:
                self._config[key] = new_settings[key]

        # Only update password if a non-masked value is provided
        pw = new_settings.get("sender_password", "")
        if pw and not pw.startswith("••"):
            self._config["sender_password"] = pw

        self._save_config()
        return {"success": True, "message": "Email settings saved successfully."}

    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate a modern, cybersecurity executive HTML report with tables
        for threats, remote desktop sessions, network processes, and audit actions.
        """
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        threats = report_data.get("threats", [])
        rmm_tools = report_data.get("rmm_tools", [])
        network = report_data.get("network", {})
        total_procs = report_data.get("total_processes", 0)
        health_index = report_data.get("system_health_index", 100)
        audit_log = report_data.get("audit_log", [])

        # Color-coded status header
        if len(threats) > 0:
            status_color = "#ef4444"
            status_badge = "CRITICAL THREATS DETECTED"
        else:
            status_color = "#10b981"
            status_badge = "SYSTEM HEALTH SECURE"

        # Build Threat Rows
        threat_rows = ""
        if threats:
            for t in threats:
                reasons_text = "<br>".join([f"• <b>{r.get('vector')}</b>: {r.get('detail')}" for r in t.get("reasons", [])])
                threat_rows += f"""
                <tr style="border-bottom: 1px solid #1e293b;">
                    <td style="padding: 10px; font-weight: bold; color: #f8fafc;">{t.get('name')} (PID: {t.get('pid')})</td>
                    <td style="padding: 10px; color: #ef4444; font-weight: bold;">{t.get('primary_category')}</td>
                    <td style="padding: 10px; font-weight: bold; color: #f59e0b;">{t.get('threat_score')}/100</td>
                    <td style="padding: 10px; font-size: 11px; color: #94a3b8; word-break: break-all;">{t.get('exe')}</td>
                    <td style="padding: 10px; font-size: 11px; color: #cbd5e1;">{reasons_text}</td>
                </tr>
                """
        else:
            threat_rows = """<tr><td colspan="5" style="padding: 15px; text-align: center; color: #10b981;">No active threats detected. All running processes passed heuristics.</td></tr>"""

        # Build RMM / Remote Desktop Rows
        rmm_rows = ""
        if rmm_tools:
            for r in rmm_tools:
                ports = ", ".join([f"{c.get('local_port')} -> {c.get('remote_addr')}" for c in r.get("network", {}).get("connections", [])]) or "No active sockets"
                rmm_rows += f"""
                <tr style="border-bottom: 1px solid #1e293b;">
                    <td style="padding: 8px; color: #06b6d4; font-weight: bold;">{r.get('name')} (PID: {r.get('pid')})</td>
                    <td style="padding: 8px; color: #94a3b8;">{r.get('primary_category')}</td>
                    <td style="padding: 8px; font-size: 11px; color: #cbd5e1;">{r.get('exe')}</td>
                    <td style="padding: 8px; font-size: 11px; color: #fde68a;">{ports}</td>
                </tr>
                """
        else:
            rmm_rows = """<tr><td colspan="4" style="padding: 12px; text-align: center; color: #94a3b8;">No active Remote Desktop or RMM sessions detected.</td></tr>"""

        # Build Network Overview Rows
        net_rows = ""
        connections = network.get("connections", [])[:15]  # Top 15 connections
        if connections:
            for c in connections:
                verdict_color = "#10b981" if c.get("trace", {}).get("is_genuine") else ("#ef4444" if c.get("is_suspicious") else "#94a3b8")
                net_rows += f"""
                <tr style="border-bottom: 1px solid #1e293b;">
                    <td style="padding: 8px; color: #f8fafc;">{c.get('process_name')} ({c.get('pid')})</td>
                    <td style="padding: 8px; font-family: monospace; color: #cbd5e1;">{c.get('local_addr')}</td>
                    <td style="padding: 8px; font-family: monospace; color: #06b6d4;">{c.get('remote_addr')}</td>
                    <td style="padding: 8px; font-size: 11px; color: #94a3b8;">{c.get('trace', {}).get('hostname')} ({c.get('trace', {}).get('org')})</td>
                    <td style="padding: 8px; font-weight: bold; color: {verdict_color}; font-size: 11px;">{c.get('trace', {}).get('verdict')}</td>
                </tr>
                """
        else:
            net_rows = """<tr><td colspan="5" style="padding: 12px; text-align: center; color: #94a3b8;">No active sockets recorded.</td></tr>"""

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>AegisShield EDR Security Report</title>
        </head>
        <body style="margin: 0; padding: 20px; background-color: #080c14; font-family: 'Segoe UI', Arial, sans-serif; color: #f8fafc;">
            <div style="max-width: 900px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
                
                <!-- Header Banner -->
                <div style="background: linear-gradient(135deg, #0b1329 0%, #172554 100%); padding: 24px; border-bottom: 2px solid #06b6d4;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <h1 style="margin: 0; font-size: 24px; letter-spacing: 1px; color: #ffffff;">AEGIS<span style="color: #06b6d4;">SHIELD</span> EDR</h1>
                            <p style="margin: 4px 0 0 0; font-size: 12px; color: #94a3b8;">Executive Endpoint Threat & Process Intelligence Report</p>
                        </div>
                        <div style="text-align: right;">
                            <span style="display: inline-block; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: bold; background-color: {status_color}22; color: {status_color}; border: 1px solid {status_color};">
                                {status_badge}
                            </span>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 5px;">Report Time: {scan_time}</div>
                        </div>
                    </div>
                </div>

                <!-- Metrics Dashboard Grid -->
                <div style="display: table; width: 100%; border-bottom: 1px solid #1e293b; background: #111a2e;">
                    <div style="display: table-row;">
                        <div style="display: table-cell; padding: 16px; border-right: 1px solid #1e293b; text-align: center;">
                            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Active Processes</div>
                            <div style="font-size: 22px; font-weight: bold; color: #ffffff; margin-top: 4px;">{total_procs}</div>
                        </div>
                        <div style="display: table-cell; padding: 16px; border-right: 1px solid #1e293b; text-align: center;">
                            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Detected Threats</div>
                            <div style="font-size: 22px; font-weight: bold; color: #ef4444; margin-top: 4px;">{len(threats)}</div>
                        </div>
                        <div style="display: table-cell; padding: 16px; border-right: 1px solid #1e293b; text-align: center;">
                            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Remote Desktop / RMM</div>
                            <div style="font-size: 22px; font-weight: bold; color: #06b6d4; margin-top: 4px;">{len(rmm_tools)}</div>
                        </div>
                        <div style="display: table-cell; padding: 16px; text-align: center;">
                            <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Health Index</div>
                            <div style="font-size: 22px; font-weight: bold; color: #10b981; margin-top: 4px;">{health_index}%</div>
                        </div>
                    </div>
                </div>

                <!-- Section: Detected Threats -->
                <div style="padding: 24px;">
                    <h2 style="margin: 0 0 12px 0; font-size: 16px; color: #f8fafc; border-bottom: 1px solid #1e293b; padding-bottom: 8px;">
                        🚨 Active Process Threats & Malware Anomaly Detection
                    </h2>
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                        <thead>
                            <tr style="background: #1e293b; color: #94a3b8;">
                                <th style="padding: 8px;">Process / PID</th>
                                <th style="padding: 8px;">Category</th>
                                <th style="padding: 8px;">Risk Score</th>
                                <th style="padding: 8px;">Executable Path</th>
                                <th style="padding: 8px;">Triggered Heuristics</th>
                            </tr>
                        </thead>
                        <tbody>
                            {threat_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Section: Remote Desktop / RMM -->
                <div style="padding: 0 24px 24px 24px;">
                    <h2 style="margin: 0 0 12px 0; font-size: 16px; color: #06b6d4; border-bottom: 1px solid #1e293b; padding-bottom: 8px;">
                        📡 Remote Desktop & RMM Software Monitor (LOLRMM)
                    </h2>
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                        <thead>
                            <tr style="background: #1e293b; color: #94a3b8;">
                                <th style="padding: 8px;">Software / PID</th>
                                <th style="padding: 8px;">Category</th>
                                <th style="padding: 8px;">Path</th>
                                <th style="padding: 8px;">Sockets / Ports</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rmm_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Section: Network Process Audit & Origin Tracer -->
                <div style="padding: 0 24px 24px 24px;">
                    <h2 style="margin: 0 0 12px 0; font-size: 16px; color: #10b981; border-bottom: 1px solid #1e293b; padding-bottom: 8px;">
                        🌐 Network Process Audit & Remote IP Origin Tracer
                    </h2>
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                        <thead>
                            <tr style="background: #1e293b; color: #94a3b8;">
                                <th style="padding: 8px;">Process (PID)</th>
                                <th style="padding: 8px;">Local Socket</th>
                                <th style="padding: 8px;">Remote Socket</th>
                                <th style="padding: 8px;">Reverse DNS / ISP</th>
                                <th style="padding: 8px;">Genuineness Verdict</th>
                            </tr>
                        </thead>
                        <tbody>
                            {net_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Footer -->
                <div style="background: #0b111e; padding: 16px; text-align: center; font-size: 11px; color: #64748b; border-top: 1px solid #1e293b;">
                    Report generated by AegisShield Endpoint Threat Detection & Eradication System. Keep this record for compliance and SOC auditing.
                </div>
            </div>
        </body>
        </html>
        """
        return html

    def send_via_resend(self, subject: str, html_content: str, recipient: Optional[str] = None) -> Dict[str, Any]:
        """Dispatch email using Resend HTTP API (HTTPS port 443 with Zero SMTP blocking)."""
        cfg = self._config
        api_key = cfg.get("resend_api_key") or os.environ.get("RESEND_API_KEY", "")
        to_email = recipient or cfg.get("recipient_email") or "ethstk911@gmail.com"
        from_email = cfg.get("sender_email") or "onboarding@resend.dev"
        
        # Resend test domain format compliance
        if "onboarding@resend.dev" in from_email or not from_email:
            from_sender = "AegisShield SOC <onboarding@resend.dev>"
        else:
            from_sender = f"AegisShield SOC <{from_email}>" if "<" not in from_email else from_email

        payload = {
            "from": from_sender,
            "to": [to_email],
            "subject": subject,
            "html": html_content
        }

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisShield-EDR/2.5"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                self._config["last_sent"] = datetime.now().isoformat()
                self._save_config()
                return {
                    "success": True,
                    "provider": "resend",
                    "resend_id": body.get("id"),
                    "message": f"Security report successfully dispatched to {to_email} via Resend API (ID: {body.get('id')})."
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            return {
                "success": False,
                "provider": "resend",
                "message": f"Resend API Error (HTTP {e.code}): {err_body}"
            }
        except Exception as e:
            return {
                "success": False,
                "provider": "resend",
                "message": f"Resend Dispatch Exception: {str(e)}"
            }

    def send_email(self, subject: str, html_content: str, recipient: Optional[str] = None) -> Dict[str, Any]:
        """Dispatch email using configured Resend API or SMTP settings."""
        cfg = self._config
        provider = (cfg.get("provider") or "resend").lower()
        to_email = recipient or cfg.get("recipient_email") or "ethstk911@gmail.com"

        # If provider is Resend or Resend API key is present, prefer Resend
        if provider == "resend" or cfg.get("resend_api_key"):
            resend_result = self.send_via_resend(subject, html_content, to_email)
            if resend_result["success"] or provider == "resend":
                return resend_result

        # SMTP Fallback
        server_host = cfg.get("smtp_server")
        server_port = int(cfg.get("smtp_port", 587))
        sender = cfg.get("sender_email")
        password = cfg.get("sender_password")

        if not server_host or not sender or not to_email:
            return {
                "success": False,
                "message": "Incomplete Email configuration. Resend API key or SMTP Server and Sender required."
            }

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"AegisShield EDR <{sender}>"
            msg["To"] = to_email

            # Attach HTML body
            msg.attach(MIMEText(html_content, "html"))

            # Dispatch via SMTP
            if server_port == 465:
                # SSL
                server = smtplib.SMTP_SSL(server_host, server_port, timeout=10)
            else:
                # STARTTLS
                server = smtplib.SMTP(server_host, server_port, timeout=10)
                if cfg.get("use_tls", True):
                    server.starttls()

            if password:
                server.login(sender, password)

            server.sendmail(sender, [to_email], msg.as_string())
            server.quit()

            self._config["last_sent"] = datetime.now().isoformat()
            self._save_config()

            return {
                "success": True,
                "provider": "smtp",
                "message": f"Security report successfully dispatched to {to_email} via SMTP."
            }

        except smtplib.SMTPAuthenticationError:
            return {
                "success": False,
                "provider": "smtp",
                "message": "SMTP Authentication failed. For Gmail, please use an 'App Password' rather than your regular account password."
            }
        except Exception as e:
            return {
                "success": False,
                "provider": "smtp",
                "message": f"SMTP Dispatch Error: {str(e)}"
            }

    def send_test_email(self, recipient: Optional[str] = None) -> Dict[str, Any]:
        """Send verification test email."""
        target = recipient or self._config.get("recipient_email") or "ethstk911@gmail.com"
        test_html = f"""
        <div style="font-family: Arial, sans-serif; background: #0f172a; color: #ffffff; padding: 24px; border-radius: 12px; border: 1px solid #1e293b; max-width: 650px; margin: 0 auto;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
                <h2 style="color: #06b6d4; margin: 0;">🛡️ AegisShield EDR - Security Telemetry Alert & Test Report</h2>
            </div>
            <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">
                This confirms that your <strong>AegisShield EDR</strong> notification engine is active and communicating over Resend API / SMTP.
            </p>
            <div style="background: #111a2e; border: 1px solid #06b6d4; border-radius: 8px; padding: 16px; margin: 20px 0;">
                <p style="margin: 0 0 8px 0; color: #10b981; font-weight: bold; font-size: 14px;">
                    ✓ Dispatch Channel: RESEND HTTP API (Port 443 / Cloud Delivery)
                </p>
                <p style="margin: 0; color: #cbd5e1; font-size: 13px;">
                    <strong>Recipient:</strong> {target}<br>
                    <strong>Engines Active:</strong> AI Monitoring Engine, AdBlocker Engine, Web Tracker, Proc Mon Engine<br>
                    <strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                    <strong>Deployment:</strong> v2.5.0-SOC-Enterprise (Built with ❤️ by Sudhir Kumar Thanna)
                </p>
            </div>
            <p style="color: #64748b; font-size: 12px; border-top: 1px solid #1e293b; padding-top: 12px; margin-top: 20px;">
                AegisShield Autonomous SOC Defense Engine. Keep this receipt for security posture auditing.
            </p>
        </div>
        """
        return self.send_email("🛡️ AegisShield EDR - Incident Alert Verification", test_html, target)

