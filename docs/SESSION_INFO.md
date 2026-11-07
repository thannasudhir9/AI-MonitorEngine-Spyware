# AegisShield EDR: Session Information & Operational Parameters

**Session ID / Target:** `f941cc48-3dd0-4ea9-a4df-91daf625a4db`  
**Host Environment:** Windows (x64)  
**Shell Environment:** PowerShell / cmd.exe  
**Active Project Directory:** `c:\Users\thann\Downloads\AntiGravity\SpywareProcessMon`  
**Current Active Server Daemon:** Task `f941cc48-3dd0-4ea9-a4df-91daf625a4db/task-926`  
**Current Process & PID:** `python.exe` (PID: 69360)  
**Assigned Listening Ports:**
- Port `8888`: AegisShield EDR Web Dashboard, REST API & WebSockets (`http://127.0.0.1:8888`)
- Port `8080`: AegisShield AdBlock & Web Tracker Intercepting Proxy (`127.0.0.1:8080`)
**Documentation Portal:** `http://127.0.0.1:8888/docs.html`  
**Upstream GitHub Remote:** `https://github.com/thannasudhir9/AI-MonitorEngine-Spyware.git` (Branch: `main`)  
**Lead Security Engineer & Author:** Sudhir Kumar Thanna  
**Author Attribution:** `Support with ❤️ - Sudhir Kumar Thanna`  
**Current Deployed Version:** `v2.5.0-SOC-Enterprise (Build 2026.11.07-STABLE)`  
**Operating Policy:** `create, update, append - always`  

---

## 1. Active Subsystems & Port Bindings

| Subsystem Name | Engine Category | Port / Protocol | Runtime Status | Diagnostics URL |
| :--- | :--- | :--- | :--- | :--- |
| **EDR Cyber Dashboard** | User Interface | `8888 / HTTP` | 🟢 ONLINE | `http://127.0.0.1:8888` |
| **Starlette REST / WS API** | Core Backend | `8888 / HTTP+WS` | 🟢 ONLINE | `http://127.0.0.1:8888/api/status` |
| **Web Documentation Hub** | Knowledge Portal | `8888 / HTTP` | 🟢 ONLINE | `http://127.0.0.1:8888/docs.html` |
| **System AdBlock Proxy** | Network Proxy | `8080 / HTTP+HTTPS` | 🟢 ONLINE | `http://127.0.0.1:8080` |
| **AI Threat Monitor** | Forensic Engine | In-Process | 🟢 ONLINE | Multi-stage Heuristic Scanner |
| **Proc Mon Engine** | Socket Auditor | In-Process | 🟢 ONLINE | Live Process & Socket Tracker |
| **Resend HTTPS Emailer** | Alert Dispatcher | `443 / HTTPS` | 🟢 ONLINE | `https://api.resend.com/emails` |
| **Windows Netsh Firewall** | Access Control | Host Kernel | 🟢 ONLINE | Dynamic rule synchronization |
| **Audio Notification Engine** | Sound Controller | Client Web Audio | 🔇 MUTED / SILENT | Zero auditory alerts (Silent Mode) |

---

## 2. Persistent Datastores & Storage State

| Datastore Path | Purpose | Format | Secret Protection Status |
| :--- | :--- | :--- | :--- |
| `database/policy_rules.json` | Whitelist/Blacklist rules (executables, hashes, paths, IPs) | JSON | Tracked in Git |
| `database/geo_cache.json` | Reverse DNS, ASN and ISP organization lookup cache | JSON | Tracked in Git |
| `database/web_traffic_logs.json`| Browsed website history, timestamps, bandwidth & block flags | JSON | Tracked in Git |
| `logs/audit_events.json` | Chronological log of process kills, quarantines & admin alerts | JSON | Tracked in Git |
| `database/email_config.json` | SMTP & Resend API credentials, sender/recipient settings | JSON | **Gitignored** (Zero-Leakage) |
| `database/email_config.example.json` | Sanitized template with masked placeholders | JSON | Tracked in Git |

---

## 3. Persistent Memory & Synchronization Protocol

This project strictly adheres to the user's permanent mandate:
> **"create, update , append - always"**  
> **"copy all brain files , new plans , implementations and all to the current project folder"**  
> **"update , append - design, architecture, project strcure, code explanation ,commands, session information ,prompts and responses , readme file, screenshot engine to take all screenshots of the app, testing engine to check all is working good"**  
> **"keep it in ur anti gravity memory for each task"**

Every development task validates that:
1. `tools/test_engine.py` passes 100%.
2. `tools/screenshot_engine.py` captures all views into `screenshots/`.
3. All brain artifacts in `<appDataDir>\brain\<conversation-id>` are mirrored to `brain_archive/`.
4. All documentation assets in `docs/` and `README.md` are appended with latest details.
5. Code is committed and pushed cleanly to GitHub `origin/main`.

