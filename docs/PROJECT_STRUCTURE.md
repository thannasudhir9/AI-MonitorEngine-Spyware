# AegisShield EDR & Network AdBlocker: Project Structure

## 1. Directory Tree Overview

```
SpywareProcessMon/
│
├── backend/                                # Core Python Security & Proxy Engines
│   ├── __init__.py                         # Python package initializer
│   ├── adblock_proxy.py                    # Multi-threaded HTTP/HTTPS CONNECT intercepting proxy (:8080)
│   ├── adblock_rules.py                    # 5000+ domain rules (EasyList, AdGuard, StevenBlack)
│   ├── detector.py                         # Threat detection engine (masquerading, cmdlines, signatures)
│   ├── drive_analyzer.py                   # Drive partitions & %TEMP% Dropper Hunter (DriveOrganiser)
│   ├── email_notifier.py                   # SMTP alerts & responsive HTML executive security reports
│   ├── network_tracer.py                   # Process network socket auditor & IP genuineness scorer
│   ├── pe_analyzer.py                      # Portable Executable forensics & Shannon entropy analysis
│   ├── persistence_hunter.py               # Windows Registry Run keys, Startup folders & Task auditor
│   ├── policy_engine.py                    # Whitelist/Blacklist rules & Windows Firewall netsh integration
│   ├── proxy_controller.py                 # Windows Internet Settings HKCU system proxy toggle
│   ├── remediator.py                       # Process eradication (SIGKILL), file quarantine & audit logging
│   ├── server.py                           # FastAPI / Starlette REST API & WebSocket server (:8888)
│   ├── services_manager.py                 # Windows Service Control Manager (services.msc) & RMM correlation
│   ├── signatures_db.py                    # Malware, Trojan, Ransomware & LOLRMM signature hashes/patterns
│   ├── simulator.py                        # Safe threat simulator lab (Trojan dropper, LOLBin, RMM)
│   ├── system_info.py                      # Hardware, OS Kernel, 24 CPU cores & Baseline (SystemInfoCheck)
│   ├── threat_ledger.py                    # Persistent Chronological Anomaly & Threat Ledger
│   ├── web_analytics.py                    # Real-time web analytics, bandwidth saved & category distributions
│   └── web_traffic_logger.py               # Thread-safe persistent logging of all browsed websites
│
├── frontend/                               # Dark Cyber SOC Web Dashboard
│   ├── index.html                          # Single-page application HTML5 interface
│   ├── css/
│   │   └── dashboard.css                   # Responsive dark-theme cyber styling & HUD components
│   └── js/
│       └── app.js                          # Real-time dashboard controller & WebSocket telemetry handler
│
├── database/                               # Persistent Storage Layer (JSON Datastores)
│   ├── email_config.json                   # SMTP server settings, credentials & alert toggles
│   ├── geo_cache.json                      # Cached reverse DNS, ASN and ISP organization lookups
│   ├── incident_audit.json                 # Eradication, firewall block and quarantine audit trail
│   ├── policy_rules.json                   # Allowlist and blocklist rules (name, path, hash, IP)
│   └── web_traffic_logs.json               # Browsed websites history, timestamps, domains & block status
│
├── docs/                                   # Complete Engineering Documentation Suite
│   ├── DESIGN.md                           # System and UX design specification
│   ├── ARCHITECTURE.md                     # Deep system architecture & process boundaries
│   ├── DESIGN_AND_ARCHITECTURE.md          # Combined architecture overview, diagrams & data flows
│   ├── FUTURE_SCOPE.md                     # Strategic 2026-2027 enterprise roadmap, ETW & eBPF research
│   ├── PROJECT_STRUCTURE.md                # File-by-file mapping, roles, and schema specifications
│   ├── CODE_EXPLANATION.md                 # Deep-dive into classes, methods, heuristics & algorithms
│   ├── COMMANDS.md                         # CLI reference, batch launchers, REST API & WebSocket schemas
│   ├── SESSION_INFO.md                     # Session metadata, environment parameters & active daemons
│   ├── SESSION_PROMPTS_AND_RESPONSES.md    # Chronological history of user prompts & engineering solutions
│   └── ANTIGRAVITY_MEMORY.md               # Persistent memory protocol ('create, update, append - always')
│
├── brain_archive/                          # Persistent Mirrored Brain Artifacts
│   ├── plan.md                             # Original system implementation plan
│   ├── adblocker_plan.md                   # AdBlocker and web tracking engine plan
│   ├── continuous_sync_and_memory_protocol.md # Persistent memory & synchronization protocol
│   └── future_scope_and_roadmap_plan.md    # Strategic future roadmap & autonomous defense blueprint
│
├── screenshots/                            # High-Definition 1600x1000 UI Screenshots
│   ├── 01_active_threats_remediation.png   # Active threats, severity badges, and 1-click eradication
│   ├── 02_network_radar_ip_tracer.png      # Network socket inspection, reverse DNS & genuineness scoring
│   ├── 03_adblocker_web_analytics.png      # AdBlock proxy telemetry, blocked ads & browsing history
│   ├── 04_remote_desktop_rmm_hunter.png    # AnyDesk, TeamViewer, VNC & ScreenConnect detection
│   ├── 05_live_process_monitor.png         # Live processes, CPU/RAM telemetry & path validation
│   ├── 06_access_control_rules.png         # Whitelist, blacklist & Windows Firewall rules management
│   ├── 07_persistence_startup.png          # Windows Registry Run keys, autorun items & scheduled tasks
│   ├── 08_threat_simulation_lab.png        # Safe attack simulation triggers (Trojan, LOLBin, RMM)
│   ├── 09_email_alerts_config.png          # SMTP configuration & manual report dispatch
│   ├── 10_incident_audit_trail.png         # Chronological eradication and policy enforcement audit trail
│   ├── 11_private_mode_stealth.png         # Zero-disk footprint stealth mode console & volatile buffer
│   ├── 12_light_mode_clean_soc.png         # Clean daylight SOC theme interface view
│   ├── 13_documentation_hub.png            # Web Documentation Hub and four engines breakdown
│   ├── 14_elevated_kill_modal_and_tracking.png # Interactive UAC elevation modal & tracking ledgers
│   ├── 15_system_diagnostics_baseline.png  # Hardware, OS kernel, CPU frequency & baseline audit
│   ├── 16_storage_dropper_hunter.png       # Drive partitions & %TEMP% dropper hunter staging zone
│   ├── 17_suspicious_threat_tracking_ledger.png # Chronological suspicious threat tracking ledger
│   └── 18_windows_services_control_panel.png # Windows Services Control Panel (services.msc) & lifecycle actions
│
├── tools/                                  # Diagnostic and Visual Engines
│   ├── screenshot_engine.py                # High-definition Pillow dashboard renderer generating 18 screenshots
│   └── test_engine.py                      # Master automated diagnostic suite (67/67 unit & integration checks)
│
├── brain_archive/                          # Complete Mirror of Session State & Brain Files
│   ├── plan.md                             # Initial master development plan
│   ├── adblocker_plan.md                   # AdBlocker and web inspector development plan
│   ├── continuous_sync_and_memory_protocol.md # Persistent memory & synchronization protocol
│   ├── future_scope_and_roadmap_plan.md    # Strategic future roadmap & autonomous defense blueprint
│   ├── systeminfo_and_drive_integration_plan.md # SystemInfoCheck & DriveOrganiser integration plan
│   ├── services_control_panel_and_shadcn_ui_plan.md # Windows Services control panel & Shadcn UI plan
│   ├── light_mode_typography_and_shadcn_css_plan.md # Light mode typography & modern CSS plan
│   ├── two_level_nav_and_dark_mode_fix_plan.md # Two-Level navigation & Dark Mode toggle fix plan
│   └── .system_generated/                  # Transcripts, logs, steps and task states
│
├── cli_scanner.py                          # Unified Terminal CLI tool for scanning, rules & remediation
├── run_server.py                           # Standalone backend server entry point (:8888)
├── start_all.bat                           # 1-Click launcher starting both EDR Server and AdBlock Proxy
├── start_all_admin.bat                     # 1-Click elevated Administrator launcher
├── start_dashboard.bat                     # Launcher starting only the EDR Web Dashboard
├── start_dashboard_admin.bat               # Launcher starting EDR Web Dashboard as Administrator
├── start_adblocker.bat                     # Launcher starting only the AdBlock Proxy server
├── run_tests.bat                           # Launcher running the master test diagnostic engine
├── generate_screenshots.bat                # Launcher executing the screenshot capture engine
├── requirements.txt                        # Python dependencies (psutil, starlette, uvicorn, requests, pillow)
└── README.md                               # Master Project Overview, Quickstart & Operator Manual
```

---

## 2. Component Responsibility Matrix

| File / Component | Primary Responsibility | Upstream Dependencies | Downstream Consumers |
| :--- | :--- | :--- | :--- |
| `backend/server.py` | Exposes REST endpoints & WebSocket telemetry on `127.0.0.1:8888` | All `backend/*` modules | Web UI (`app.js`), External clients |
| `backend/services_manager.py` | Enumerates 331+ Windows services via CIM/sc.exe, correlates RMM threat indicators, manages service lifecycle | `Get-CimInstance`, `sc.exe`, `psutil` | `server.py`, `test_engine.py` |
| `backend/detector.py` | Scans processes, executes heuristic analysis, scores threat level (0-100) | `signatures_db.py`, `pe_analyzer.py` | `server.py`, `cli_scanner.py`, `test_engine.py` |
| `backend/remediator.py` | Terminates malicious PIDs, quarantines files, writes audit records | `psutil`, `incident_audit.json` | `server.py`, `cli_scanner.py` |
| `backend/system_info.py` | Audits hardware, OS kernel, CPU load, RAM/Swap, NICs, Security baseline | `psutil`, `platform` | `server.py`, `test_engine.py` |
| `backend/drive_analyzer.py` | Scans partitions, disk space, and audits %TEMP% dropper staging zones | `psutil`, `pathlib` | `server.py`, `test_engine.py` |
| `backend/threat_ledger.py` | Persistent chronological ledger of suspicious & critical threats | `logs/threat_tracking_ledger.json` | `server.py`, `test_engine.py` |
| `backend/adblock_proxy.py` | Multithreaded HTTP/HTTPS proxy filtering ad/tracker domains on `:8080` | `adblock_rules.py`, `web_traffic_logger.py` | System browsers (Chrome, Edge, Firefox) |
| `backend/adblock_rules.py` | Curated 5,000+ domain reputation dictionary (ad networks, trackers, telemetry) | Built-in set | `adblock_proxy.py`, `test_engine.py` |
| `backend/web_traffic_logger.py` | Thread-safe logging of all browsed websites to `web_traffic_logs.json` | `database/web_traffic_logs.json` | `adblock_proxy.py`, `web_analytics.py`, `server.py` |
| `backend/web_analytics.py` | Computes metrics: top clean sites, top blocked ads, bandwidth saved | `web_traffic_logger.py` | `server.py`, Web UI |
| `backend/proxy_controller.py` | Programmatic Windows Internet Settings (`ProxyEnable=1/0`) toggle | Windows Registry (`winreg`) | `server.py`, Web UI |
| `backend/network_tracer.py` | Audits process sockets, resolves reverse DNS, scores origin genuineness | `database/geo_cache.json` | `server.py`, `cli_scanner.py` |
| `backend/policy_engine.py` | Manages Whitelist/Blacklist rules and syncs Windows Firewall rules | `database/policy_rules.json`, `netsh` | `detector.py`, `server.py`, `cli_scanner.py` |
| `backend/email_notifier.py` | Generates executive HTML threat reports and dispatches via SMTP/Resend | `database/email_config.json`, `smtplib`| `server.py`, `cli_scanner.py` |
| `frontend/app.js` | Drives Two-Level (Level 1 / Level 2) non-scrolling nav, dark/light theme, WebSockets & actions | `frontend/index.html` | User / Operator |
| `tools/test_engine.py` | 67-step automated verification suite testing all 21 subsystems | All backend modules | CI/CD, Quality Assurance |
| `tools/screenshot_engine.py` | Pillow-based visual engine generating 18 HD 1600x1000 screenshots | Pillow (`PIL`) | Documentation, Review |

---

## 3. Database Schemas

### 3.1 Policy Rules Store (`database/policy_rules.json`)
```json
{
  "allowlist": [
    {
      "id": "rule_20261107_061501",
      "type": "name",
      "value": "code.exe",
      "description": "Visual Studio Code editor",
      "created_at": "2026-11-07 06:15:01"
    }
  ],
  "blocklist": [
    {
      "id": "rule_20261107_061612",
      "type": "ip",
      "value": "198.51.100.1",
      "description": "Observed suspicious C2 beacon",
      "created_at": "2026-11-07 06:16:12"
    }
  ]
}
```

### 3.2 Web Traffic Store (`database/web_traffic_logs.json`)
```json
[
  {
    "id": "req_20261107_073209_184201",
    "domain": "news.ycombinator.com",
    "method": "CONNECT",
    "port": 443,
    "is_blocked": false,
    "category": "CLEAN / ALLOWED",
    "reason": "Verified clean tech news domain",
    "bytes_transferred": 4096,
    "date_time": "2026-11-07 07:32:09",
    "timestamp": 1794033129.542
  },
  {
    "id": "req_20261107_073210_195102",
    "domain": "adservice.google.com",
    "method": "CONNECT",
    "port": 443,
    "is_blocked": true,
    "category": "AD / TRACKER",
    "reason": "Known commercial advertising network: adservice.google.com",
    "bytes_transferred": 0,
    "date_time": "2026-11-07 07:32:10",
    "timestamp": 1794033130.124
  }
]
```

### 3.3 Email Configuration Store (`database/email_config.json`)
```json
{
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "use_tls": true,
  "sender_email": "security-edr@yourdomain.com",
  "sender_password": "",
  "recipient_email": "admin@yourdomain.com",
  "alert_on_critical": true,
  "subject_prefix": "[AEGISSHIELD EDR ALERT]"
}
```

### 3.4 IP Geolocation & ASN Cache (`database/geo_cache.json`)
```json
{
  "8.8.8.8": {
    "hostname": "dns.google",
    "org": "Google Public DNS",
    "asn": "AS15169",
    "country": "US",
    "verdict": "GENUINE CLOUD / CDN",
    "is_genuine": true,
    "cached_at": 1794033120.0
  }
}
```

---

## 4. Version Control & Continuous Maintenance Assets

### 4.1 Git & Upstream Repository
- **Remote URL:** `https://github.com/thannasudhir9/AI-MonitorEngine-Spyware.git`
- **Tracked Branch:** `main`
- **Protection File (`.gitignore`):** Excludes Python bytecode caches (`__pycache__`), quarantine files (`quarantine/*` except `.gitkeep`), and OS artifacts, ensuring clean repository clones across development environments.

### 4.2 Batch Automation Suite
- `start_all.bat`: Concurrently initializes both the EDR web server (`:8888`) and the AdBlock proxy (`:8080`).
- `start_dashboard.bat`: Starts the backend server and opens the SOC cyber console.
- `start_adblocker.bat`: Runs the high-performance intercepting web proxy.
- `run_tests.bat`: Executes the 22-step master diagnostic test runner.
- `generate_screenshots.bat`: Renders fresh 1600x1000 UI state captures into `screenshots/`.


