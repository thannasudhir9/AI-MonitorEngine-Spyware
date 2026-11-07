# AegisShield EDR: System & UX Design Document

**System Name:** AegisShield Enterprise Cyber Defense Suite  
**App Title:** AI Monitoring Engine • AdBlocker Engine • Web Tracker • Proc Mon Engine  
**Author:** Sudhir Kumar Thanna  
**Version:** v2.5.0-SOC-Enterprise  
**Updated:** 2026-11-07  

---

## 1. Visual & Interactive Design Principles

### 1.1 Cyber SOC Aesthetics
AegisShield's visual interface is modeled after mission-critical Security Operations Center (SOC) dashboards and military avionics Heads-Up Displays (HUD):
- **Primary Cyber Theme:** Obsidian void (`#080c14`) background paired with glassmorphic cards (`rgba(13, 20, 36, 0.75)`), 1px cyan border glows (`rgba(0, 240, 255, 0.15)`), and neon status accents.
- **Light Clean SOC Theme:** Clean daylight palette (`#f8fafc`) with stark white cards (`#ffffff`), subtle borders (`#e2e8f0`), deep slate typography (`#0f172a`), and sky-blue highlights (`#0284c7`).
- **Dynamic Theme Switcher:** Smooth instant transition without page refresh; selection persisted across browser sessions via `localStorage.getItem('aegis_theme')`.

### 1.2 Enterprise Header Layout
- **Brand Identity:** Neon cyber shield icon with pulsating core.
- **Primary Title:** `AI Monitoring Engine • AdBlocker Engine • Web Tracker • Proc Mon Engine`.
- **SOC Badges:** Live status indicator (`🟢 SYSTEM PROTECTED`), active engine counters, and quick shortcut to `[Docs]`.
- **Top 6-Card KPI Navigation Ticker:**
  - `ACTIVE PROCS`: Live running Windows processes, CPU load, and physical RAM usage.
  - `CRITICAL THREATS`: Clickable neon red card focusing high-risk detections (Score &ge; 75).
  - `SUSPICIOUS THREATS`: Clickable amber card displaying heuristic anomalies (Score 20-74, %TEMP% droppers, LOLBins).
  - `REMOTE / RMM`: Active remote tools (AnyDesk, VNC, RDP) requiring SOC audit.
  - `SYS & STORAGE`: Direct jump to System Diagnostics and Drive space capacity pool.
  - `HEALTH INDEX`: System Health Index with direct link to incident audit ledger.

### 1.3 Interactive Navigation Matrix
12 dedicated cybersecurity views accessible via top tab navigation:
1. **Threat Intelligence (`view-threats`):** Active threat cards, severity indicators, sub-views for `All Risks`, `🚨 Critical`, `⚠️ Suspicious`, `📜 Threat Tracking Ledger`, and `🛡️ Blocked History`.
2. **System Diagnostics (`view-sysinfo`):** Comprehensive hardware audit, OS kernel, 24 CPU cores load, RAM/Swap, network NICs, and security baseline from `SystemInfoCheck`.
3. **Storage & Dropper Hunter (`view-drives`):** Drive partitions, capacity utilization bars, %TEMP% dropper hunter, and 1-click clean temp action from `DriveOrganiserAndAnalyzer-AG2.0`.
4. **Network Radar (`view-network`):** Active process sockets, reverse DNS, ASN, genuineness verdict, and Windows Firewall IP blocklist.
5. **System AdBlocker (`view-adblock`):** Live proxy metrics, blocked domain statistics, browsed history, and live traffic stream.
6. **Remote Desktop Hunter (`view-rmm`):** Active AnyDesk, TeamViewer, VNC, ScreenConnect sessions, and eradicated tools history.
7. **Process Explorer (`view-processes`):** Live Windows process table, CPU/Memory telemetry, digital signatures, and terminated history.
8. **Access Control (`view-policy`):** Executable, path, hash, and IP allowlist/blocklist management with netsh firewall sync.
9. **Persistence Hunter (`view-persistence`):** Windows Registry Run keys, Startup folder items, and Scheduled Tasks inspector.
10. **Threat Simulator Lab (`view-simulation`):** Safe controlled generation of test threats (Trojan droppers, LOLBins, RMM beacons) for SOC validation.
11. **Email Alerting (`view-email`):** Resend API and SMTP settings, recipient configurations, and test dispatch triggers.
12. **Documentation Hub (`view-docs`):** Complete interactive web documentation portal embedded natively in the application.

---

### 1.7 Suspicious Threat Tracking Ledger UX Design
- **Chronological Anomaly Ledger Table:** Displays First Seen, Last Seen, Observation Count, Target PID, Threat Name, Binary Path, Risk Score with colored badges (`CRITICAL`, `SUSPICIOUS`, `HIGH`, `MEDIUM`), Heuristic Reasons, and Lifecycle Status (`ACTIVE` with pulsing red dot, `ERADICATED`, `QUARANTINED`, `INACTIVE`).
- **Real-Time Interactive Filter Toolbar:** Search by executable name, path, PID, or category; filter by severity and lifecycle state.
- **Immediate Eradication Controls:** Direct in-table `Kill`, `Tree Kill`, and `Quarantine` actions.


### 1.4 Elevated Administrator Remediation Modal (`#elevated-kill-modal`)
Designed for non-blocking handling of protected system processes (e.g. `PID 5824 Access Denied`):
- High-contrast warning HUD banner.
- Diagnostic readout detailing PID, process name, owner, and detected Windows Service name.
- Direct copyable PowerShell and Command Prompt kill strings.
- 1-Click Action Buttons: `[⚡ Elevate & Kill via UAC]`, `[🛑 Stop Associated Service]`, `[🚀 Restart AegisShield as Admin]`, and `[Close]`.

### 1.5 Enterprise SOC Footer
Positioned persistently at the bottom of the dashboard:
- **Active Process & PID:** Live readout from backend (`python.exe (PID: 69360)`).
- **Listening Ports:** Port `8888` (EDR & API) and Port `8080` (AdBlock Proxy).
- **Sub-App Badges:** Five active engine badges (`AI Monitor: ON`, `AdBlock: ON`, `Web Tracker: ON`, `Proc Mon: ON`, `Netsh Firewall: ON`).
- **Attribution & Support:** `Support with ❤️ - Sudhir Kumar Thanna`.
- **Live Clock:** Real-time ticking date, UTC/Local time, and ISO timestamp.
- **Deployed Version:** `v2.5.0-SOC-Enterprise (Build 2026.11.07-STABLE)`.

### 1.6 Notification Sound Removal & Silent Mode Control (`#btn-sound-toggle`)
Per user directive, intrusive audio chimes on threat detections, process terminations, and status changes are permanently silenced:
- **Default State:** `state.soundEnabled = false` (Strict Silent Mode).
- **Header Control:** Positioned in top navigation header next to theme toggle (`🔇 Silent`).
- **Zero Sound Synthesis:** Web Audio API context and oscillator frequencies are gated by `if (!state.soundEnabled) return;`.
- **Persistence:** Mute state persisted across page reloads via `localStorage.getItem('aegis_sound')`.


