# AegisShield EDR: System & UX Design Document

**System Name:** AegisShield Enterprise Cyber Defense Suite  
**App Title:** AI Monitoring Engine • AdBlocker Engine • Web Tracker • Proc Mon Engine  
**Author:** Sudhir Kumar Thanna  
**Version:** v2.7.0-Enterprise-Services  
**Updated:** 2026-11-07  

---

## 1. Visual & Interactive Design Principles

### 1.1 Modern Shadcn Design & Default Light Mode
AegisShield adopts clean, minimalist design principles inspired by **shadcn/ui**, engineered with high contrast, crisp typography, and responsive micro-interactions:
- **Default Theme — Light Clean SOC Mode:** Designed for executive readability and daylight SOC operations. Pure white card surfaces (`#ffffff`) on off-white canvas (`#f8fafc`), subtle borders (`#e2e8f0`), high-contrast dark slate typography (`#0f172a` and `#1e293b`), and vibrant semantic accents.
- **Dark Cyber SOC Theme:** Obsidian void (`#080c14`) background paired with glassmorphic cards (`rgba(17, 26, 46, 0.75)`), 1px cyan border glows (`rgba(6, 182, 212, 0.15)`), and neon status accents.
- **Dynamic Theme Switcher:** Smooth instant transition without page refresh; selection persisted across browser sessions via `localStorage.getItem('aegis_theme')` (defaults to `'light'`).

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
13 dedicated cybersecurity views accessible via top tab navigation:
1. **Threat Intelligence (`view-threats`):** Active threat cards, severity indicators, sub-views for `All Risks`, `🚨 Critical`, `⚠️ Suspicious`, `📜 Threat Tracking Ledger`, and `🛡️ Blocked History`.
2. **Windows Services Control Panel (`view-services`):** Native `services.msc` management equivalent: status, host PIDs, startup type configuration, and Start/Stop/Restart lifecycle controls.
3. **System Diagnostics (`view-sysinfo`):** Comprehensive hardware audit, OS kernel, 24 CPU cores load, RAM/Swap, network NICs, and security baseline from `SystemInfoCheck`.
4. **Storage & Dropper Hunter (`view-drives`):** Drive partitions, capacity utilization bars, %TEMP% dropper hunter, and 1-click clean temp action from `DriveOrganiserAndAnalyzer-AG2.0`.
5. **Network Radar (`view-network`):** Active process sockets, reverse DNS, ASN, genuineness verdict, and Windows Firewall IP blocklist.
6. **System AdBlocker (`view-adblock`):** Live proxy metrics, blocked domain statistics, browsed history, and live traffic stream.
7. **Remote Desktop Hunter (`view-rmm`):** Active AnyDesk, TeamViewer, VNC, ScreenConnect sessions, and eradicated tools history.
8. **Process Explorer (`view-processes`):** Live Windows process table, CPU/Memory telemetry, digital signatures, and terminated history.
9. **Access Control (`view-policy`):** Executable, path, hash, and IP allowlist/blocklist management with netsh firewall sync.
10. **Persistence Hunter (`view-persistence`):** Windows Registry Run keys, Startup folder items, and Scheduled Tasks inspector.
11. **Threat Simulator Lab (`view-simulation`):** Safe controlled generation of test threats (Trojan droppers, LOLBins, RMM beacons) for SOC validation.
12. **Email Alerting (`view-email`):** Resend API and SMTP settings, recipient configurations, and test dispatch triggers.
13. **Documentation Hub (`view-docs`):** Complete interactive web documentation portal embedded natively in the application.

---

### 1.7 Suspicious Threat Tracking Ledger UX Design
- **Chronological Anomaly Ledger Table:** Displays First Seen, Last Seen, Observation Count, Target PID, Threat Name, Binary Path, Risk Score with colored badges (`CRITICAL`, `SUSPICIOUS`, `HIGH`, `MEDIUM`), Heuristic Reasons, and Lifecycle Status (`ACTIVE` with pulsing red dot, `ERADICATED`, `QUARANTINED`, `INACTIVE`).
- **Real-Time Interactive Filter Toolbar:** Search by executable name, path, PID, or category; filter by severity and lifecycle state.

### 1.8 Shadcn UI System, Segmented Tabs & Thin Scrolling UX
- **Shadcn Segmented Pill Navigation (`.shadcn-tabs-nav`):** Horizontal segmented container with pill tabs (`.shadcn-tab-item`), subtle active pill background, smooth hover transitions, and overflow handling.
- **Modern Smooth Thin Scrollbars:** Custom 6px webkit scrollbars with pill thumbs, ensuring clean aesthetics without intrusive native scrollbars.
- **Sticky Table Headers:** `sticky top-0 z-10 backdrop-blur` keeps column headers in view during deep table exploration.
- **High-Contrast Light Mode Badges:** Soft pastel backgrounds (`#fff1f2`, `#fffbeb`, `#f0fdf4`, `#f0f9ff`) with dark, readable font foregrounds.

### 1.9 Windows Services Management (`services.msc`) UX Design
- **KPI Metrics Header:** Summary cards displaying Total Services (331), Running Services (153), Stopped Services (178), and RMM / Threat Linked Services (1).
- **Search & Filter Strip:** 7 Filter pills (`All`, `Running`, `Stopped`, `Automatic`, `Manual`, `Disabled`, `RMM / Threats`) paired with instantaneous search across service names, display titles, PIDs, and paths.
- **Direct Interactive Controls:** Inline dropdown selectors to modify startup modes and 1-click Start, Stop, and Restart buttons with immediate toast confirmations.
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


