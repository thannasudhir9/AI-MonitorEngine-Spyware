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
- **Top KPI Navigation Counters:**
  - `TOTAL PROCESSES`: Active running Windows processes.
  - `FLAGGED THREATS`: Clickable pill navigating directly to Threat Intelligence with blocked history.
  - `CRITICAL THREATS`: Clickable pill triggering immediate focus on high-risk detections or eradication logs.
  - `REMOTE DESKTOP / RMM`: Active remote tools requiring audit.
  - `NETWORK CONNECTIONS`: Active foreign and local sockets.
  - `ADS / TRACKERS BLOCKED`: Cumulative web telemetry blocked.

### 1.3 Interactive Navigation Matrix
10 dedicated cybersecurity views accessible via top tab navigation:
1. **Threat Intelligence (`view-threats`):** Active threat cards, severity indicators, and historical quarantined/terminated ledger.
2. **Process Explorer (`view-processes`):** Live Windows process table, CPU/Memory telemetry, digital signatures, and terminated history.
3. **Remote Desktop Hunter (`view-rmm`):** Active AnyDesk, TeamViewer, VNC, ScreenConnect sessions, and eradicated tools history.
4. **Network Radar (`view-network`):** Active process sockets, reverse DNS, ASN, genuineness verdict, and Windows Firewall IP blocklist.
5. **System AdBlocker (`view-adblock`):** Live proxy metrics, blocked domain statistics, browsed history, and live traffic stream.
6. **Access Control (`view-policy`):** Executable, path, hash, and IP allowlist/blocklist management with netsh firewall sync.
7. **Persistence Hunter (`view-persistence`):** Windows Registry Run keys, Startup folder items, and Scheduled Tasks inspector.
8. **Threat Simulator Lab (`view-simulator`):** Safe controlled generation of test threats (Trojan droppers, LOLBins, RMM beacons) for SOC validation.
9. **Email Alerting (`view-email`):** Resend API and SMTP settings, recipient configurations, and test dispatch triggers.
10. **Documentation Hub (`view-docs`):** Complete interactive web documentation portal embedded natively in the application.

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


