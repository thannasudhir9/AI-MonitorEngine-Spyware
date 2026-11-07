# System Diagnostics, Drive Dropper Hunter & Suspicious Threat Ledger Integration Plan

**Session Timestamp:** 2026-11-07 10:00:00 UTC+01:00  
**Project:** AegisShield Cyber SOC EDR  
**Integration Repositories:**
- `https://github.com/thannasudhir9/SystemInfoCheck`
- `https://github.com/thannasudhir9/DriveOrganiserAndAnalyzer-AG2.0`

---

## 1. Executive Summary & Architecture Additions

In response to user directives:
1. **System Diagnostics & Security Baseline Engine (`backend/system_info.py`)**:
   - Audits Windows kernel, OS build (26100 AMD64), CPU physical cores (24) and logical threads, frequencies, RAM/Swap metrics, active network interface cards (NICs), MAC addresses, link speeds, and security baseline posture.
2. **Drive Storage & Malware Dropper Staging Analyzer (`backend/drive_analyzer.py`)**:
   - Inspects physical and logical drive partitions (`C:\`, `D:\`), capacity gauges, and usage percentages.
   - Hunts for malicious dropper staging files (`.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.hta`, `.dll`) in `%TEMP%`, `AppData\Local\Temp`, `C:\Windows\Temp`, and `C:\Users\Public`.
   - 1-click temp dropper cleaning action returning exact files cleaned and MB freed.
3. **Suspicious Threat Heuristics & Persistent Threat Tracking Ledger (`backend/threat_ledger.py`)**:
   - Flags suspicious heuristic anomalies with risk scores $20 - 74$ (e.g. `%TEMP%` path anomaly, LOLBIN cmdline arguments, high entropy, unverified signatures) alongside critical threats ($\ge 75$).
   - Maintains an immutable, persistent chronological tracking ledger (`logs/threat_tracking_ledger.json`) tracking first seen, last seen, observation count, PID, executable, risk score, severity, category, and lifecycle states (`ACTIVE`, `INACTIVE`, `ERADICATED`, `QUARANTINED`).
4. **UI/UX Modernization**:
   - Upgraded dashboard with 6-card top KPI ticker (`ACTIVE PROCS`, `CRITICAL THREATS`, `SUSPICIOUS THREATS`, `REMOTE / RMM`, `SYS & STORAGE`, `HEALTH INDEX`).
   - Added sub-views for `Active Risks`, `Critical Threats`, `Suspicious Threats`, `Threat Tracking Ledger`, and `Blocked History`.
   - Added dedicated tabs for `view-sysinfo` (System Diagnostics) and `view-drives` (Storage & Dropper Hunter).
5. **Testing & Screenshot Verification**:
   - Expanded test suite to **46 automated tests across 17 subsystems (100% pass rate)**.
   - Generated **17 HD 1600x1000 screenshots** covering all views and modals.
