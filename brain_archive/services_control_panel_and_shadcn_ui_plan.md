# Architectural Plan: Windows Services Control Panel (`services.msc`), Shadcn UI/UX Modernization & Default Light Mode

## 1. Executive Summary

This plan outlines the architecture, backend engineering, REST API specifications, UI/UX redesign inspired by **shadcn/ui**, and default light mode implementation for **AegisShield EDR & Enterprise Endpoint Suite**.

---

## 2. Core Architectural Components

### 2.1 Backend Engine: Windows Services Manager (`backend/services_manager.py`)
Provides comprehensive inspection and control of Windows Services (equivalent to `services.msc`), with threat correlation:
- **Service Enumeration:** Queries Windows Services via CIM / WMI / native PowerShell / `sc.exe queryex`:
  - `name`: Service short identifier (e.g. `AnyDesk`, `WinDefend`, `wuauserv`).
  - `display_name`: Human-readable name (e.g. `AnyDesk Service`, `Windows Defender Antivirus Service`).
  - `status`: `RUNNING`, `STOPPED`, `PAUSED`, `START_PENDING`, `STOP_PENDING`.
  - `start_type`: `AUTOMATIC`, `MANUAL`, `DISABLED`, `BOOT`, `SYSTEM`.
  - `pid`: Process ID of host executable (if running).
  - `binpath`: Absolute path to binary executable with arguments.
  - `description`: Service functional description.
  - `is_threat_associated`: Flagged if hosting or associated with an identified suspicious / RMM tool.
- **Service Lifecycle Control Operations:**
  - `start_service(name)`: Invokes `sc start <name>` with verification.
  - `stop_service(name)`: Invokes `sc stop <name>` with timeout verification.
  - `restart_service(name)`: Sequence of `sc stop` followed by `sc start`.
  - `set_startup_type(name, start_type)`: Invokes `sc config <name> start= auto|demand|disabled`.

### 2.2 REST API Endpoints (`backend/server.py`)
- `GET /api/services`: Retrieve all installed Windows services with real-time state, PIDs, and metadata.
- `GET /api/services/{name}`: Retrieve detailed metadata for a single service.
- `POST /api/services/{name}/start`: Start service.
- `POST /api/services/{name}/stop`: Stop service.
- `POST /api/services/{name}/restart`: Restart service.
- `POST /api/services/{name}/config`: Set startup type (`auto`, `manual`, `disabled`).

### 2.3 UI/UX Design Modernization (Shadcn UI System Principles)
- **Design Foundations:**
  - Clean zinc/slate neutral palette, sharp micro-radii (`rounded-xl` for cards, `rounded-lg` for inputs/buttons), 1px crisp borders.
  - High-performance horizontal tabs with active pill indicators and overflow handling.
  - Polished typography with high contrast (`text-slate-900` dark text on `bg-white` card surfaces in light mode).
  - Thin modern scrollbars (`6px` width, smooth scroll pill).
- **Default Light Mode:**
  - Set default theme to **Light Clean SOC Mode** across both the frontend application and the documentation hub.
  - Persistent user toggle in `localStorage`.
  - Flawless contrast: no washed-out text, dark headers, crisp badge accents (rose, emerald, amber, sky).

### 2.4 Diagnostic Tests & Visual Captures
- Expand `tools/test_engine.py` to test service enumeration, status retrieval, and API responses (target: 50+ passing tests).
- Expand `tools/screenshot_engine.py` to capture View 18: `18_windows_services_control_panel.png`.

---

## 3. Implementation Steps

1. **Backend Engine:** Create `backend/services_manager.py` with multi-method fallback (CIM/WMI/PowerShell/sc).
2. **REST API:** Wire services routes into `backend/server.py`.
3. **Frontend UI:**
   - Add "Windows Services" (`services`) tab and sub-navigation in `frontend/index.html`.
   - Update CSS classes in `frontend/index.html` and `frontend/js/app.js` with shadcn style tokens and default light mode.
   - Implement service filtering (Running, Stopped, Automatic, RMM/Threats) and search.
4. **Docs Hub Update:** Add Services Panel and View 18 screenshot to `frontend/docs.html`.
5. **Testing & Verification:** Run `tools/test_engine.py` (verify 100% pass) and `tools/screenshot_engine.py`.
6. **Documentation & Git:** Synchronize all docs and push upstream to GitHub `origin/main`.
