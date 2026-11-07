# Implementation Plan: Level 1 & Level 2 Structured Navigation, Dark Mode Toggle Fix, All-Pages Table Overhaul & Modern Scrollbars

## 1. Executive Summary
This plan addresses the three core requirements in the latest user request:
1. **Dark Mode Toggle Fix:** Resolve the issue preventing users from toggling between Light Mode and Dark Mode. Ensure both CSS tokens and DOM class lists (`dark`, `theme-dark`, `light`, `theme-light`) seamlessly switch without state lock.
2. **Two-Level Navigation (Level 1 & Level 2):** Replace the single overflowing 14-tab horizontal strip with a structured, non-scrolling two-tier navigation:
   - **Level 1 (5 Core SOC Categories):** `Threat Defense & Intel`, `Endpoint & System Monitor`, `Network & AdBlocker`, `Policies & Resilience`, `Reports & Knowledge`.
   - **Level 2 (Active Sub-Tabs):** Immediately visible secondary pill selector displaying only the relevant sub-views for the chosen Level 1 category.
3. **All-Pages Table Overhaul & Modern Scrollbars:** Refine data grids, sticky headers, cell padding, high-contrast badges, and custom ultra-thin (6px) rounded scrollbars across all 10+ data tables in the application.

---

## 2. Technical Architecture & Modifications

### 2.1 Dark Mode Toggle Fix
- **Root Cause Analysis:**
  - `setTheme()` in `frontend/js/app.js` only added/removed `theme-light` on `document.body` and `document.documentElement`, but never added `dark` to `document.documentElement` or `document.body`.
  - Tailwind CSS relies on `darkMode: 'class'`, requiring the literal `dark` class on the root element.
  - CSS `:root` contained light mode variables, and without `.dark` class on root, Tailwind's dark utility classes (`dark:bg-slate-900`, `dark:text-slate-100`) remained inactive.
- **Resolution:**
  - In `setTheme(theme, notify)`:
    - If `dark`: Add `dark` and `theme-dark` to both `<html>` and `<body>`; remove `light` and `theme-light`. Update toggle label to `'Light Mode'` and icon to `'sun'`.
    - If `light`: Add `light` and `theme-light` to both `<html>` and `<body>`; remove `dark` and `theme-dark`. Update toggle label to `'Dark Mode'` and icon to `'moon'`.
    - Persist to `localStorage.setItem('aegis_theme', theme)`.
  - In `frontend/css/dashboard.css`:
    - Ensure `.dark, body.dark, html.dark body` have full dark cyber background `#080c14 !important`, card background `rgba(19, 28, 49, 0.7) !important`, and light text `#f8fafc !important`.
    - Ensure light mode overrides only apply when `.theme-light` or `html.light` is present.

### 2.2 Two-Level (Level 1 / Level 2) Non-Scrolling Navigation
- **Level 1 Categories (Visible horizontally without scrolling):**
  1. `cat-threats`: **Threat Defense & Intel** (`Active Threats`, `Threat Tracking Ledger`, `RMM & Remote Desktop`, `Incident Eradication Audit`)
  2. `cat-endpoints`: **Endpoint & System Monitor** (`Windows Services (services.msc)`, `Process Monitor`, `System Diagnostics`, `Storage & Dropper Hunter`)
  3. `cat-network`: **Network & AdBlocker** (`Network Radar & Sockets`, `AdBlocker & Web Analytics`)
  4. `cat-policy`: **Policies & Resilience** (`Access Rules & Firewall`, `Persistence & Startup`, `Simulation Lab`)
  5. `cat-reports`: **Reports & Knowledge** (`Email Posture Reports`, `Documentation Hub`)
- **Level 2 Sub-Nav Container:**
  - Positioned directly below Level 1.
  - Dynamically switches sub-tab pills based on the active Level 1 selection.
  - Retains direct tab hash support (`#threats`, `#services`, `#processes`, etc.) so top KPI cards, modals, and deep links continue to activate the exact target tab and its parent category.

### 2.3 Table Enhancements Across All Pages
- **Table Design Tokens:**
  - `border-collapse: separate; border-spacing: 0;`
  - Sticky Headers (`sticky top-0 z-10 backdrop-blur-md`): subtle border bottom `#e2e8f0` (light) / `#1e293b` (dark).
  - High contrast header typography: uppercase, 11px font-semibold, letter-spacing `0.05em`.
  - Consistent row height and padding: `py-2.5 px-3.5` for compact readability.
  - Hover highlights: `#f8fafc` (light) / `#162035` (dark).
  - Numerical alignment: `font-mono tabular-nums text-right` for PIDs, memory, ports, and timestamps.
- **Scrollbars:**
  - Modern 6px ultra-thin scrollbar with pill thumb (`border-radius: 9999px`).
  - Light mode: Track `#f1f5f9`, Thumb `#cbd5e1`, Thumb Hover `#94a3b8`.
  - Dark mode: Track `#0b111e`, Thumb `#1e293b`, Thumb Hover `#38bdf8`.

---

## 3. Step-by-Step Implementation Flow
1. **Fix Theme Controller & CSS:**
   - Update `setTheme` and `toggleTheme` in `frontend/js/app.js` and `frontend/docs.html`.
   - Update `frontend/css/dashboard.css` to ensure dark mode properly activates when `.dark` is added.
2. **Re-architect Navigation to Level 1 / Level 2:**
   - Replace the single 14-tab nav in `frontend/index.html` with Level 1 category tabs and Level 2 sub-tab containers.
   - Update tab switching logic in `frontend/js/app.js` (`navigateToTab`, `switchCategory`, URL hash sync).
3. **Enhance Tables & Scrollbars:**
   - Polish table containers and classes in `frontend/css/dashboard.css` and `frontend/index.html`.
4. **Verification:**
   - Run `tools/test_engine.py` (target: 100% pass rate).
   - Run `tools/screenshot_engine.py` to regenerate all 18 HD screenshots.
   - Verify live API and server responses.
5. **Documentation & Upstream Sync:**
   - Update all documentation files in `docs/` and root `README.md`.
   - Commit and push upstream to GitHub `origin/main`.

