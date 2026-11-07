# Plan: Table Size Expansion & Advanced CSS Modernization

## 1. Executive Summary & Objective
The user has requested:
> **"EXPAND table size , improve css."**

Currently, several data tables across the dashboard (such as Processes, Staging Zone Droppers, Threat Ledger, Web Browsing History, Network Radar, Services, Autoruns, and Access Control) are constrained to narrow, restrictive heights (e.g. `max-h-[400px]` or `max-h-[500px]`) and basic borders. On modern displays, this creates unnecessary nested vertical scrolling, displays only 8-12 rows simultaneously, and leaves significant viewport real estate unused.

This plan details the systematic expansion of all tables across the application, standardizing them onto a unified **Shadcn Enterprise Table Architecture**, increasing vertical heights by 50–80%, providing expansive cell padding, implementing frosted glassmorphism sticky headers, smooth alternating zebra striping, rich tactile action buttons, and ultra-smooth 8px rounded scrollbars for both Light Clean SOC and Dark Cyber SOC modes.

---

## 2. Key Technical Improvements

### 2.1 Table Size Expansion (Vertical & Horizontal Real Estate)
- **Container Height Expansion:**
  - Increase table scroll viewport heights from restrictive 400px–500px to dynamic `min-h-[520px] max-h-[calc(100vh-240px)]` (with fallback to `max-h-[750px]`).
  - Staging Zone Droppers: Expanded from cramped `max-h-[400px]` to `min-h-[460px] max-h-[680px]`.
  - Live Running Processes: Expanded from `max-h-[500px]` to `min-h-[580px] max-h-[780px]` (permitting 20+ live processes in full view).
  - Network Radar & Origin Tracer: Expanded from `max-h-[550px]` to `min-h-[540px] max-h-[750px]`.
  - Windows Services: Expanded to `min-h-[560px] max-h-[calc(100vh-230px)]`.
  - Web Traffic & Browsing History: Expanded from `max-h-[550px]` to `min-h-[540px] max-h-[750px]`.
  - Persistent Threat Tracking Ledger: Expanded from `max-h-[520px]` to `min-h-[540px] max-h-[750px]`.
- **Horizontal Width & Cell Proportions:**
  - Standardize all table layouts to `w-full border-collapse separate border-spacing-0`.
  - Expand cell padding from tight `10px 14px` to spacious `14px 18px` (`py-3.5 px-4.5`).
  - Generous column width allocations preventing awkward truncation of file paths, hashes, IP addresses, and anomaly descriptions.

### 2.2 Advanced CSS Modernization
- **Frosted Glass Sticky Headers:**
  - Frosted backdrop blur (`backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px)`).
  - Light Mode: `background-color: rgba(248, 250, 252, 0.95); border-bottom: 2px solid #e2e8f0; color: #334155; font-weight: 700;`.
  - Dark Mode: `background-color: rgba(15, 23, 42, 0.95); border-bottom: 2px solid #1e293b; color: #94a3b8; font-weight: 700;`.
  - Letter spacing: `0.06em uppercase` for high-end cybersecurity HUD feel.
- **Zebra Striping & Hover States:**
  - Light Mode: `#ffffff` base with subtle `rgba(248, 250, 252, 0.6)` even row striping; smooth `hover:bg-slate-100/90` with left accent highlight.
  - Dark Mode: `rgba(17, 26, 46, 0.7)` base with `rgba(15, 23, 42, 0.5)` even row striping; smooth `hover:bg-slate-800/60` on cursor hover.
- **Tabular Monospace Figures:**
  - Numbers, PIDs, Ports, Dates, and Hashes rendered in `font-mono tabular-nums` for clean vertical column alignment.
- **Ultra-Smooth 8px Rounded Scrollbars:**
  - Modern custom webkit scrollbars specifically tailored for table scroll containers (`width: 8px; height: 8px; border-radius: 9999px;`).

---

## 3. Implementation Steps & Target Files
1. **CSS Enhancement:** Update [`frontend/css/dashboard.css`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/frontend/css/dashboard.css) with new `.shadcn-table-card`, `.shadcn-table-scroll`, expanded sizes, glass headers, and row striping.
2. **HTML Markup Standardization:** Update [`frontend/index.html`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/frontend/index.html) across all views:
   - Threat Tracking Ledger & Eradicated History
   - Network Adapters (NICs)
   - Staging Zone Dropper Hunter
   - Windows Services Control Panel
   - Network Socket Radar
   - LOLRMM Remote Desktop Hunter
   - Live Running Processes
   - Allowlist & Blocklist Policy Rules
   - Web Traffic History & AdBlock Domain Rules
   - Persistence & Startup Hunter
   - Incident Audit Trail
3. **Mirror Plan:** Mirror artifact to [`brain_archive/table_expansion_and_css_enhancement_plan.md`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/brain_archive/table_expansion_and_css_enhancement_plan.md).
4. **Test Suite Expansion:** Update [`tools/test_engine.py`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/tools/test_engine.py) to add tests verifying expanded table dimensions and new CSS selectors.
5. **Screenshot Regeneration:** Execute [`tools/screenshot_engine.py`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/tools/screenshot_engine.py) for all 18 views.
6. **Documentation Suite:** Update [`README.md`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/README.md), [`frontend/docs.html`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/frontend/docs.html), [`docs/SESSION_INFO.md`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/docs/SESSION_INFO.md), and [`docs/SESSION_PROMPTS_AND_RESPONSES.md`](file:///c:/Users/thann/Downloads/AntiGravity/SpywareProcessMon/docs/SESSION_PROMPTS_AND_RESPONSES.md).
7. **Git Push:** Stage, commit, and push upstream to `origin/main`.
