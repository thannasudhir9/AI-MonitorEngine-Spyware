# Implementation Plan: Light Mode Typography, Font Formatting & Modern CSS Overhaul (Shadcn & Bootstrap)

## Executive Summary
This plan addresses the UI/UX enhancement request:
> *"improve text and color font formatting in light mode and css, use shadcn , bootstratp and others from web whichever is best"*

In light mode, low-contrast text classes (`text-amber-300`, `text-cyan-300`, `text-purple-300`, `text-slate-400`, `text-red-400`) and dark container backgrounds can create legibility issues. By implementing modern **shadcn/ui** and **Bootstrap 5.3+** design tokens, high-contrast typography hierarchies, and semantic color scales, we ensure WCAG AAA contrast, razor-sharp font rendering, and seamless theme switching.

---

## Technical Objectives & Architecture

### 1. Typography & Font System
- **Font Stack:**
  - Sans-Serif: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`
  - Monospace: `JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace`
- **Rendering & Smoothing:**
  - `-webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility;`
- **Tabular Numerics:**
  - `font-feature-settings: "cv02", "cv03", "cv04", "cv11", "tnum"; font-variant-numeric: tabular-nums;` for all counters, PIDs, risk scores, memory/CPU metrics, and timestamps.
- **Hierarchy & Weights:**
  - Headings (H1/H2/H3): 700 / 600 weight, letter spacing `-0.025em` to `-0.02em` (tracking-tight), high-contrast slate-900 (`#0f172a`).
  - Body Text: 400 / 500 weight, slate-700 (`#334155`) for readable descriptions (no washed-out gray).
  - Captions & Meta: 500 weight, slate-500 (`#64748b`).
  - Table Headers: 600 weight, 11px uppercase with `letter-spacing: 0.05em`, slate-600 (`#475569`).

### 2. Semantic Color System (Shadcn + Bootstrap Tokens)
| Semantic Role | Dark Mode (Cyber SOC) | Light Mode (Shadcn / Clean SOC) | Light Text | Light Surface | Light Border |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Critical / Danger** | `#ef4444` / Crimson | `#dc2626` / Red-600 | `#b91c1c` (Red-700) | `#fef2f2` (Red-50) | `#fecaca` (Red-200) |
| **Suspicious / Warning**| `#f59e0b` / Amber | `#d97706` / Amber-600 | `#b45309` (Amber-700) | `#fffbeb` (Amber-50) | `#fde68a` (Amber-200) |
| **Safe / Clean / Ok** | `#10b981` / Emerald | `#16a34a` / Green-600 | `#15803d` (Green-700) | `#f0fdf4` (Green-50) | `#bbf7d0` (Green-200) |
| **Info / Sky / Blue** | `#06b6d4` / Cyan | `#0284c7` / Sky-600 | `#0369a1` (Sky-700) | `#f0f9ff` (Sky-50) | `#bae6fd` (Sky-200) |
| **Purple / RMM / Stealth**| `#8b5cf6` / Purple | `#7c3aed` / Violet-600 | `#6d28d9` (Violet-700) | `#faf5ff` (Violet-50)| `#e9d5ff` (Violet-200)|
| **Neutral / Slate** | `#f8fafc` / `#94a3b8` | `#0f172a` / Slate-900 | `#334155` (Slate-700) | `#ffffff` (White) | `#e2e8f0` (Slate-200)|

### 3. Component Enhancements
- **Header Action Buttons:**
  - In light mode, styled like Shadcn secondary buttons: `#ffffff` background, `1px solid #e2e8f0` border, `#0f172a` text with subtle icons, hover `#f8fafc` and `#cbd5e1` border, `shadow-sm`.
- **Top KPI Metric Cards:**
  - Values render in rich dark semantic colors (`#b91c1c` for Critical, `#b45309` for Suspicious, `#0369a1` for RMM, `#4338ca` for Storage, `#15803d` for Health, `#0f172a` for Active Procs).
- **Sub-View Filter Rails & Pills:**
  - Active button: Deep slate `#0f172a` background with white text, or clean white with slate-900 and border.
  - Inactive buttons: Crisp slate-600 (`#475569`) text on transparent/subtle background, hover `#0f172a`.
- **Form Controls:**
  - Inputs, search boxes, and dropdown selects: White background, slate-300 border (`#cbd5e1`), slate-900 text, slate-400 placeholder, focus ring `2px solid #0284c7`.
- **Tables & Modals:**
  - Table rows have subtle border bottom `#f1f5f9` and hover background `#f8fafc`.
  - Sticky table headers with subtle slate `#f8fafc` backdrop and blur.
  - Modals feature crisp white backgrounds, subtle shadows, and slate-900 title typography.
- **Documentation Hub (`frontend/docs.html`):**
  - Updated to match the refined light mode styling with clean white cards, high-contrast code blocks, and crisp sidebar navigation.

---

## Verification & Protocol Execution
1. Update `frontend/css/dashboard.css` with comprehensive light mode styling rules and typography improvements.
2. Update `frontend/index.html` to refine button classes, KPI cards, and sub-view bars.
3. Update `frontend/js/app.js` to ensure dynamically created badges and tables use high-contrast classes in light mode.
4. Update `frontend/docs.html` to harmonize styling.
5. Re-run `tools/test_engine.py` (target: 56/56 passing).
6. Re-run `tools/screenshot_engine.py` to regenerate all 18 HD screenshots reflecting the improved typography.
7. Update all documentation files in `docs/` and root `README.md`.
8. Commit and push cleanly to GitHub `origin/main`.
