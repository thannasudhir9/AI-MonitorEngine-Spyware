# Antigravity Persistent Memory & Operational Rules

**Status:** ACTIVE & PERMANENT  
**Effective Date:** 2026-11-07  
**System Architect:** Sudhir Kumar Thanna  

---

## 1. The Golden Directives

For every current and future task in this workspace, Antigravity must execute the following cycle without exception:

1. **CREATE, UPDATE, APPEND - ALWAYS:**
   - Never remove or overwrite historical context, decisions, logs, or features.
   - Always append newly introduced capabilities, schemas, endpoints, and architectural changes.
   - Maintain continuous traceability across the entire lifecycle of the application.

2. **MIRROR ALL BRAIN FILES TO PROJECT DIRECTORY:**
   - Every artifact, plan, or research document created in `<appDataDir>\brain\<conversation-id>` must be mirrored to `brain_archive/` in the project root.
   - Ensure git ignore rules protect raw session logs and secrets (`brain_archive/.system_generated/`, `database/email_config.json`).

3. **CONTINUOUS DOCUMENTATION SYNCHRONIZATION:**
   Every modification must be reflected across all 8 core documentation assets:
   - `docs/DESIGN.md` & `docs/DESIGN_AND_ARCHITECTURE.md`
   - `docs/ARCHITECTURE.md`
   - `docs/PROJECT_STRUCTURE.md`
   - `docs/CODE_EXPLANATION.md`
   - `docs/COMMANDS.md`
   - `docs/SESSION_INFO.md`
   - `docs/SESSION_PROMPTS_AND_RESPONSES.md`
   - `README.md`

4. **DIAGNOSTIC TEST ENGINE (100% PASS RATE):**
   - Execute `python tools/test_engine.py` after code changes to ensure all endpoints, heuristics, proxy rules, and integrations pass.

5. **VISUAL CAPTURE ENGINE:**
   - Execute `python tools/screenshot_engine.py` to ensure all 14+ UI views are rendered into high-definition 1600x1000 PNGs in `screenshots/`.

6. **SAFE UPSTREAM GIT SYNCHRONIZATION:**
   - Commit all tracked updates and push to `origin/main` on GitHub (`thannasudhir9/AI-MonitorEngine-Spyware`).
   - Strictly avoid committing raw API secrets to satisfy GitHub Secret Scanning and Push Protection rules.

---

## 2. Memory Checklist for Every Subsequent User Request

```markdown
- [ ] 1. Analyze user request in context of existing four-engine suite
- [ ] 2. Implement backend / frontend / tool changes
- [ ] 3. Mirror all brain files and plans to brain_archive/
- [ ] 4. Update and append all 8 documents in docs/ and README.md
- [ ] 5. Run tools/test_engine.py (verify 100% pass across 46 tests & 17 subsystems)
- [ ] 6. Run tools/screenshot_engine.py (verify 17 HD screenshots rendered)
- [ ] 7. Git commit and push cleanly to origin/main
- [ ] 8. Present concise, structured verification to the user

---

## 3. Integrated Subsystems Log

- **Build 2026.11.07-v2.5.0-SOC:**
  - `SystemInfoCheck` Integration: Hardware, OS kernel, 24 CPU cores load, RAM/Swap, network NICs, and security posture baseline (`backend/system_info.py`).
  - `DriveOrganiserAndAnalyzer` Integration: Partition capacities, %TEMP% Dropper Hunter, and 1-click temp cleanup action (`backend/drive_analyzer.py`).
  - Suspicious Threat Detection: Heuristic risk scores 20-74 flagged alongside critical threats (&ge;75).
  - Persistent Threat Tracking Ledger: Chronological anomaly chronicle with lifecycle tracking (`backend/threat_ledger.py`).
  - UI/UX Modernization: Slate-950 dark glassmorphism, 6-card top KPI ticker, interactive sub-views, and 17 HD screenshot captures.

```

