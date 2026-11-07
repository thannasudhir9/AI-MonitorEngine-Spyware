# 🛡️ Implementation Plan: AegisShield Advanced Features

This plan outlines the architecture, data models, backend engines, and frontend interfaces for the three requested features:
1. **Allow / Block Policy Control Engine** (Whitelisting & Blacklisting for Processes & IPs)
2. **Automated & On-Demand Email Security Reporting** (SMTP with HTML Incident Reports)
3. **Network Intelligence & Origin Tracer** (Process Network Auditing, IP Geolocation, Reverse DNS, and Genuineness Assessment)

---

## 🏗️ Architectural Overview & File Map

```
SpywareProcessMon/
├── backend/
│   ├── policy_engine.py       # [NEW] Allow/Block rules engine (process names, paths, hashes, IPs)
│   ├── email_notifier.py      # [NEW] SMTP email dispatcher & HTML threat report generator
│   ├── network_tracer.py      # [NEW] Network process auditor, IP reverse DNS, GeoIP & Genuineness scorer
│   ├── config.py              # [MODIFY] Add database paths for rules, email settings, and geo cache
│   ├── detector.py            # [MODIFY] Integrate policy engine (skip allowed, flag/auto-kill blocked)
│   ├── remediator.py          # [MODIFY] Support IP firewall blocking & policy enforcement
│   └── server.py              # [MODIFY] Expose REST APIs for policies, email dispatch, and network tracer
├── database/
│   ├── policy_rules.json      # [NEW] Persistent allowlist and blocklist rules
│   ├── email_config.json      # [NEW] SMTP server configurations
│   └── geo_cache.json         # [NEW] Cached IP geolocation and reputation lookups
├── frontend/
│   ├── index.html             # [MODIFY] Add Network Tracer, Policy Rules, and Email Settings views
│   ├── css/dashboard.css      # [MODIFY] Add styling for genuineness badges, IP tables, and forms
│   └── js/app.js              # [MODIFY] UI controllers for network explorer, allow/block actions, email dispatch
└── README.md                  # [MODIFY] Document new features, CLI commands, and usage
```

---

## 📋 Detailed Feature Specifications

### 1. Allow & Block Policy Engine (`backend/policy_engine.py`)

#### Purpose
Enables security administrators to explicitly **trust (allow)** or **ban (block)** processes, executable hashes, and remote IP addresses.

#### Capabilities
* **Allowlist (Whitelist):**
  * Processes, paths, or SHA256 hashes marked as **Allowed** will have their threat scores neutralized to 0, suppress alerts, and will be protected from manual or bulk termination.
* **Blocklist (Blacklist):**
  * Processes or hashes marked as **Blocked** will be flagged as `CRITICAL POLICY VIOLATION` (Score: 100) and can be set to automatically terminate on sight.
* **IP Blocklist (Network Firewall Integration):**
  * Remote IP addresses marked as **Blocked** can be actively blocked via Windows Firewall (`netsh advfirewall firewall add rule name="AegisShield Block IP" dir=out action=block remoteip=...`) and any process currently connected to that IP will have its socket flagged or severed.
* **Persistence:** Saved in `database/policy_rules.json` with rule ID, type, value, target, date added, and reason.

#### API Endpoints
* `GET /api/policy/rules` — Retrieve all allowed and blocked rules.
* `POST /api/policy/allow` — Add process name, executable path, or SHA256 to allowlist.
* `POST /api/policy/block` — Add process or IP to blocklist.
* `DELETE /api/policy/rule/{rule_id}` — Remove a rule.

---

### 2. Email Incident & Status Reporting (`backend/email_notifier.py`)

#### Purpose
Allows administrators to send full system security posture reports, incident alerts, and network telemetry to any email address via standard SMTP (Gmail, Outlook, custom corporate SMTP, etc.).

#### Capabilities
* **Configurable SMTP Settings:**
  * SMTP Server host, port (465 SSL or 587 STARTTLS), sender email, username, app password, and default recipient.
  * Settings persisted locally in `database/email_config.json`.
* **HTML Email Security Report:**
  * **System Posture Banner:** Overall health index, scan timestamp, host name, OS version.
  * **Threat Breakdown:** Critical, High, and Medium threats with triggered heuristic vectors.
  * **Network Telemetry Table:** Processes using network, remote IPs, reverse DNS, and country.
  * **Remediation Summary:** Processes terminated, trees eradicated, and files quarantined.
* **Dispatch Triggers:**
  * **On-Demand:** One-click "Send Security Report to Email" button on the dashboard.
  * **Automated Alerting:** Configurable trigger to automatically dispatch an alert when a **CRITICAL** threat or unauthorized RAT is detected.
  * **Test Email Dispatch:** "Send Test Email" button to verify SMTP credentials before enabling alerting.

#### API Endpoints
* `GET /api/email/config` — Get SMTP settings (passwords masked).
* `POST /api/email/config` — Save SMTP configuration.
* `POST /api/email/send-test` — Dispatch a verification email.
* `POST /api/email/send-report` — Generate and dispatch full security report.

---

### 3. Network Intelligence & Origin Tracer (`backend/network_tracer.py`)

#### Purpose
Audits **all processes using the network**, maps remote IPs, resolves reverse DNS hostnames, traces geographical source, and assesses whether the remote endpoint and local process are **genuine** or suspicious.

#### Capabilities
* **Network Process Enumeration:**
  * Scans active TCP/UDP sockets grouped by PID and executable.
  * Calculates total network-active processes, total listening ports, and established outbound connections.
* **Source Tracing (Reverse DNS & Geolocation):**
  * Resolves remote IP to hostname via PTR reverse DNS lookup (`socket.gethostbyaddr`).
  * Traces country, city, ISP, ASN, and organization using a local lookup engine with online fallback (IP-API / whois) and caching in `database/geo_cache.json`.
* **Genuineness & Reputation Classification Engine:**
  * Evaluates remote endpoints across verified intelligence rules:
    1. **`GENUINE CLOUD / CDN`**: IP belongs to verified networks of Microsoft/Azure, Google/GCP, Cloudflare, AWS, Apple, Akamai, or GitHub.
    2. **`PRIVATE LAN`**: Local or private subnet (`192.168.x`, `10.x`, `172.16.x`, `127.0.0.1`).
    3. **`SUSPICIOUS / RAT / C2`**: Remote port matches known Trojan/RAT ports (`1177`, `1604`, `2404`, `4444`, `4782`, `5555`, `6606`, etc.) or mining pools.
    4. **`ANONYMIZED / TOR`**: Known Tor exit nodes or unverified proxy tunnels.
    5. **`UNVERIFIED EXTERNAL`**: General internet endpoint not associated with verified major tech infrastructure.
  * Correlates with local process authenticity: checks if process executable is in system directories and has valid signatures.
* **Interactive Actions:**
  * One-click "Block IP" (adds to blocklist + optional Windows Firewall block rule).
  * One-click "Terminate Process".
  * Deep inspection of connection latency, state, and bytes transferred.

#### API Endpoints
* `GET /api/network/analytics` — High-level network metrics (processes count, sockets, external vs internal).
* `GET /api/network/tracer` — Full list of network-active processes with traced IP source and genuineness assessment.
* `POST /api/network/trace-ip` — Deep tracer lookup for an arbitrary IP address.
* `POST /api/network/block-ip` — Block an IP via policy engine and firewall.

---

### 4. Frontend SOC Dashboard Additions (`frontend/`)

#### New Tabs & UI Components
1. **🌐 Network Radar & IP Origin Tracer Tab:**
   * Stat cards: Processes Using Network, Active Outbound Sockets, Listening Server Ports, Unverified External Hosts.
   * Search and filter: Filter by "All", "External Public IPs Only", "Suspicious Endpoints", "Genuine CDNs".
   * Network Table Columns:
     * Process Name & PID
     * Local Port -> Remote Socket (`IP:Port`)
     * Hostname / Reverse DNS
     * Location & ISP (with Country Flag)
     * Genuineness Verdict Badge (`GENUINE`, `PRIVATE`, `SUSPICIOUS`, `UNVERIFIED`)
     * Actions: `Block IP`, `Kill Process`, `Deep Trace`
2. **🛡️ Access Control & Rules Tab:**
   * Sub-tabs: "Allowed Processes (Whitelist)", "Blocked Processes (Blacklist)", "Blocked IPs (Firewall)".
   * "Add New Rule" button with modal (Name, Path, SHA256 Hash, or IP address).
   * Delete or toggle rules on/off.
3. **📧 Email Alerts & Reports Tab / Modal:**
   * Form to enter SMTP Server, Port, User, App Password, Recipient.
   * "Send Security Report Now" button.
   * "Send Test Email" button.
   * Live status indicator showing last dispatched report time and outcome.
4. **Enhanced Process Explorer & Threat Cards:**
   * Threat cards and process rows now feature:
     * `[✔ Allow]` button (quick-add to trusted whitelist).
     * `[🚫 Block]` button (quick-add to blacklist).
     * Network IP Origin Badge (e.g. `US - Microsoft Corp (Genuine)`).

---

## 🛠️ Step-by-Step Implementation Sequence

1. **Step 1:** Create `backend/policy_engine.py` to handle persistent allowlist/blocklist rules and IP firewall blocking.
2. **Step 2:** Create `backend/network_tracer.py` to audit network processes, perform reverse DNS, geolocation lookup, and evaluate genuineness.
3. **Step 3:** Create `backend/email_notifier.py` with SMTP transmission and clean HTML report generation.
4. **Step 4:** Integrate policies and network tracer into `backend/detector.py`, `backend/remediator.py`, and `backend/server.py`.
5. **Step 5:** Update `frontend/index.html`, `frontend/css/dashboard.css`, and `frontend/js/app.js` with the new Network Tracer tab, Allow/Block Rules tab, and Email dispatch interface.
6. **Step 6:** Run end-to-end tests to verify:
   - Allowlist suppresses threat detection on selected processes.
   - Blocklist terminates banned processes immediately.
   - Network tracer resolves IPs and assigns correct genuineness badges.
   - Email dispatch correctly delivers reports via SMTP.
7. **Step 7:** Update documentation in `README.md`.
