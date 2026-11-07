# 🛡️ Architecture & Implementation Plan: Network Ad Blocker, Web Tracker & Analytics Engine

This plan details the design, proxy architecture, domain filtering algorithms, web browsing analytics, automated screenshot engine, testing framework, and documentation suite for **AegisShield Network Ad Blocker & Web Inspector**.

---

## 🏗️ Architectural Overview & File Map

```
SpywareProcessMon/
├── backend/
│   ├── adblock_proxy.py       # [NEW] Multi-threaded HTTP & HTTPS CONNECT intercepting proxy on port 8080
│   ├── adblock_rules.py       # [NEW] Curated blocklist of 5,000+ ad, tracker, telemetry & malware domains
│   ├── web_traffic_logger.py  # [NEW] Persistent logging of all visited websites, timestamps, and categories
│   ├── web_analytics.py       # [NEW] Aggregates browsing trends, top sites, blocked ads, and analytics
│   ├── proxy_controller.py    # [NEW] 1-click Windows System Proxy enabler/disabler via registry / PowerShell
│   ├── policy_engine.py       # Access control whitelist & blacklist rules
│   ├── network_tracer.py      # Network process auditor, reverse DNS, GeoIP & Genuineness scorer
│   ├── email_notifier.py      # SMTP dispatcher & HTML threat report generator
│   ├── detector.py            # Process threat detection engine
│   ├── remediator.py          # Kill engine & quarantine
│   └── server.py              # [MODIFY] Expose REST APIs for AdBlocker, Web Traffic logs, Analytics & Proxy controls
├── database/
│   ├── web_traffic_logs.json  # [NEW] Persistent log of every website browsed, timestamp, and block status
│   ├── adblock_config.json    # [NEW] Ad blocker proxy settings and custom whitelist/blacklist
│   ├── policy_rules.json      # Whitelist & blacklist rules
│   ├── email_config.json      # SMTP settings
│   └── geo_cache.json         # IP geolocation cache
├── frontend/
│   ├── index.html             # [MODIFY] Add AdBlocker & Web Browsing Analytics Dashboard tab
│   ├── css/dashboard.css      # [MODIFY] Add analytics charts & AdBlock styling
│   └── js/app.js              # [MODIFY] Add AdBlocker UI controls, live traffic feed, and analytics charts
├── tools/
│   ├── screenshot_engine.py   # [NEW] Headless browser screenshot capture engine for all app views
│   └── test_engine.py         # [NEW] End-to-end automated verification test suite
├── docs/
│   ├── DESIGN_AND_ARCHITECTURE.md       # [NEW] In-depth technical design & architecture
│   ├── PROJECT_STRUCTURE.md             # [NEW] Complete file-by-file project map
│   ├── CODE_EXPLANATION.md              # [NEW] In-depth code walkthrough
│   ├── COMMANDS.md                      # [NEW] Master reference of CLI & API commands
│   └── SESSION_PROMPTS_AND_RESPONSES.md # [NEW] Chronological record of prompts and actions
├── brain_archive/             # [COPIED] All brain artifacts, logs, steps, and transcripts
├── cli_scanner.py             # CLI threat scanner & network auditor
├── run_server.py              # Server launcher
├── start_dashboard.bat        # Windows 1-click launcher
├── requirements.txt           # Python dependencies
└── README.md                  # Master documentation
```

---

## 📋 Technical Specifications

### 1. Intercepting Web Ad Blocker Proxy (`backend/adblock_proxy.py`)
* **Multi-Threaded TCP Proxy (Port 8080):**
  * Listens on `127.0.0.1:8080`.
  * Handles standard HTTP requests (`GET`, `POST`, `HEAD`, etc.) and HTTPS tunneling requests (`CONNECT target:443`).
* **Domain Extraction & SNI Inspection:**
  * Extracts exact target hostname from `CONNECT host:443` or `Host:` header.
  * Normalizes domains and checks against curated Ad & Tracker database.
* **Instant Blocking:**
  * If domain matches ad/tracker: returns `HTTP/1.1 403 Forbidden` with a lightweight block notification, immediately preventing advertising scripts and tracking pixels from executing.
* **Transparent Forwarding:**
  * If domain is clean: establishes a bi-directional TCP streaming tunnel with the remote web server and relays encrypted payloads without breaking SSL/TLS integrity.

---

### 2. Curated Ad & Tracker Signature Rules (`backend/adblock_rules.py`)
* **Sources & Coverage:**
  * Curated from **StevenBlack/hosts**, **EasyList**, and **AdGuard DNS Filters**.
  * Covers 5,000+ top advertising exchanges, behavioral tracking beacons, telemetry domains, pop-up networks, and cryptominers:
    * Google Ad Services, DoubleClick, AdSense, AdMob
    * Facebook / Meta Pixel & Graph tracking
    * Criteo, Taboola, Outbrain, Pubmatic, Rubicon Project
    * Amazon Advertising, AppNexus, Media.net
    * Telemetry & diagnostics endpoints
* **Sub-Domain Wildcard Matching:**
  * Matches base domains and subdomains (e.g. `*.doubleclick.net` blocks `ad.doubleclick.net`, `securepubads.g.doubleclick.net`).

---

### 3. Web Traffic Tracking & Analytics Engine (`backend/web_traffic_logger.py` & `backend/web_analytics.py`)
* **Real-Time Logging:**
  * Every web browsing connection is recorded with:
    * `timestamp` (ISO format and formatted date/time, e.g. `2026-11-07 07:25:10`)
    * `domain` (e.g. `github.com`, `adservice.google.com`, `youtube.com`)
    * `method` (`CONNECT`, `GET`, `POST`)
    * `category` (`Ad / Tracker`, `Telemetry`, `Malware / Scam`, `Social Media`, `Clean / Allowed`)
    * `status` (`BLOCKED` vs `ALLOWED`)
    * `bytes_transferred`
    * `client_ip`
* **Analytics Aggregations:**
  * Total queries processed
  * Total ads and trackers blocked
  * Block percentage (%)
  * Top 10 most visited websites
  * Top 10 blocked ad domains
  * Categorical distribution (Ads, Social, News, Tech, Clean)
  * Activity timeline (queries per hour / minute)

---

### 4. 1-Click Windows System Proxy Integration (`backend/proxy_controller.py`)
* **Native Windows Integration:**
  * Automates configuring Windows Internet Settings (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`):
    * Sets `ProxyEnable = 1`
    * Sets `ProxyServer = 127.0.0.1:8080`
    * Broadcasts setting change via `wininet.dll` (`InternetSetOption`) or PowerShell so all browsers (Edge, Chrome, Brave, Firefox) immediately route through AegisShield without requiring browser restarts.
* **Safe Disable:**
  * 1-click disable reverts `ProxyEnable = 0`, restoring standard direct connection instantly.

---

### 5. Automated Screenshot Engine (`tools/screenshot_engine.py`)
* **Visual Verification Suite:**
  * Connects to the local server, navigates through all views:
    1. Threat Remediation Dashboard
    2. Network Radar & Origin Tracer
    3. Ad Blocker & Web Traffic Analytics
    4. Live Process Explorer
    5. Access Control Policy Manager
    6. Threat Simulation Lab
  * Captures full-resolution PNG screenshots into `screenshots/` directory for documentation and verification.

---

### 6. Automated Testing Engine (`tools/test_engine.py`)
* **Comprehensive Diagnostic Harness:**
  * Runs automated unit, integration, and E2E checks:
    * Test 1: Proxy initialization and socket binding (Port 8080)
    * Test 2: Ad domain blocking (`CONNECT ad.doubleclick.net:443` -> HTTP 403 Forbidden)
    * Test 3: Clean domain passthrough (`CONNECT example.com:443` -> Tunnel established)
    * Test 4: Web traffic logging and analytics calculation
    * Test 5: Policy allow/block rule enforcement
    * Test 6: Threat detection heuristics and process termination
    * Test 7: Email notification report generation
    * Test 8: REST API endpoints response validation

---

### 7. Documentation Suite (`docs/`)
* **`docs/DESIGN_AND_ARCHITECTURE.md`**: Complete architectural diagrams, data flows, and design principles.
* **`docs/PROJECT_STRUCTURE.md`**: File-by-file directory tree and module roles.
* **`docs/CODE_EXPLANATION.md`**: In-depth explanation of classes, methods, and algorithms.
* **`docs/COMMANDS.md`**: Master command reference for CLI, REST APIs, and batch launchers.
* **`docs/SESSION_PROMPTS_AND_RESPONSES.md`**: Complete chronological record of user requests, decisions, and outcomes.
