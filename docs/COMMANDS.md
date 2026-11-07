# AegisShield EDR & Network AdBlocker: Command & API Reference

## 1. Batch File Launchers

All batch files are located in the project root directory and can be executed via Command Prompt, PowerShell, or Windows File Explorer:

| Batch File | Description | Execution Command |
| :--- | :--- | :--- |
| **`start_all.bat`** | Launches both the EDR Cyber Dashboard (`:8888`) and the AdBlock Intercepting Proxy (`:8080`) in synchronized background windows. | `.\start_all.bat` |
| **`start_dashboard.bat`** | Starts only the AegisShield EDR Dashboard and REST/WebSocket API server on `127.0.0.1:8888`. | `.\start_dashboard.bat` |
| **`start_adblocker.bat`** | Starts only the high-speed AdBlock Intercepting Proxy on `127.0.0.1:8080`. | `.\start_adblocker.bat` |
| **`run_tests.bat`** | Executes the automated diagnostic testing engine verifying all 22 subsystem health checks. | `.\run_tests.bat` |
| **`generate_screenshots.bat`** | Executes the high-definition Pillow screenshot engine, producing 10 UI captures in `screenshots/`. | `.\generate_screenshots.bat` |

---

## 2. AegisShield CLI Scanner Reference (`cli_scanner.py`)

The unified CLI tool `cli_scanner.py` provides direct terminal access to all EDR detection, eradication, network origin tracing, policy management, and reporting features.

### 2.1 Threat Detection & Remediation
```bash
# Perform an immediate scan of all running processes
python cli_scanner.py --scan

# Scan processes and automatically terminate all CRITICAL threats (Score >= 70)
python cli_scanner.py --scan --kill

# Perform deep PE header and entropy analysis on suspicious binaries during scan
python cli_scanner.py --scan --deep-pe

# Terminate a specific process by PID immediately
python cli_scanner.py --kill-pid 8412
```

### 2.2 Network Origin Tracer & Remote IP Genuineness
```bash
# Audit all processes currently using network sockets and classify remote endpoint genuineness
python cli_scanner.py --network

# Inspect and trace a specific foreign IP address (reverse DNS, ASN, ISP, verdict)
python cli_scanner.py --trace-ip 8.8.8.8
python cli_scanner.py --trace-ip 198.51.100.1
```

### 2.3 Remote Desktop (LOLRMM) & Persistence Hunting
```bash
# Audit active Remote Desktop (AnyDesk, TeamViewer, VNC, ScreenConnect) and dual-use RMM tools
python cli_scanner.py --rmm

# Audit Windows Registry Run keys, autorun items, startup folders, and scheduled tasks
python cli_scanner.py --persistence
```

### 2.4 Access Control Policy Management (Allowlist / Blocklist)
```bash
# Display all currently active Allowlist and Blocklist rules
python cli_scanner.py --rules

# Add a process binary name to the Allowlist (whitelisting it from heuristic penalties)
python cli_scanner.py --allow --name "code.exe" --desc "Visual Studio Code editor"

# Add an executable path to the Allowlist
python cli_scanner.py --allow --path "C:\Tools\dev_agent.exe" --desc "Internal developer agent"

# Add a malicious binary name to the Blocklist (terminates on sight)
python cli_scanner.py --block --name "evil_miner.exe" --desc "Known cryptominer binary"

# Block a remote IP address (instantly adds Windows Firewall block rule via netsh)
python cli_scanner.py --block --ip "198.51.100.1" --desc "Active C2 beacon destination"

# Remove an access control rule by its Rule ID
python cli_scanner.py --delete-rule rule_20261107_061501
```

### 2.5 Security Reporting & Threat Simulation
```bash
# Dispatch an executive HTML security incident report via configured SMTP server
python cli_scanner.py --email-report

# Launch a harmless simulated threat scenario to test detection and alerting
python cli_scanner.py --simulate temp_trojan
python cli_scanner.py --simulate encoded_cmdline
python cli_scanner.py --simulate rmm_beacon
```

---

## 3. REST API Reference

The AegisShield backend exposes a comprehensive RESTful API on `http://127.0.0.1:8888`:

### 3.1 Threat & Process Endpoints
| Endpoint | Method | Description | Sample Query / Body |
| :--- | :---: | :--- | :--- |
| `/api/scan` | `GET` | Returns list of all evaluated processes with threat scores and indicators. | `GET /api/scan` |
| `/api/kill/{pid}` | `POST` | Immediately terminates process tree and quarantines binary. | `POST /api/kill/8412` |
| `/api/rmm-tools` | `GET` | Returns list of active remote desktop and dual-use RMM tools. | `GET /api/rmm-tools` |
| `/api/persistence` | `GET` | Returns startup, registry, and scheduled task persistence items. | `GET /api/persistence` |
| `/api/simulate-threat` | `POST` | Spawns a harmless threat simulation scenario. | `{"scenario": "temp_trojan"}` |
| `/api/audit-log` | `GET` | Returns historical record of all remediation and policy actions. | `GET /api/audit-log` |

### 3.2 Network Tracer Endpoints
| Endpoint | Method | Description | Sample Query / Body |
| :--- | :---: | :--- | :--- |
| `/api/network-processes` | `GET` | Returns all processes using network sockets with mapped remote IPs. | `GET /api/network-processes` |
| `/api/trace-ip` | `GET` | Resolves reverse DNS, ASN, ISP and genuineness score for an IP. | `GET /api/trace-ip?ip=8.8.8.8` |

### 3.3 AdBlocker & Web Analytics Endpoints
| Endpoint | Method | Description | Sample Query / Body |
| :--- | :---: | :--- | :--- |
| `/api/adblock/status` | `GET` | Returns proxy state (`active`, port, filtered domains count, system proxy state). | `GET /api/adblock/status` |
| `/api/adblock/toggle-proxy`| `POST` | Enables or disables Windows system-wide proxy settings in Registry. | `{"enabled": true}` |
| `/api/adblock/traffic-logs`| `GET` | Returns chronological log of browsed websites, categories, and block states. | `GET /api/adblock/traffic-logs?limit=100` |
| `/api/adblock/analytics` | `GET` | Returns aggregated metrics: total requests, blocked ads, bandwidth saved, top sites. | `GET /api/adblock/analytics` |
| `/api/adblock/clear-logs` | `POST` | Flushes web browsing traffic logs. | `POST /api/adblock/clear-logs` |

### 3.4 Access Control Policy Endpoints
| Endpoint | Method | Description | Sample Query / Body |
| :--- | :---: | :--- | :--- |
| `/api/policy-rules` | `GET` | Returns all allowlist and blocklist rules. | `GET /api/policy-rules` |
| `/api/policy-rules` | `POST` | Creates a new allow or block rule. | `{"action": "allow", "type": "name", "value": "code.exe", "description": "VS Code"}` |
| `/api/policy-rules/{id}` | `DELETE`| Deletes a rule by ID and removes any associated firewall rules. | `DELETE /api/policy-rules/rule_123` |

### 3.5 Email Alerts Endpoints
| Endpoint | Method | Description | Sample Query / Body |
| :--- | :---: | :--- | :--- |
| `/api/email/config` | `GET` | Returns current SMTP configuration (passwords masked). | `GET /api/email/config` |
| `/api/email/config` | `POST` | Updates SMTP host, port, TLS, and sender/recipient settings. | `{"smtp_server": "smtp.gmail.com", ...}` |
| `/api/email/send-report` | `POST` | Triggers immediate compilation and dispatch of executive HTML report. | `POST /api/email/send-report` |

---

## 4. WebSocket Telemetry Protocol

- **Endpoint:** `ws://127.0.0.1:8888/ws/telemetry`
- **Streaming Frequency:** Pushes live metrics every 2.0 seconds.
- **Payload Schema:**
```json
{
  "type": "TELEMETRY_UPDATE",
  "timestamp": 1794033150.21,
  "metrics": {
    "system_health_index": 98.5,
    "active_threats_count": 0,
    "total_processes": 142,
    "network_processes_count": 18,
    "adblock_requests_total": 450,
    "adblock_blocked_total": 118,
    "bandwidth_saved_mb": 28.4
  },
  "critical_alerts": []
}
```

---

## 5. Helpful Windows Administration Commands

### 5.1 Inspect Windows Internet Settings Proxy
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable, ProxyServer
```

### 5.2 Inspect Active Windows Firewall Rules Added by AegisShield
```powershell
netsh advfirewall firewall show rule name=all | Select-String "AegisShield" -Context 0,4
```

### 5.3 Verify Listening Ports for EDR and AdBlocker
```powershell
netstat -ano | findstr "8888 8080"
```

