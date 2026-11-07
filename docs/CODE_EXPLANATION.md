# AegisShield EDR & Network AdBlocker: Comprehensive Code Explanation

## 1. Threat Detection Engine (`backend/detector.py`)

### 1.1 Class Architecture: `ThreatDetector`
The `ThreatDetector` class is the central analysis orchestrator for all running processes. It accepts an optional `PolicyEngine` instance to evaluate allowlist and blocklist rules before executing computational heuristics.

### 1.2 Masquerading Detection Heuristic
Attackers frequently name malware after critical Windows binaries to blend into Task Manager (e.g., placing `svchost.exe` in `%APPDATA%`).
```python
CRITICAL_WINDOWS_BINARIES = {
    "svchost.exe": ["system32", "syswow64"],
    "csrss.exe": ["system32"],
    "lsass.exe": ["system32"],
    "services.exe": ["system32"],
    "smss.exe": ["system32"],
    "explorer.exe": ["windows"],
    "wininit.exe": ["system32"],
    "winlogon.exe": ["system32"]
}
```
The method `is_masquerading_system_binary(proc_name, exe_path)` performs the following validation:
1. Normalizes the executable name to lowercase.
2. If `proc_name` exists in `CRITICAL_WINDOWS_BINARIES`, it inspects the directory path of `exe_path`.
3. If none of the approved system directory substrings (e.g. `C:\Windows\System32`) appear in `exe_path`, the process is flagged as **CRITICAL MASQUERADING** (+35 score penalty).

### 1.3 Command-Line Heuristic Scoring
The method `evaluate_cmdline(cmdline_str)` searches for indicators of living-off-the-land binaries (LOLBins) and script execution attacks:
- **Base64 / Encoded Commands:** `-enc`, `-encodedcommand`, `frombase64string`.
- **Evasion & Hidden Windows:** `-w hidden`, `-windowstyle hidden`, `-ep bypass`, `-executionpolicy bypass`.
- **Download Cradles & In-Memory Execution:** `iex`, `invoke-expression`, `downloadstring`, `webclient`, `bitsadmin`, `certutil -urlcache`.
- **Credential Access & Memory Dumping:** `procdump`, `comsvcs.dll`, `mimikatz`, `sekurlsa`.
- Scoring: Each matched pattern adds +15 to +35 to the threat score.

### 1.4 Comprehensive Heuristic Scoring Matrix
Each process receives a cumulative score from 0 to 100:
$$\text{Score} = \min(100, S_{\text{sig}} + S_{\text{masq}} + S_{\text{cmd}} + S_{\text{path}} + S_{\text{pe}})$$

- **Score $\ge 70$:** Classified as `CRITICAL` (Highlighted in neon red, triggers automatic kill if enabled, queues email alert).
- **Score $40 - 69$:** Classified as `SUSPICIOUS` (Highlighted in amber).
- **Score $15 - 39$:** Classified as `LOW` (Informational notice).
- **Score $< 15$:** Classified as `SAFE` (Highlighted in emerald green).

---

## 2. Portable Executable (PE) Forensics (`backend/pe_analyzer.py`)

### 2.1 Shannon Entropy Calculation
Malware authors commonly employ packers (UPX, Themida, VMProtect) or encrypt their payloads to evade static signature detection. Packed and encrypted data exhibits high informational randomness (entropy).
The Shannon entropy $H(X)$ of a byte array is computed as:
$$H(X) = -\sum_{i=0}^{255} P(b_i) \log_2 P(b_i)$$
Where $P(b_i)$ is the probability of occurrence of byte value $b_i$ in the file.
- **$H(X) > 7.2$:** Strong indicator of packed executable code or embedded encrypted payload (+20 score).
- **$H(X) \approx 5.0 - 6.8$:** Normal compiled code sections.

### 2.2 PE Header & Authenticode Inspection
- Reads the DOS header (`IMAGE_DOS_HEADER`), checks the `e_magic` (`0x5A4D` / `MZ`), parses `IMAGE_NT_HEADERS`, and examines section names (`.text`, `.data`, `.rsrc`, `.reloc`).
- Unusual section names (e.g., `.upx0`, `.pack`, non-printable characters) flag packing anomalies.
- Checks `IMAGE_DIRECTORY_ENTRY_SECURITY` to determine whether the PE binary carries a valid Authenticode digital certificate.

---

## 3. Remote Desktop & Dual-Use Tools Hunter (`backend/signatures_db.py`)

### 3.1 LOLRMM Threat Vector
Attackers increasingly deploy legitimate Remote Monitoring and Management (RMM) utilities instead of traditional malware to maintain persistent control across victim networks without tripping simple antivirus signatures.

### 3.2 Detection Matrix
The detector cross-references:
1. **Process Binary Names:** `AnyDesk.exe`, `TeamViewer.exe`, `TeamViewer_Service.exe`, `ScreenConnect.ClientService.exe`, `AteraAgent.exe`, `Splashtop.exe`, `winvnc.exe`, `vncserver.exe`, `RustDesk.exe`.
2. **Network Listening Ports:**
   - Port `5938`: TeamViewer default control port.
   - Port `7070`: AnyDesk peer listening port.
   - Port `5900`: Standard VNC Server port.
   - Port `8040` / `8041`: ScreenConnect (ConnectWise Control) agent relay.
3. **State Flagging:** If an RMM tool is running and actively listening on a network port, it is categorized as `ACTIVE RMM` or `ACTIVE VNC SERVER`.

---

## 4. System-Wide Network Ad Blocker (`backend/adblock_proxy.py` & `backend/adblock_rules.py`)

### 4.1 Proxy Architecture
Windows native DNS Client cache (`Dnscache`) binds UDP port 53 by default with `WinError 10013`. To provide system-wide interception without driver installations or kernel hooks, AegisShield employs an **Intercepting Local Proxy** running on `127.0.0.1:8080`.

### 4.2 Handling HTTP and HTTPS (`CONNECT`)
1. **HTTPS Interception via `CONNECT`:**
   - The browser sends: `CONNECT doubleclick.net:443 HTTP/1.1\r\nHost: doubleclick.net:443\r\n\r\n`.
   - The proxy extracts the target host (`doubleclick.net`).
   - The domain is passed to `check_domain_reputation(domain)`.
   - **If Blocked:** The proxy immediately responds with `HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n[AegisShield] Ad / Tracker Blocked` and terminates the TCP connection. No TLS handshake occurs, saving 100% of the payload bandwidth.
   - **If Allowed:** The proxy establishes a direct TCP connection to the upstream server on port 443, responds with `HTTP/1.1 200 Connection Established\r\n\r\n`, and establishes a bi-directional raw streaming tunnel between the browser and upstream host.
2. **Plain HTTP Handling:**
   - For `GET` / `POST` requests to ad domains, the proxy returns a small HTML placeholder block page.

### 4.3 Subdomain Tree Matching Algorithm
Domains are checked using exact matching and hierarchical subdomain suffix matching:
```python
def check_domain_reputation(domain: str) -> tuple[bool, str, str]:
    domain = domain.lower().strip()
    # 1. Exact match in blacklisted domains set
    if domain in AD_DOMAINS:
        return True, "AD / TRACKER", f"Known commercial advertising network: {domain}"
    
    # 2. Suffix match against parent domains
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent_domain = ".".join(parts[i:])
        if parent_domain in AD_DOMAINS:
            return True, "AD / TRACKER", f"Subdomain of blocked ad provider: {parent_domain}"
            
    return False, "CLEAN / ALLOWED", "Domain passed reputation check"
```

---

## 5. Web Traffic Logger & Analytics (`backend/web_traffic_logger.py`, `backend/web_analytics.py`)

### 5.1 Thread-Safe Persistence
The proxy handles dozens of concurrent browser connections simultaneously. `WebTrafficLogger` wraps all file writes in a `threading.Lock()`:
- Maintains an in-memory deque capped at 10,000 entries for zero-latency lookups.
- Periodically flushes entries to `database/web_traffic_logs.json`.
- Formats date and time in human-readable ISO-8601 strings (`YYYY-MM-DD HH:MM:SS`).

### 5.2 Real-Time Analytics Calculations
`WebAnalytics.get_analytics()` calculates:
- **Total Requests & Block Rate:** Percentage of total web requests blocked as telemetry or advertising.
- **Bandwidth Saved:** Estimated byte savings calculated from average ad payload sizes (typically 120 KB to 450 KB per blocked ad request).
- **Top 10 Visited Clean Websites:** Aggregated by unique visit count.
- **Top 10 Blocked Ad Networks:** Identifies the top trackers attempting to collect machine telemetry.
- **Category Distribution:** Breakdowns across `AD / TRACKER`, `TELEMETRY`, `MALWARE`, and `CLEAN / ALLOWED`.

---

## 6. Network Process Origin & Genuineness Tracer (`backend/network_tracer.py`)

### 6.1 Socket Inspection
Queries `psutil.net_connections(kind="inet")` to enumerate active TCP/UDP sockets and maps each socket to its owning process PID.

### 6.2 Reverse DNS & Origin Resolution
For each foreign remote IP:
1. Skips loopback (`127.0.0.1`, `::1`) and RFC 1918 private subnets (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`).
2. Checks local persistent cache in `database/geo_cache.json`.
3. Performs non-blocking PTR lookup (`socket.gethostbyaddr(ip)`).
4. Evaluates Autonomous System Numbers (ASN) and organization owners (Google, Cloudflare, Amazon AWS, Microsoft).

### 6.3 Genuineness Classification Rules
- **`GENUINE CLOUD / CDN`:** Hostnames matching `*.1e100.net`, `*.google.com`, `*.cloudflare.com`, `*.amazonaws.com`, `*.azure.com`, `*.akamaitechnologies.com`, `*.fastly.net`.
- **`PRIVATE LAN`:** Addresses in RFC 1918 ranges or mDNS / link-local addresses.
- **`SUSPICIOUS C2 / RAT PORT`:** Any connection to foreign IP on ports `4444` (Metasploit default), `1337`, `6667` (IRC botnets), `5552` (AsyncRAT default), or `8888`.
- **`UNVERIFIED EXTERNAL`:** Non-CDN foreign IP addresses without verified reverse PTR records.

---

## 7. Access Control Policy Engine (`backend/policy_engine.py`)

### 7.1 Rule Matching Strategy
The policy engine supports four distinct match criteria:
1. `name`: Matches the process executable filename (e.g. `slack.exe`, `malware.exe`).
2. `path`: Matches the exact absolute executable path (e.g. `C:\tools\agent.exe`).
3. `hash`: Matches the calculated SHA-256 hash of the binary file.
4. `ip`: Matches remote destination IP addresses.

### 7.2 Windows Firewall Integration
When an IP address is added to the blocklist:
```python
def sync_firewall_rule(ip_address: str, action: str = "block"):
    rule_name = f"AegisShield_Block_{ip_address}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip_address}"
    ]
    subprocess.run(cmd, capture_output=True, text=True)
```
This ensures instant operating-system level packet dropping before any application socket can transmit data.

---

## 8. Process Eradication & Remediation (`backend/remediator.py`)

### 8.1 Termination Strategy
1. **Phase 1: Graceful Termination:**
   - Sends `proc.terminate()` (`WM_CLOSE` on Windows).
   - Waits up to 1.5 seconds for cleanup.
2. **Phase 2: Forced Kernel Eradication:**
   - If the process resists, calls `proc.kill()` which triggers `TerminateProcess` at the Windows kernel level.
   - For malicious trees, executes recursive child process tree eradication:
     ```python
     for child in proc.children(recursive=True):
         child.kill()
     ```
3. **Phase 3: File Quarantine:**
   - Moves the hostile executable to `.quarantine/` with an appended `.quarantine` extension.
   - Removes write and execution permissions from the file.
4. **Phase 4: Audit Trail:**
   - Logs timestamp, target PID, binary path, SHA-256, and outcome to `database/incident_audit.json`.

---

## 9. SMTP Email Alerts & Reports (`backend/email_notifier.py`)

### 9.1 Report Generation
`EmailNotifier.generate_html_report(data)` compiles a responsive, dark-themed HTML email containing:
- Executive Summary Badge (System Health Index, Active Threat Count).
- Detailed Threat Remediation Table (Process Name, PID, File Path, Threat Score, Heuristic Triggers).
- Remote Desktop & RMM Tool Inventory.
- High-Risk Network Sockets and Remote Endpoints.
- Remediation Audit History.

### 9.2 Dispatch Pipeline
- Connects securely via `smtplib.SMTP(host, port)`.
- Upgrades to TLS encryption with `server.starttls()`.
- Authenticates using credentials from `database/email_config.json`.
- Sends MIME multipart message (`text/plain` fallback and `text/html`).

---

## 10. Threat Simulation Lab (`backend/simulator.py`)

Allows operators and evaluators to safely test AegisShield's detection, alerting, and eradication capabilities without downloading malicious files:
1. **`temp_trojan`:** Drops and launches a harmless Python sleep process inside `%TEMP%` named `svch0st_sim.exe`.
2. **`encoded_cmdline`:** Spawns a background process with `-enc` and `-w hidden` parameters.
3. **`rmm_beacon`:** Spawns a benign local loopback listener on port `5900` mimicking a VNC server.

