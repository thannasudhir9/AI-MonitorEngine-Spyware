"""
AegisShield - Threat Intelligence & Signature Catalog
Comprehensive database of RMM tools, Remote Access Trojans (RATs),
Spyware, Infostealers, LOLBins heuristics, and known threat indicators.
Sources: LOLRMM (Living Off The Land RMM), Sigma rules, MITRE ATT&CK.
"""

from typing import Dict, List, Any

# Remote Monitoring & Management (RMM) and Remote Desktop Tools
# Tracked by LOLRMM project for potential dual-use / unauthorized persistence
RMM_DATABASE: Dict[str, Dict[str, Any]] = {
    "anydesk.exe": {
        "name": "AnyDesk",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "Legitimate Remote Desktop software frequently abused for unauthorized remote access and screen takeover.",
        "default_ports": [7070, 6568, 50001, 50002, 50003]
    },
    "teamviewer.exe": {
        "name": "TeamViewer",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "Commercial remote control tool often installed by attackers or scammers for unattended remote desktop access.",
        "default_ports": [5938]
    },
    "teamviewer_service.exe": {
        "name": "TeamViewer Service",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "TeamViewer background service enabling unattended remote control.",
        "default_ports": [5938]
    },
    "rustdesk.exe": {
        "name": "RustDesk",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 65,
        "description": "Open-source remote desktop software capable of self-hosted relaying, abused by threat actors for persistent remote control.",
        "default_ports": [21115, 21116, 21117, 21118, 21119]
    },
    "screenconnect.clientservice.exe": {
        "name": "ConnectWise ScreenConnect",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 75,
        "description": "ConnectWise ScreenConnect remote management client, heavily targeted in ransomware intrusions.",
        "default_ports": [8040, 8041]
    },
    "screenconnect.windowsclient.exe": {
        "name": "ConnectWise ScreenConnect Client",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 75,
        "description": "Active ScreenConnect GUI session for remote desktop control.",
        "default_ports": [8040, 8041]
    },
    "winvnc.exe": {
        "name": "UltraVNC Server",
        "category": "Remote Desktop / VNC",
        "severity": "HIGH",
        "score": 75,
        "description": "VNC Server listening for incoming remote graphical desktop connections.",
        "default_ports": [5900, 5800]
    },
    "tvnserver.exe": {
        "name": "TightVNC Server",
        "category": "Remote Desktop / VNC",
        "severity": "HIGH",
        "score": 75,
        "description": "TightVNC server running in the background for remote access.",
        "default_ports": [5900]
    },
    "vncserver.exe": {
        "name": "RealVNC Server",
        "category": "Remote Desktop / VNC",
        "severity": "HIGH",
        "score": 75,
        "description": "RealVNC remote desktop daemon.",
        "default_ports": [5900]
    },
    "splashtop.exe": {
        "name": "Splashtop",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "Splashtop remote access application.",
        "default_ports": [6783, 6784, 6785]
    },
    "srservice.exe": {
        "name": "Splashtop Remote Service",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "Splashtop streamer background service.",
        "default_ports": [6783]
    },
    "logmein.exe": {
        "name": "LogMeIn",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "LogMeIn remote control client.",
        "default_ports": [443]
    },
    "rutserv.exe": {
        "name": "Remote Utilities Host",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 75,
        "description": "Remote Utilities host server enabling full unattended remote control, frequently dropped by phishing attacks.",
        "default_ports": [5650, 5651]
    },
    "rfusclient.exe": {
        "name": "Remote Utilities Viewer",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "Remote Utilities client process.",
        "default_ports": [5650]
    },
    "meshagent.exe": {
        "name": "MeshCentral Agent",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 75,
        "description": "MeshCentral open-source remote management agent capable of terminal, files, and desktop takeover.",
        "default_ports": [443, 80]
    },
    "ninjarmmagent.exe": {
        "name": "NinjaRMM Agent",
        "category": "Remote Desktop / RMM",
        "severity": "MEDIUM",
        "score": 60,
        "description": "NinjaOne Remote Monitoring & Management agent.",
        "default_ports": [443]
    },
    "ateraagent.exe": {
        "name": "Atera Agent",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 75,
        "description": "Atera RMM client frequently abused by threat actors with free trial accounts to gain remote persistence.",
        "default_ports": [443]
    },
    "syncro.service.exe": {
        "name": "SyncroMSP Agent",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 70,
        "description": "Syncro MSP remote control and scripting agent.",
        "default_ports": [443]
    },
    "client32.exe": {
        "name": "NetSupport Manager",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 80,
        "description": "NetSupport Manager remote control client, widely weaponized as RAT malware in malvertising campaigns.",
        "default_ports": [443, 80]
    },
    "radmin.exe": {
        "name": "Radmin Remote Administrator",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 75,
        "description": "Famatech Radmin remote administration tool.",
        "default_ports": [4899]
    },
    "aa_v3.exe": {
        "name": "Ammyy Admin",
        "category": "Remote Desktop / RMM",
        "severity": "HIGH",
        "score": 80,
        "description": "Ammyy Admin remote desktop tool, heavily utilized in tech support scams.",
        "default_ports": [5399]
    },
    "parsecd.exe": {
        "name": "Parsec Daemon",
        "category": "Remote Desktop / Screen Share",
        "severity": "LOW",
        "score": 40,
        "description": "Parsec low-latency remote desktop streaming daemon.",
        "default_ports": [8000, 9000]
    }
}

# Reverse Tunneling Tools (Living off the land tunnels for C2 and remote access)
TUNNEL_DATABASE: Dict[str, Dict[str, Any]] = {
    "ngrok.exe": {
        "name": "Ngrok",
        "category": "Reverse Tunnel / Proxy",
        "severity": "HIGH",
        "score": 80,
        "description": "Ngrok reverse proxy tunnel creating public internet ingress to local machine ports, bypassing firewalls.",
    },
    "cloudflared.exe": {
        "name": "Cloudflare Tunnel",
        "category": "Reverse Tunnel / Proxy",
        "severity": "HIGH",
        "score": 75,
        "description": "Cloudflare Argo tunnel agent abused to expose internal endpoints to the internet without port forwarding.",
    },
    "frpc.exe": {
        "name": "FRP Client (Fast Reverse Proxy)",
        "category": "Reverse Tunnel / Proxy",
        "severity": "HIGH",
        "score": 85,
        "description": "Fast Reverse Proxy client extensively leveraged in APT campaigns for C2 communication.",
    },
    "chisel.exe": {
        "name": "Chisel Tunnel",
        "category": "Reverse Tunnel / Proxy",
        "severity": "CRITICAL",
        "score": 90,
        "description": "TCP/UDP tunnel over HTTP secured via SSH, commonly used for pentesting and malicious pivoting.",
    },
    "ligolo.exe": {
        "name": "Ligolo-ng Tunnel",
        "category": "Reverse Tunnel / Proxy",
        "severity": "CRITICAL",
        "score": 90,
        "description": "Ligolo reverse tunneling proxy for internal network pivoting.",
    }
}

# Remote Access Trojans (RATs), Trojans, Infostealers, Keyloggers, and Spyware
TROJAN_RAT_DATABASE: Dict[str, Dict[str, Any]] = {
    "njrat.exe": {
        "name": "njRAT (Bladabindi)",
        "category": "Trojan / RAT",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Infamous Remote Access Trojan capable of keylogging, webcam spying, remote shell, and credential extraction."
    },
    "asyncrat.exe": {
        "name": "AsyncRAT",
        "category": "Trojan / RAT",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Open-source remote access trojan actively weaponized for espionage, keylogging, and remote code execution."
    },
    "quasar.client.exe": {
        "name": "QuasarRAT",
        "category": "Trojan / RAT",
        "severity": "CRITICAL",
        "score": 100,
        "description": "C# based remote administration trojan providing screen capture, keylogger, reverse proxy, and password recovery."
    },
    "quasarclient.exe": {
        "name": "QuasarRAT Client",
        "category": "Trojan / RAT",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Quasar Remote Access Trojan executable."
    },
    "remcos.exe": {
        "name": "Remcos RAT",
        "category": "Trojan / RAT / Spyware",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Commercial remote control tool categorized as high-threat spyware; logs keystrokes, audio, webcam, and steals credentials."
    },
    "darkcomet.exe": {
        "name": "DarkComet RAT",
        "category": "Trojan / RAT",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Remote Access Trojan with extensive surveillance, keystroke logging, and system control capabilities."
    },
    "nanocore.exe": {
        "name": "NanoCore RAT",
        "category": "Trojan / RAT",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Modular Remote Access Trojan with surveillance, surveillance audio/video capture, and reverse proxy plugins."
    },
    "agenttesla.exe": {
        "name": "AgentTesla",
        "category": "Spyware / Infostealer",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Advanced spyware and infostealer targeting browser passwords, VPN profiles, FTP credentials, and keyboard input."
    },
    "redline.exe": {
        "name": "RedLine Stealer",
        "category": "Spyware / Infostealer",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Infostealer malware harvesting browser logins, autofills, cookies, cryptocurrency wallets, and system telemetry."
    },
    "vidar.exe": {
        "name": "Vidar Stealer",
        "category": "Spyware / Infostealer",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Malware stealer targeting 2FA apps, browser sessions, Telegram, Discord tokens, and crypto keys."
    },
    "mimikatz.exe": {
        "name": "Mimikatz",
        "category": "Credential Dumper / HackTool",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Well-known credential extraction tool that dumps LSASS memory passwords, NTLM hashes, and Kerberos tickets."
    },
    "xmrig.exe": {
        "name": "XMRig Miner",
        "category": "CryptoMiner / Trojan",
        "severity": "CRITICAL",
        "score": 95,
        "description": "Monero cryptocurrency CPU miner, frequently dropped by unauthorized botnets and trojans to hijack system resources."
    },
    "beacon.exe": {
        "name": "Cobalt Strike Beacon",
        "category": "Trojan / C2 Agent",
        "severity": "CRITICAL",
        "score": 100,
        "description": "Cobalt Strike adversary simulation payload used in targeted ransomware intrusions for hands-on-keyboard control."
    },
    "sliver-client.exe": {
        "name": "Sliver C2 Agent",
        "category": "Trojan / C2 Agent",
        "severity": "CRITICAL",
        "score": 95,
        "description": "Cross-platform adversary emulation and command-and-control framework implant."
    }
}

# Suspicious Command Line Patterns (Regex or Substring triggers)
SUSPICIOUS_CMDLINE_PATTERNS = [
    {
        "pattern": "-enc",
        "name": "Encoded PowerShell Command",
        "severity": "HIGH",
        "score": 45,
        "category": "Obfuscation",
        "description": "PowerShell execution using Base64 encoded payload, commonly used to conceal malicious downloaders."
    },
    {
        "pattern": "-encodedcommand",
        "name": "Encoded PowerShell Command",
        "severity": "HIGH",
        "score": 45,
        "category": "Obfuscation",
        "description": "Explicit Base64 encoded command execution in PowerShell."
    },
    {
        "pattern": "-w hidden",
        "name": "Hidden Console Window",
        "severity": "MEDIUM",
        "score": 30,
        "category": "Evasion",
        "description": "Process launched with a hidden window style to evade user detection."
    },
    {
        "pattern": "-windowstyle hidden",
        "name": "Hidden Console Window",
        "severity": "MEDIUM",
        "score": 30,
        "category": "Evasion",
        "description": "PowerShell launched with explicit hidden window style."
    },
    {
        "pattern": "downloadstring",
        "name": "In-Memory Web Download & Execution",
        "severity": "HIGH",
        "score": 50,
        "category": "Downloader",
        "description": "WebClient.DownloadString fetching and executing payloads directly in memory (cradle)."
    },
    {
        "pattern": "invoke-expression",
        "name": "Dynamic Expression Invocation (IEX)",
        "severity": "HIGH",
        "score": 40,
        "category": "Execution",
        "description": "Dynamic script evaluation often combined with downloaded remote payloads."
    },
    {
        "pattern": "iex (new-object",
        "name": "PowerShell Download Cradle",
        "severity": "CRITICAL",
        "score": 70,
        "category": "Trojan Downloader",
        "description": "Classic malicious PowerShell download cradle (IEX Net.WebClient)."
    },
    {
        "pattern": "certutil -urlcache",
        "name": "CertUtil Remote Payload Ingress",
        "severity": "CRITICAL",
        "score": 75,
        "category": "LOLBin Abuse",
        "description": "Certutil abused as a Living Off The Land binary to download remote malware."
    },
    {
        "pattern": "vssadmin delete shadows",
        "name": "Ransomware Volume Shadow Deletion",
        "severity": "CRITICAL",
        "score": 100,
        "category": "Ransomware",
        "description": "Attempt to delete Volume Shadow copies to prevent recovery from ransomware encryption."
    },
    {
        "pattern": "wmic shadowcopy delete",
        "name": "Ransomware Volume Shadow Deletion (WMIC)",
        "severity": "CRITICAL",
        "score": 100,
        "category": "Ransomware",
        "description": "WMIC command deleting restore points and shadow copies."
    },
    {
        "pattern": "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "name": "Ransomware Boot Tampering",
        "severity": "CRITICAL",
        "score": 100,
        "category": "Ransomware",
        "description": "Modifying Windows bootloader to suppress crash screens and boot recovery."
    },
    {
        "pattern": "stratum+tcp://",
        "name": "Crypto Miner Pool Protocol",
        "severity": "CRITICAL",
        "score": 90,
        "category": "CryptoMiner",
        "description": "Active connection string to a cryptocurrency mining pool over Stratum protocol."
    },
    {
        "pattern": "amsiutils",
        "name": "AMSI Bypass Tampering",
        "severity": "CRITICAL",
        "score": 85,
        "category": "Evasion",
        "description": "Attempt to patch AmsiUtils memory structures to neutralize Windows Defender AMSI protection."
    }
]

# Suspicious Parent-Child Process Relationships (Sigma / ATT&CK)
SUSPICIOUS_PARENT_CHILD = [
    {
        "parent": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
        "children": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"],
        "name": "Office Malicious Macro Shell Spawn",
        "severity": "CRITICAL",
        "score": 85,
        "category": "Macro Weaponization"
    },
    {
        "parent": ["acrord32.exe", "acrobat.exe"],
        "children": ["cmd.exe", "powershell.exe", "wscript.exe"],
        "name": "PDF Reader Shell Spawn",
        "severity": "CRITICAL",
        "score": 85,
        "category": "Exploit"
    },
    {
        "parent": ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"],
        "children": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "name": "Browser Spawned Interactive Shell",
        "severity": "HIGH",
        "score": 75,
        "category": "Browser Exploit / Malicious Download"
    }
]

# Suspicious Windows API Imports (Common in Keyloggers, Trojans, and Injected DLLs)
SUSPICIOUS_PE_APIS = {
    # Injection & Memory Manipulation
    "VirtualAllocEx": {"score": 25, "role": "Memory Allocation in Remote Process"},
    "WriteProcessMemory": {"score": 25, "role": "Remote Process Memory Tampering"},
    "CreateRemoteThread": {"score": 30, "role": "Remote Thread Injection"},
    "QueueUserAPC": {"score": 20, "role": "Asynchronous Injection (Early Bird)"},
    "NtUnmapViewOfSection": {"score": 35, "role": "Process Hollowing / RunPE"},
    
    # Spyware & Keylogging
    "SetWindowsHookExA": {"score": 30, "role": "Global Keyboard / Mouse Hook (Keylogger)"},
    "SetWindowsHookExW": {"score": 30, "role": "Global Keyboard / Mouse Hook (Keylogger)"},
    "GetAsyncKeyState": {"score": 20, "role": "Polling Keystroke Monitor (Keylogger)"},
    "GetKeyboardState": {"score": 15, "role": "Keyboard State Snooper"},
    "BitBlt": {"score": 15, "role": "Screen Capture / Spyware"},
    "GetDC": {"score": 10, "role": "Device Context Capture"},
    
    # Evasion & Privilege Escalation
    "AdjustTokenPrivileges": {"score": 15, "role": "Privilege Escalation (SeDebugPrivilege)"},
    "OpenProcessToken": {"score": 10, "role": "Token Access"},
    "IsDebuggerPresent": {"score": 10, "role": "Anti-Analysis / Anti-Debugging"}
}

