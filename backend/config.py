"""
AegisShield - Spyware, Antivirus, Malware, RMM & Trojan Detector
Configuration, Whitelists, and Constants
"""

import os
from pathlib import Path

# Base Paths
APP_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = APP_ROOT / "logs"
QUARANTINE_DIR = APP_ROOT / "quarantine"
DATABASE_DIR = APP_ROOT / "database"

# Ensure directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_DIR.mkdir(parents=True, exist_ok=True)

# Server Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

# Threat Score Thresholds (0 - 100)
SCORE_SAFE = 0
SCORE_LOW = 25
SCORE_MEDIUM = 50
SCORE_HIGH = 75
SCORE_CRITICAL = 90

# Critical Windows System Binaries
# These must ONLY run from C:\Windows\System32 (or SysWOW64).
# If running elsewhere, they are flagged as MASQUERADING / CRITICAL MALWARE.
# They are also protected from being killed accidentally.
CRITICAL_SYSTEM_PROCESSES = {
    "system": {"expected_path": None, "allow_kill": False},
    "registry": {"expected_path": None, "allow_kill": False},
    "smss.exe": {"expected_path": r"c:\windows\system32\smss.exe", "allow_kill": False},
    "csrss.exe": {"expected_path": r"c:\windows\system32\csrss.exe", "allow_kill": False},
    "wininit.exe": {"expected_path": r"c:\windows\system32\wininit.exe", "allow_kill": False},
    "services.exe": {"expected_path": r"c:\windows\system32\services.exe", "allow_kill": False},
    "lsass.exe": {"expected_path": r"c:\windows\system32\lsass.exe", "allow_kill": False},
    "svchost.exe": {"expected_path": r"c:\windows\system32\svchost.exe", "allow_kill": True},
    "winlogon.exe": {"expected_path": r"c:\windows\system32\winlogon.exe", "allow_kill": False},
    "fontdrvhost.exe": {"expected_path": r"c:\windows\system32\fontdrvhost.exe", "allow_kill": False},
    "dwm.exe": {"expected_path": r"c:\windows\system32\dwm.exe", "allow_kill": False},
    "explorer.exe": {"expected_path": r"c:\windows\explorer.exe", "allow_kill": True},
}

# Known Typosquats / Masquerading names commonly used by Trojans
TYPOSQUAT_PATTERNS = [
    "svch0st", "scvhost", "svchost32", "svchosts",
    "lsasss", "lsas", "lsass32", "isass",
    "csrsss", "csrs", "csrss32",
    "smsss", "smss32",
    "services32", "servicess",
    "taskmngr", "taskmgrr", "taskmgr32",
    "explorerr", "explor3r", "explorer32",
    "winlog0n", "winlogon32",
    "rund1132", "rundll", "rundll64",
    "spoolsv32", "spoolsvv",
    "dwm0", "dwm32",
    "chrome_updater", "windows_updater", "system_update"
]

# Suspicious Directory Substrings where executables should typically NOT execute
SUSPICIOUS_PATHS = [
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
    r"\$recycle.bin",
    r"\appdata\roaming\temp",
    r"\device\harddiskvolume",
]

# Remote Desktop & RMM Default Ports
RMM_PORTS = {
    3389: "Microsoft Remote Desktop (RDP)",
    5900: "VNC Remote Desktop (Standard)",
    5901: "VNC Remote Desktop (Display 1)",
    5902: "VNC Remote Desktop (Display 2)",
    5938: "TeamViewer Control Port",
    7070: "AnyDesk Direct Port",
    6568: "AnyDesk Secondary Port",
    8040: "ConnectWise ScreenConnect Relay",
    8041: "ConnectWise ScreenConnect Client",
    21115: "RustDesk Rendezvous Server",
    21116: "RustDesk NAT Traversal / Heartbeat",
    21117: "RustDesk Relay Server",
    21118: "RustDesk Web Client",
    5650: "Remote Utilities Host",
    6783: "Splashtop Port",
    4782: "QuasarRAT Default Port",
    1177: "njRAT Default Port",
    1604: "DarkComet RAT Default Port",
    2404: "Remcos RAT Default Port",
    6606: "AsyncRAT Default Port",
    7707: "AsyncRAT Alternate Port",
    8808: "AsyncRAT Alternate Port",
    4444: "Metasploit / Reverse Shell Default",
    5555: "Android ADB / Trojan Reverse Shell",
    3333: "Crypto Mining Stratum Pool",
    7777: "Trojan / Miner Pool Port",
    9999: "Trojan / Miner Pool Port"
}

