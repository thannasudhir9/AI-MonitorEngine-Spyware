"""
AegisShield - Harmless Threat Simulation Lab
Allows users to safely launch benign test processes that exhibit detectable
malware, spyware, and RAT patterns (e.g., Temp execution, hidden window,
disguised process name) to verify detection and remediation in real time.
"""

import os
import sys
import time
import subprocess
from typing import Dict, List, Any
from pathlib import Path

# Track simulated test PIDs
_SIMULATED_PIDS: List[int] = []


def spawn_simulated_threat(threat_type: str = "temp_trojan") -> Dict[str, Any]:
    """
    Launch a completely harmless background Python process mimicking suspicious behavior.
    """
    try:
        if threat_type == "temp_trojan":
            # Spawns harmless sleep in Temp folder with suspicious name
            temp_dir = Path(os.environ.get("TEMP", "."))
            dummy_script = temp_dir / "simulated_trojan_test.py"
            with open(dummy_script, "w", encoding="utf-8") as f:
                f.write("""# AegisShield Safe Test Process
import time
print('Simulated Suspicious Process Active')
while True:
    time.sleep(1)
""")
            # Launch with hidden style or standard
            proc = subprocess.Popen(
                [sys.executable, str(dummy_script), "--simulated-rat-beacon"],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            _SIMULATED_PIDS.append(proc.pid)
            return {
                "success": True,
                "pid": proc.pid,
                "type": "Temp Execution Trojan (Simulated)",
                "details": f"Spawned simulated threat in {temp_dir} with PID {proc.pid}"
            }

        elif threat_type == "encoded_cmdline":
            # Spawns harmless process with simulated encoded/obfuscated command line
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(300)", "-enc", "-w", "hidden", "downloadstring"],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            _SIMULATED_PIDS.append(proc.pid)
            return {
                "success": True,
                "pid": proc.pid,
                "type": "Obfuscated LOLBin Cradle (Simulated)",
                "details": f"Spawned simulated encoded command process with PID {proc.pid}"
            }

        elif threat_type == "rmm_beacon":
            # Spawns harmless process listening or tagged as remote desktop beacon
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(300)", "--remote-vnc-session", "--port-5900"],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            _SIMULATED_PIDS.append(proc.pid)
            return {
                "success": True,
                "pid": proc.pid,
                "type": "Remote Desktop / RMM Beacon (Simulated)",
                "details": f"Spawned simulated remote control beacon with PID {proc.pid}"
            }

        return {"success": False, "message": "Unknown simulation type"}

    except Exception as e:
        return {"success": False, "message": f"Simulation failed: {str(e)}"}


def stop_all_simulations() -> Dict[str, Any]:
    """Terminate any lingering simulated test processes."""
    killed = 0
    import psutil
    global _SIMULATED_PIDS
    for pid in list(_SIMULATED_PIDS):
        try:
            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.kill()
                killed += 1
        except Exception:
            pass
    _SIMULATED_PIDS.clear()
    return {"success": True, "killed": killed, "message": f"Cleaned up {killed} test simulations."}

