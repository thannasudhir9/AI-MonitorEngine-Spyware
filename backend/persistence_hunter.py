"""
AegisShield - Persistence & Autoruns Hunter
Scans Windows Startup Folders, Registry Run Keys, and Scheduled Tasks
to discover hidden persistence mechanisms used by Trojans, Spyware, and RATs.
"""

import os
import sys
import csv
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import SUSPICIOUS_PATHS
from .signatures_db import RMM_DATABASE, TROJAN_RAT_DATABASE, TUNNEL_DATABASE


def scan_startup_folders() -> List[Dict[str, Any]]:
    """Scan User and System-wide Startup folders for autorun shortcuts and binaries."""
    items = []
    folders = []

    # User Startup Folder
    appdata = os.environ.get("APPDATA")
    if appdata:
        folders.append({
            "path": Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            "scope": "Current User Startup"
        })

    # All Users / ProgramData Startup Folder
    programdata = os.environ.get("PROGRAMDATA")
    if programdata:
        folders.append({
            "path": Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            "scope": "All Users Startup"
        })

    for folder_meta in folders:
        folder_path = folder_meta["path"]
        if not folder_path.exists():
            continue

        try:
            for entry in folder_path.iterdir():
                if entry.name.lower() in ("desktop.ini",):
                    continue

                item_path = str(entry.resolve())
                item_name = entry.name
                lower_name = item_name.lower()

                # Evaluate risk
                is_suspicious = False
                flags = []
                score = 0

                # Check extensions
                if lower_name.endswith((".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta")):
                    is_suspicious = True
                    score += 40
                    flags.append("Script file set to run on system startup")
                elif lower_name.endswith((".exe", ".scr")):
                    score += 20
                    flags.append("Direct binary in startup folder")

                # Check known threats
                if lower_name in TROJAN_RAT_DATABASE:
                    score += 90
                    is_suspicious = True
                    flags.append(f"Known Trojan / RAT payload: {TROJAN_RAT_DATABASE[lower_name]['name']}")

                if lower_name in RMM_DATABASE:
                    score += 50
                    is_suspicious = True
                    flags.append(f"Auto-starting Remote Desktop / RMM tool: {RMM_DATABASE[lower_name]['name']}")

                items.append({
                    "id": f"startup_{entry.name}",
                    "name": item_name,
                    "target_path": item_path,
                    "location_type": folder_meta["scope"],
                    "location": str(folder_path),
                    "is_suspicious": is_suspicious or score >= 40,
                    "threat_score": min(score, 100),
                    "flags": flags,
                    "can_disable": True
                })
        except Exception:
            pass

    return items


def scan_registry_run_keys() -> List[Dict[str, Any]]:
    """Scan Windows Registry Run and RunOnce keys."""
    items = []
    
    # Try importing winreg
    try:
        import winreg
    except ImportError:
        return items

    keys_to_check = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce")
    ]

    for root_hkey, sub_path, label in keys_to_check:
        try:
            with winreg.OpenKey(root_hkey, sub_path, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        data_str = str(val_data).strip()
                        lower_data = data_str.lower()

                        score = 0
                        flags = []
                        is_suspicious = False

                        # Heuristic: Running from suspicious folder (Temp, AppData, etc.)
                        for susp in SUSPICIOUS_PATHS:
                            if susp in lower_data:
                                score += 50
                                is_suspicious = True
                                flags.append(f"Runs from suspicious directory: {susp}")
                                break

                        # Heuristic: Script interpreter or LOLBin
                        if any(term in lower_data for term in ["powershell", "wscript", "cscript", "mshta", "cmd /c"]):
                            score += 40
                            is_suspicious = True
                            flags.append("Launches command interpreter at startup")

                        # Match known trojans
                        for bad_name in TROJAN_RAT_DATABASE:
                            if bad_name in lower_data:
                                score += 80
                                is_suspicious = True
                                flags.append(f"Matches known malware signature: {bad_name}")

                        items.append({
                            "id": f"reg_{label}_{val_name}",
                            "name": val_name,
                            "target_path": data_str,
                            "location_type": f"Registry ({label})",
                            "location": sub_path,
                            "is_suspicious": is_suspicious or score >= 40,
                            "threat_score": min(score, 100),
                            "flags": flags,
                            "can_disable": True
                        })
                    except Exception:
                        continue
        except (PermissionError, OSError):
            continue

    return items


def scan_scheduled_tasks() -> List[Dict[str, Any]]:
    """Scan Windows Scheduled Tasks for suspicious jobs."""
    items = []
    try:
        # Run schtasks /query /fo csv
        output = subprocess.check_output(
            ["schtasks.exe", "/query", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5
        )
        reader = csv.reader(output.splitlines())
        for row in reader:
            if not row or len(row) < 2:
                continue
            task_name = row[0].strip('"')
            task_status = row[1] if len(row) > 1 else ""
            lower_task = task_name.lower()

            # Filter out standard Microsoft system tasks for efficiency
            if lower_task.startswith(("\\microsoft\\windows\\", "\\microsoft\\office\\")):
                continue

            score = 0
            flags = []
            is_suspicious = False

            for susp in SUSPICIOUS_PATHS:
                if susp in lower_task:
                    score += 45
                    is_suspicious = True
                    flags.append(f"Task name or path references suspicious folder: {susp}")

            for bad in TROJAN_RAT_DATABASE:
                if bad in lower_task:
                    score += 85
                    is_suspicious = True
                    flags.append(f"Task matches known malware signature: {bad}")

            items.append({
                "id": f"task_{task_name}",
                "name": task_name,
                "target_path": task_name,
                "location_type": "Scheduled Task",
                "location": "Windows Task Scheduler",
                "is_suspicious": is_suspicious,
                "threat_score": min(score, 100),
                "flags": flags,
                "status": task_status,
                "can_disable": True
            })
    except Exception:
        pass

    return items


def get_all_persistence_entries() -> List[Dict[str, Any]]:
    """Gather all persistence vectors across Startup, Registry, and Tasks."""
    results = []
    results.extend(scan_startup_folders())
    results.extend(scan_registry_run_keys())
    results.extend(scan_scheduled_tasks())
    return results


def disable_persistence_item(item_id: str, item_path: str, location_type: str) -> Dict[str, Any]:
    """Disable or remove a persistent autorun item."""
    try:
        if "Startup" in location_type:
            target = Path(item_path)
            if target.exists():
                # Rename with .disabled extension for safety
                disabled_name = target.with_suffix(target.suffix + ".disabled")
                target.rename(disabled_name)
                return {"success": True, "message": f"Startup item disabled: {target.name} -> {disabled_name.name}"}
            return {"success": False, "message": "File not found"}

        elif "Registry" in location_type:
            import winreg
            # Parse registry location
            root = winreg.HKEY_CURRENT_USER if "HKCU" in location_type else winreg.HKEY_LOCAL_MACHINE
            sub_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            if "RunOnce" in location_type:
                sub_key = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"

            val_name = item_id.split("_")[-1]
            with winreg.OpenKey(root, sub_key, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, val_name)
            return {"success": True, "message": f"Registry autorun value '{val_name}' deleted successfully"}

        elif "Scheduled Task" in location_type:
            task_name = item_path
            subprocess.run(["schtasks.exe", "/delete", "/tn", task_name, "/f"], check=True, timeout=5)
            return {"success": True, "message": f"Scheduled task '{task_name}' deleted"}

        return {"success": False, "message": "Unknown persistence type"}
    except Exception as e:
        return {"success": False, "message": f"Failed to disable persistence: {str(e)}"}

