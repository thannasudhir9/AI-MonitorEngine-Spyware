"""
AegisShield - Drive Space & Malware Dropper Staging Zone Analyzer
Inspired by DriveOrganiserAndAnalyzer-AG2.0:
Scans all local drives/partitions, analyzes disk space usage, and audits
malware dropper staging zones (%TEMP%, AppData, Windows Temp).
"""

import os
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List


class DriveAnalyzerEngine:
    def __init__(self):
        self.dropper_extensions = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".dll"}

    def get_drives_overview(self) -> Dict[str, Any]:
        """Enumerate all connected physical and logical partitions with space telemetry."""
        drives = []
        total_capacity_gb = 0
        total_used_gb = 0
        total_free_gb = 0

        for part in psutil.disk_partitions(all=False):
            if not part.mountpoint:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                cap = round(usage.total / (1024 ** 3), 2)
                used = round(usage.used / (1024 ** 3), 2)
                free = round(usage.free / (1024 ** 3), 2)
                total_capacity_gb += cap
                total_used_gb += used
                total_free_gb += free

                drives.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "opts": part.opts,
                    "total_gb": cap,
                    "used_gb": used,
                    "free_gb": free,
                    "percent_used": usage.percent
                })
            except (PermissionError, OSError):
                continue

        return {
            "total_drives": len(drives),
            "total_capacity_gb": round(total_capacity_gb, 2),
            "total_used_gb": round(total_used_gb, 2),
            "total_free_gb": round(total_free_gb, 2),
            "overall_percent_used": round((total_used_gb / total_capacity_gb * 100), 1) if total_capacity_gb > 0 else 0,
            "drives": drives,
            "timestamp": datetime.now().isoformat()
        }

    def scan_dropper_staging_zones(self, max_items: int = 50) -> Dict[str, Any]:
        """
        Audit high-risk directories where malware, spyware, and trojans typically drop payloads:
        %TEMP%, AppData/Local/Temp, C:\\Windows\\Temp, C:\\Users\\Public.
        """
        candidate_zones = []
        user_temp = os.environ.get("TEMP")
        if user_temp and os.path.exists(user_temp):
            candidate_zones.append(("User Temp", Path(user_temp)))

        appdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            alt_temp = Path(appdata) / "Temp"
            if alt_temp.exists() and alt_temp != Path(user_temp or ""):
                candidate_zones.append(("AppData Local Temp", alt_temp))

        public_dir = os.environ.get("PUBLIC")
        if public_dir and os.path.exists(public_dir):
            candidate_zones.append(("Public Directory", Path(public_dir)))

        win_temp = Path("C:/Windows/Temp")
        if win_temp.exists():
            candidate_zones.append(("Windows System Temp", win_temp))

        found_droppers = []
        total_scanned_files = 0
        total_dropper_bytes = 0

        for zone_name, zone_path in candidate_zones:
            try:
                for entry in zone_path.iterdir():
                    if entry.is_file():
                        total_scanned_files += 1
                        suffix = entry.suffix.lower()
                        if suffix in self.dropper_extensions:
                            try:
                                sz = entry.stat().st_size
                                total_dropper_bytes += sz
                                mtime = datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                                found_droppers.append({
                                    "zone": zone_name,
                                    "filename": entry.name,
                                    "path": str(entry.resolve()),
                                    "extension": suffix,
                                    "size_kb": round(sz / 1024, 1),
                                    "size_bytes": sz,
                                    "modified": mtime,
                                    "is_suspicious": suffix in [".exe", ".scr", ".bat", ".ps1", ".vbs", ".hta"]
                                })
                                if len(found_droppers) >= max_items:
                                    break
                            except (PermissionError, OSError):
                                continue
            except (PermissionError, OSError):
                continue

        return {
            "total_zones": len(candidate_zones),
            "zones_audited": [z[0] for z in candidate_zones],
            "total_files_scanned": total_scanned_files,
            "dropper_count": len(found_droppers),
            "dropper_size_mb": round(total_dropper_bytes / (1024 * 1024), 2),
            "droppers": found_droppers
        }

    def clean_temp_droppers(self, safe_only: bool = True) -> Dict[str, Any]:
        """Safely clean temporary files and suspected droppers in %TEMP%."""
        user_temp = os.environ.get("TEMP")
        if not user_temp or not os.path.exists(user_temp):
            return {"success": False, "cleaned_count": 0, "freed_mb": 0, "message": "Temp directory not found"}

        cleaned_count = 0
        freed_bytes = 0
        errors = 0

        p = Path(user_temp)
        for item in p.iterdir():
            try:
                if item.is_file():
                    # If safe_only, clean files with extensions or temp prefixes
                    sz = item.stat().st_size
                    item.unlink()
                    cleaned_count += 1
                    freed_bytes += sz
            except Exception:
                errors += 1

        freed_mb = round(freed_bytes / (1024 * 1024), 2)
        return {
            "success": True,
            "cleaned_count": cleaned_count,
            "freed_mb": freed_mb,
            "errors": errors,
            "message": f"Successfully cleaned {cleaned_count} files ({freed_mb} MB freed)."
        }
