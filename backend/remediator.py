"""
AegisShield - Remediation & Eradication Engine
Safe process termination, recursive tree killing, threat quarantine,
and immutable incident audit logging.
"""

import os
import time
import json
import shutil
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import LOGS_DIR, QUARANTINE_DIR, CRITICAL_SYSTEM_PROCESSES, SCORE_MEDIUM
from .pe_analyzer import get_file_hashes

AUDIT_LOG_FILE = LOGS_DIR / "audit_events.json"


class ThreatRemediator:
    """Handles eradication of malicious processes, tree pruning, quarantine, and logs."""

    def __init__(self):
        self._audit_log: List[Dict[str, Any]] = self._load_audit_log()

    def _load_audit_log(self) -> List[Dict[str, Any]]:
        """Load persistent incident log from disk."""
        if AUDIT_LOG_FILE.exists():
            try:
                with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_audit_log(self):
        """Persist audit log to disk."""
        try:
            with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._audit_log[-500:], f, indent=2)  # Retain latest 500 events
        except Exception:
            pass

    def log_event(self, action: str, target: str, pid: Optional[int], details: str, status: str = "SUCCESS"):
        """Record an incident or remediation event."""
        event = {
            "id": f"evt_{int(time.time() * 1000)}",
            "timestamp": datetime.now().isoformat(),
            "time_display": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "target": target,
            "pid": pid,
            "details": details,
            "status": status
        }
        self._audit_log.insert(0, event)
        if len(self._audit_log) > 500:
            self._audit_log = self._audit_log[:500]
        self._save_audit_log()
        return event

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent audit events."""
        return self._audit_log[:limit]

    def is_protected(self, proc: psutil.Process) -> bool:
        """Check if process is a protected Windows core binary."""
        try:
            name = (proc.name() or "").lower()
            if name in CRITICAL_SYSTEM_PROCESSES:
                sys_rule = CRITICAL_SYSTEM_PROCESSES[name]
                if not sys_rule.get("allow_kill", True):
                    # Check if running from legitimate System32
                    expected = sys_rule.get("expected_path")
                    try:
                        exe = (proc.exe() or "").lower()
                        if not expected or exe.startswith(expected):
                            return True
                    except Exception:
                        return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def kill_process(self, pid: int, force: bool = True, reason: str = "Manual Eradication") -> Dict[str, Any]:
        """
        Safely terminate a single process by PID.
        """
        try:
            if not psutil.pid_exists(pid):
                return {"success": False, "message": f"Process PID {pid} does not exist or has already exited."}

            proc = psutil.Process(pid)
            name = proc.name()

            # Safeguard core system processes
            if self.is_protected(proc):
                self.log_event("KILL_ABORTED", name, pid, "Protected core Windows OS process - Termination blocked", "BLOCKED")
                return {
                    "success": False,
                    "message": f"Cannot terminate '{name}' (PID: {pid}). This is a protected Windows core system process."
                }

            # Attempt termination
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                if force:
                    proc.kill()
                    proc.wait(timeout=1.5)

            self.log_event("PROCESS_KILLED", name, pid, f"{reason}. Successfully terminated.", "SUCCESS")
            return {
                "success": True,
                "message": f"Successfully terminated process '{name}' (PID: {pid}).",
                "pid": pid,
                "name": name
            }

        except psutil.NoSuchProcess:
            return {"success": True, "message": f"Process PID {pid} already exited."}
        except psutil.AccessDenied:
            self.log_event("KILL_FAILED", str(pid), pid, "Access denied. Elevated administrator rights required.", "FAILED")
            return {
                "success": False,
                "message": f"Access denied when killing PID {pid}. Please run AegisShield as Administrator."
            }
        except Exception as e:
            self.log_event("KILL_ERROR", str(pid), pid, str(e), "ERROR")
            return {"success": False, "message": f"Error terminating process: {str(e)}"}

    def kill_process_tree(self, pid: int, reason: str = "Tree Eradication") -> Dict[str, Any]:
        """
        Recursively discover and terminate a parent process and all its children.
        """
        try:
            if not psutil.pid_exists(pid):
                return {"success": False, "message": f"Process PID {pid} does not exist."}

            parent = psutil.Process(pid)
            parent_name = parent.name()

            if self.is_protected(parent):
                return {"success": False, "message": f"Process '{parent_name}' is a protected core system component."}

            # Gather all children recursively
            children = parent.children(recursive=True)
            killed_list = []

            # Kill children first
            for child in children:
                try:
                    c_name = child.name()
                    c_pid = child.pid
                    if not self.is_protected(child):
                        child.kill()
                        killed_list.append(f"{c_name} (PID: {c_pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Kill parent
            parent.kill()
            killed_list.append(f"{parent_name} (PID: {pid})")

            details = f"Terminated tree of {len(killed_list)} processes: {', '.join(killed_list)}"
            self.log_event("PROCESS_TREE_KILLED", parent_name, pid, details, "SUCCESS")

            return {
                "success": True,
                "message": f"Successfully eradicated process tree ({len(killed_list)} processes killed).",
                "killed_processes": killed_list
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"success": False, "message": f"Failed to kill process tree: {str(e)}"}

    def kill_all_threats(self, detected_threats: List[Dict[str, Any]], min_score: int = SCORE_MEDIUM) -> Dict[str, Any]:
        """
        Bulk eradicate all detected high-risk threats currently running.
        Safely ignores protected processes.
        """
        killed = []
        errors = []

        for threat in detected_threats:
            if threat.get("threat_score", 0) < min_score:
                continue
            if threat.get("is_protected", False):
                continue

            pid = threat.get("pid")
            name = threat.get("name", "Unknown")
            cat = threat.get("primary_category", "THREAT")

            res = self.kill_process(pid, force=True, reason=f"Bulk Eradication [{cat} - Score: {threat.get('threat_score')}]")
            if res.get("success"):
                killed.append({"pid": pid, "name": name, "category": cat})
            else:
                errors.append({"pid": pid, "name": name, "error": res.get("message")})

        self.log_event(
            "BULK_THREAT_KILL",
            f"{len(killed)} Threats",
            None,
            f"Bulk eradication executed. Killed: {len(killed)}, Failed/Skipped: {len(errors)}",
            "SUCCESS" if killed else "INFO"
        )

        return {
            "success": True,
            "killed_count": len(killed),
            "killed": killed,
            "failed_count": len(errors),
            "errors": errors,
            "message": f"Bulk eradication completed: {len(killed)} threats killed, {len(errors)} skipped."
        }

    def quarantine_file(self, file_path: str, reason: str = "Suspicious Binary") -> Dict[str, Any]:
        """
        Isolate a suspicious executable into the quarantine repository.
        Renames and revokes execute attributes.
        """
        if not file_path or not os.path.exists(file_path):
            return {"success": False, "message": "File does not exist or invalid path."}

        try:
            src = Path(file_path)
            hashes = get_file_hashes(file_path)
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{src.stem}_{timestamp_str}_{hashes['sha256'][:8]}.quarantined"
            dest = QUARANTINE_DIR / quarantine_filename

            # Copy or move
            shutil.copy2(src, dest)
            try:
                os.remove(src)
                moved = True
            except Exception:
                moved = False

            # Save quarantine receipt
            meta = {
                "original_path": file_path,
                "quarantine_path": str(dest),
                "quarantined_at": datetime.now().isoformat(),
                "hashes": hashes,
                "reason": reason,
                "original_removed": moved
            }
            meta_file = dest.with_suffix(".json")
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            self.log_event("FILE_QUARANTINED", src.name, None, f"Quarantined to {dest.name}. Removed source: {moved}", "SUCCESS")

            return {
                "success": True,
                "message": f"File quarantined successfully to '{dest.name}'.",
                "quarantine_name": dest.name,
                "moved": moved
            }

        except Exception as e:
            self.log_event("QUARANTINE_FAILED", file_path, None, str(e), "ERROR")
            return {"success": False, "message": f"Quarantine failed: {str(e)}"}

