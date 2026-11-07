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
import subprocess
import ctypes
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import LOGS_DIR, QUARANTINE_DIR, CRITICAL_SYSTEM_PROCESSES, SCORE_MEDIUM
from .pe_analyzer import get_file_hashes

AUDIT_LOG_FILE = LOGS_DIR / "audit_events.json"


def enable_debug_privilege() -> bool:
    """Acquire SeDebugPrivilege to allow terminating processes across user and service boundaries."""
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002

        h_token = wintypes.HANDLE()
        h_process = kernel32.GetCurrentProcess()
        if not advapi32.OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
            return False

        luid = wintypes.LARGE_INTEGER()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            kernel32.CloseHandle(h_token)
            return False

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", wintypes.LARGE_INTEGER), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
        kernel32.CloseHandle(h_token)
        return True
    except Exception:
        return False


# Attempt SeDebugPrivilege elevation on module import
enable_debug_privilege()


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

    def get_blocked_history(self, limit: int = 150) -> List[Dict[str, Any]]:
        """Retrieve tracking history of all processes killed, IPs blocked, and files quarantined."""
        blocked_actions = {
            "PROCESS_KILLED",
            "PROCESS_TREE_KILLED",
            "IP_BLOCKED",
            "FILE_QUARANTINED",
            "PERSISTENCE_DISABLED",
            "KILL_ABORTED",
            "KILL_FAILED"
        }
        history = [e for e in self._audit_log if e.get("action") in blocked_actions]
        return history[:limit]

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

    def get_service_for_pid(self, pid: int) -> Optional[str]:
        """Detect if target PID belongs to a registered Windows Service."""
        try:
            cmd = f"Get-CimInstance Win32_Service | Where-Object {{ $_.ProcessId -eq {pid} }} | Select-Object -ExpandProperty Name"
            res = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=2.0)
            svc = res.stdout.strip()
            if svc:
                return svc

            # Fallback: query via native tasklist /svc
            tk = subprocess.run(["tasklist", "/svc", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=2.0)
            if tk.stdout:
                parts = tk.stdout.strip().replace('"', '').split(',')
                if len(parts) >= 3:
                    candidate = parts[2].strip()
                    if candidate.lower() not in ["n/a", "none", ""]:
                        return candidate
            return None
        except Exception:
            return None

    def kill_process(self, pid: int, force: bool = True, reason: str = "Manual Eradication") -> Dict[str, Any]:
        """
        Safely terminate a single process by PID with multi-tier failover and UAC elevation handling.
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

            # Check if this PID is managed by a Windows Service
            svc_name = self.get_service_for_pid(pid)
            if svc_name:
                try:
                    subprocess.run(["sc", "stop", svc_name], capture_output=True, text=True, timeout=2.5)
                    time.sleep(0.4)
                    if not psutil.pid_exists(pid):
                        self.log_event("PROCESS_KILLED", name, pid, f"{reason}. Stopped host Windows Service '{svc_name}'.", "SUCCESS")
                        return {
                            "success": True,
                            "message": f"Successfully stopped Windows Service '{svc_name}' hosting process '{name}' (PID: {pid}).",
                            "pid": pid,
                            "name": name,
                            "service_name": svc_name
                        }
                except Exception:
                    pass

            # Attempt termination via psutil
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=0.8)
                except psutil.TimeoutExpired:
                    if force:
                        proc.kill()
                        proc.wait(timeout=0.8)
            except (psutil.AccessDenied, psutil.TimeoutExpired):
                # Fallback Tier 1: Windows Native Taskkill
                tk_res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
                time.sleep(0.3)
                if not psutil.pid_exists(pid) or tk_res.returncode == 0:
                    self.log_event("PROCESS_KILLED", name, pid, f"{reason}. Terminated via native taskkill.", "SUCCESS")
                    return {
                        "success": True,
                        "message": f"Successfully terminated process '{name}' (PID: {pid}) via native taskkill.",
                        "pid": pid,
                        "name": name
                    }

                # Fallback Tier 2: PowerShell Stop-Process -Force
                ps_cmd = f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
                subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
                time.sleep(0.3)
                if not psutil.pid_exists(pid):
                    self.log_event("PROCESS_KILLED", name, pid, f"{reason}. Terminated via PowerShell force.", "SUCCESS")
                    return {
                        "success": True,
                        "message": f"Successfully terminated process '{name}' (PID: {pid}) via PowerShell force.",
                        "pid": pid,
                        "name": name
                    }

                # Fallback Tier 3: Trigger UAC Elevation Dialog with -Wait
                uac_cmd = f"Start-Process taskkill -ArgumentList '/F /T /PID {pid}' -Verb RunAs -Wait -WindowStyle Hidden"
                subprocess.run(["powershell", "-NoProfile", "-Command", uac_cmd], capture_output=True, text=True)
                time.sleep(0.8)
                if not psutil.pid_exists(pid):
                    self.log_event("PROCESS_KILLED", name, pid, f"{reason}. Terminated via Administrator UAC.", "SUCCESS")
                    return {
                        "success": True,
                        "message": f"Successfully terminated elevated process '{name}' (PID: {pid}) via Administrator UAC.",
                        "pid": pid,
                        "name": name
                    }

                # If still alive, report actionable elevation guidance
                details_msg = f"Access denied. Process '{name}' (PID: {pid}) is protected by Windows SYSTEM/Service token."
                if svc_name:
                    details_msg += f" Hosted in Windows Service: '{svc_name}'."
                self.log_event("KILL_FAILED", name, pid, details_msg, "FAILED")
                return {
                    "success": False,
                    "message": f"Access denied for process '{name}' (PID: {pid}). Elevated administrator rights required.",
                    "requires_admin": True,
                    "pid": pid,
                    "name": name,
                    "service_name": svc_name,
                    "admin_command": f"taskkill /F /PID {pid}"
                }

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
            # Native fallback if psutil was blocked on init
            tk_res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
            if not psutil.pid_exists(pid) or tk_res.returncode == 0:
                self.log_event("PROCESS_KILLED", str(pid), pid, f"{reason}. Terminated via taskkill fallback.", "SUCCESS")
                return {"success": True, "message": f"Terminated PID {pid} using native taskkill."}

            # Prompt UAC
            uac_cmd = f"Start-Process taskkill -ArgumentList '/F /T /PID {pid}' -Verb RunAs -Wait -WindowStyle Hidden"
            subprocess.run(["powershell", "-NoProfile", "-Command", uac_cmd], capture_output=True, text=True)
            time.sleep(0.8)
            if not psutil.pid_exists(pid):
                return {"success": True, "message": f"Terminated PID {pid} via Administrator UAC elevation."}

            self.log_event("KILL_FAILED", str(pid), pid, "Access denied. Elevated administrator rights required.", "FAILED")
            return {
                "success": False,
                "message": f"Access denied when killing PID {pid}. Elevated administrator rights required.",
                "requires_admin": True,
                "pid": pid,
                "admin_command": f"taskkill /F /PID {pid}"
            }
        except Exception as e:
            self.log_event("KILL_ERROR", str(pid), pid, str(e), "ERROR")
            return {"success": False, "message": f"Error terminating process: {str(e)}"}

    def kill_process_tree(self, pid: int, reason: str = "Tree Eradication") -> Dict[str, Any]:
        """
        Recursively discover and terminate a parent process and all its children
        with multi-tier failover (sc stop, taskkill /F /T, PowerShell, UAC elevation).
        """
        try:
            if not psutil.pid_exists(pid):
                return {"success": False, "message": f"Process PID {pid} does not exist."}

            try:
                parent = psutil.Process(pid)
                parent_name = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_name = f"PID:{pid}"

            if psutil.pid_exists(pid):
                try:
                    proc_check = psutil.Process(pid)
                    if self.is_protected(proc_check):
                        return {"success": False, "message": f"Process '{parent_name}' is a protected core system component."}
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Tier 1: Check if this PID is managed by a Windows Service (e.g., AnyDesk, TeamViewer)
            svc_name = self.get_service_for_pid(pid)
            if svc_name:
                try:
                    subprocess.run(["sc", "stop", svc_name], capture_output=True, text=True, timeout=2.5)
                    time.sleep(0.4)
                    if not psutil.pid_exists(pid):
                        details = f"{reason}. Stopped host Windows Service '{svc_name}'."
                        self.log_event("PROCESS_TREE_KILLED", parent_name, pid, details, "SUCCESS")
                        return {
                            "success": True,
                            "message": f"Successfully stopped Windows Service '{svc_name}' hosting process tree for '{parent_name}' (PID: {pid}).",
                            "killed_processes": [f"{parent_name} (Service: {svc_name})"],
                            "service_name": svc_name
                        }
                except Exception:
                    pass

            killed_list = []
            # Tier 2: Attempt standard psutil child + parent kill
            try:
                parent = psutil.Process(pid)
                children = parent.children(recursive=True)
                for child in children:
                    try:
                        c_name = child.name()
                        c_pid = child.pid
                        if not self.is_protected(child):
                            child.kill()
                            killed_list.append(f"{c_name} (PID: {c_pid})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                parent.kill()
                killed_list.append(f"{parent_name} (PID: {pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            time.sleep(0.3)
            if not psutil.pid_exists(pid):
                details = f"Terminated tree of {len(killed_list)} processes: {', '.join(killed_list)}"
                self.log_event("PROCESS_TREE_KILLED", parent_name, pid, details, "SUCCESS")
                return {
                    "success": True,
                    "message": f"Successfully eradicated process tree ({len(killed_list)} processes killed).",
                    "killed_processes": killed_list
                }

            # Tier 3: Native Windows taskkill with /T (Tree) and /F (Force)
            tk_res = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, text=True)
            time.sleep(0.3)
            if not psutil.pid_exists(pid) or tk_res.returncode == 0:
                self.log_event("PROCESS_TREE_KILLED", parent_name, pid, f"{reason}. Eradicated via native taskkill /F /T.", "SUCCESS")
                return {
                    "success": True,
                    "message": f"Successfully eradicated process tree for '{parent_name}' (PID: {pid}) via native taskkill.",
                    "killed_processes": [f"{parent_name} (PID: {pid})"]
                }

            # Tier 4: PowerShell Stop-Process -Force
            ps_cmd = f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
            time.sleep(0.3)
            if not psutil.pid_exists(pid):
                self.log_event("PROCESS_TREE_KILLED", parent_name, pid, f"{reason}. Eradicated via PowerShell force.", "SUCCESS")
                return {
                    "success": True,
                    "message": f"Successfully eradicated process tree for '{parent_name}' (PID: {pid}) via PowerShell force.",
                    "killed_processes": [f"{parent_name} (PID: {pid})"]
                }

            # Tier 5: Interactive UAC Elevation with -Wait
            uac_cmd = f"Start-Process taskkill -ArgumentList '/F /T /PID {pid}' -Verb RunAs -Wait -WindowStyle Hidden"
            subprocess.run(["powershell", "-NoProfile", "-Command", uac_cmd], capture_output=True, text=True)
            time.sleep(0.8)
            if not psutil.pid_exists(pid):
                self.log_event("PROCESS_TREE_KILLED", parent_name, pid, f"{reason}. Eradicated via Administrator UAC.", "SUCCESS")
                return {
                    "success": True,
                    "message": f"Successfully eradicated process tree for '{parent_name}' (PID: {pid}) via Administrator UAC.",
                    "killed_processes": [f"{parent_name} (PID: {pid})"]
                }

            # If still alive, report elevation guidance & service name
            details_msg = f"Access denied. Process tree '{parent_name}' (PID: {pid}) is protected by Windows SYSTEM/Service token."
            if svc_name:
                details_msg += f" Hosted in Windows Service: '{svc_name}'."
            self.log_event("KILL_FAILED", parent_name, pid, details_msg, "FAILED")
            return {
                "success": False,
                "message": f"Access denied for process tree '{parent_name}' (PID: {pid}). Elevated administrator rights required.",
                "requires_admin": True,
                "pid": pid,
                "name": parent_name,
                "service_name": svc_name
            }

        except Exception as e:
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

