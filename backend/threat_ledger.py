"""
AegisShield - Threat Tracking & Anomaly Ledger Engine
Maintains an immutable, persistent chronological ledger of all suspicious and critical threats,
their anomaly scores, lifecycle states, observation count, and remediation actions.
"""

import os
import json
import time
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import LOGS_DIR

LEDGER_FILE = LOGS_DIR / "threat_tracking_ledger.json"


class ThreatTrackingLedger:
    """Persistent tracking ledger for suspicious and critical threats."""

    def __init__(self):
        self._entries: Dict[str, Dict[str, Any]] = self._load_ledger()

    def _load_ledger(self) -> Dict[str, Dict[str, Any]]:
        """Load persistent ledger from disk."""
        if LEDGER_FILE.exists():
            try:
                with open(LEDGER_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
                    elif isinstance(data, list):
                        # Convert legacy list format to dict keyed by unique id
                        return {e.get("id", f"threat_{i}"): e for i, e in enumerate(data)}
            except Exception:
                return {}
        return {}

    def _save_ledger(self):
        """Save ledger to disk."""
        try:
            with open(LEDGER_FILE, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass

    def _generate_key(self, threat: Dict[str, Any]) -> str:
        """Generate deduplication key based on executable path or name + cmdline."""
        exe = (threat.get("exe") or "").lower().strip()
        if exe:
            return f"exe_{exe}"
        name = (threat.get("name") or "unknown").lower().strip()
        cmdline = (threat.get("cmdline") or "").lower().strip()
        return f"proc_{name}_{hash(cmdline)}"

    def record_threats(self, threats: List[Dict[str, Any]]) -> int:
        """
        Record and update active threats into the tracking ledger.
        Updates observation count, timestamps, severity, and maintains timeline.
        """
        now_iso = datetime.now().isoformat()
        now_display = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_count = 0

        # Mark previously active threats whose PIDs are dead as TERMINATED
        active_pids = set(psutil.pids())
        for key, entry in self._entries.items():
            if entry.get("status") == "ACTIVE":
                recorded_pid = entry.get("pid")
                if recorded_pid and recorded_pid not in active_pids:
                    entry["status"] = "INACTIVE"
                    entry["history"].append({
                        "timestamp": now_iso,
                        "time_display": now_display,
                        "action": "PROCESS_TERMINATED",
                        "details": f"Process (PID: {recorded_pid}) no longer present in process table."
                    })

        for t in threats:
            key = self._generate_key(t)
            score = t.get("threat_score", 0)
            severity = t.get("severity") or ("CRITICAL" if score >= 75 else ("SUSPICIOUS" if score >= 20 else "LOW"))
            pid = t.get("pid")
            name = t.get("name", "Unknown")
            exe = t.get("exe") or ""
            reasons = t.get("reasons", [])
            primary_cat = t.get("primary_category", "SUSPICIOUS THREAT")

            if key in self._entries:
                entry = self._entries[key]
                entry["last_seen"] = now_iso
                entry["last_seen_display"] = now_display
                entry["pid"] = pid
                entry["threat_score"] = max(entry.get("threat_score", 0), score)
                entry["severity"] = severity
                entry["primary_category"] = primary_cat
                entry["times_observed"] = entry.get("times_observed", 1) + 1
                entry["status"] = "ACTIVE"
                if reasons:
                    entry["reasons"] = reasons
            else:
                entry = {
                    "id": f"threat_{int(time.time() * 1000)}_{len(self._entries) + 1}",
                    "key": key,
                    "first_seen": now_iso,
                    "first_seen_display": now_display,
                    "last_seen": now_iso,
                    "last_seen_display": now_display,
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cmdline": t.get("cmdline", ""),
                    "threat_score": score,
                    "severity": severity,
                    "primary_category": primary_cat,
                    "reasons": reasons,
                    "status": "ACTIVE",
                    "times_observed": 1,
                    "history": [
                        {
                            "timestamp": now_iso,
                            "time_display": now_display,
                            "action": "FLAGGED",
                            "details": f"First detected with risk score {score} [{severity}] ({primary_cat})"
                        }
                    ]
                }
                self._entries[key] = entry
                updated_count += 1

        self._save_ledger()
        return updated_count

    def record_remediation(self, pid: Optional[int], exe_or_name: str, action: str, details: str):
        """Update threat status when remediated (killed, tree killed, quarantined)."""
        now_iso = datetime.now().isoformat()
        now_display = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        matched = False
        for key, entry in self._entries.items():
            if (pid and entry.get("pid") == pid) or (exe_or_name and (exe_or_name.lower() in (entry.get("exe") or "").lower() or exe_or_name.lower() == (entry.get("name") or "").lower())):
                entry["status"] = "ERADICATED" if "KILL" in action.upper() else ("QUARANTINED" if "QUARANTINE" in action.upper() else "RESOLVED")
                entry["history"].append({
                    "timestamp": now_iso,
                    "time_display": now_display,
                    "action": action,
                    "details": details
                })
                matched = True

        if matched:
            self._save_ledger()

    def get_ledger(self, limit: int = 200, severity: Optional[str] = None, status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve threat tracking ledger with flexible filters."""
        results = list(self._entries.values())

        if severity:
            sev_upper = severity.upper()
            results = [e for e in results if e.get("severity", "").upper() == sev_upper]

        if status:
            stat_upper = status.upper()
            results = [e for e in results if e.get("status", "").upper() == stat_upper]

        if search:
            q = search.lower()
            results = [
                e for e in results
                if q in (e.get("name") or "").lower()
                or q in (e.get("exe") or "").lower()
                or q in (e.get("primary_category") or "").lower()
                or str(e.get("pid", "")) == q
            ]

        # Sort by last seen descending
        results.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
        return results[:limit]

    def clear_ledger(self) -> Dict[str, Any]:
        """Clear the tracking ledger."""
        count = len(self._entries)
        self._entries.clear()
        self._save_ledger()
        return {"success": True, "cleared_count": count, "message": "Threat tracking ledger successfully cleared."}

