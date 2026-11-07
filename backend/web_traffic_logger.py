"""
AegisShield - Web Traffic Logger
Thread-safe persistent recording of every website browsed, timestamps,
ad-blocking decisions, and data transfer volumes.
"""

import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import DATABASE_DIR

TRAFFIC_LOG_FILE = DATABASE_DIR / "web_traffic_logs.json"


class WebTrafficLogger:
    """Records and queries all intercepted HTTP/HTTPS web traffic."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(WebTrafficLogger, cls).__new__(cls)
                cls._instance._init_logger()
            return cls._instance

    def _init_logger(self):
        self.logs: List[Dict[str, Any]] = self._load_logs()
        self._flush_lock = threading.Lock()
        self._pending_writes = 0

    def _load_logs(self) -> List[Dict[str, Any]]:
        """Load traffic logs from disk."""
        if TRAFFIC_LOG_FILE.exists():
            try:
                with open(TRAFFIC_LOG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_logs(self):
        """Persist logs to disk."""
        try:
            with open(TRAFFIC_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.logs[:3000], f, indent=2)  # Keep latest 3000 requests
        except Exception:
            pass

    def log_request(
        self,
        domain: str,
        method: str,
        port: int,
        is_blocked: bool,
        category: str,
        reason: str,
        bytes_transferred: int = 0,
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """Record an intercepted web browsing event."""
        now = datetime.now()
        entry = {
            "id": f"req_{int(time.time() * 1000)}_{len(self.logs)}",
            "timestamp": now.isoformat(),
            "date_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain.lower().split(":")[0].strip(),
            "method": method.upper(),
            "port": port,
            "status": "BLOCKED" if is_blocked else "ALLOWED",
            "is_blocked": is_blocked,
            "category": category,
            "reason": reason,
            "bytes_transferred": bytes_transferred,
            "client_ip": client_ip
        }

        with self._flush_lock:
            self.logs.insert(0, entry)
            if len(self.logs) > 3000:
                self.logs = self.logs[:3000]
            self._pending_writes += 1

            # Flush to disk every 5 requests or on blocked ads
            if is_blocked or self._pending_writes >= 5:
                self._save_logs()
                self._pending_writes = 0

        return entry

    def get_logs(
        self,
        limit: int = 150,
        status_filter: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve filtered traffic history."""
        with self._flush_lock:
            results = list(self.logs)

        if status_filter:
            sf = status_filter.upper()
            if sf in ("BLOCKED", "ALLOWED"):
                results = [r for r in results if r["status"] == sf]

        if search_query:
            q = search_query.lower().strip()
            results = [
                r for r in results
                if q in r["domain"] or q in r["category"].lower() or q in r["date_time"]
            ]

        return results[:limit]

    def clear_logs(self) -> Dict[str, Any]:
        """Clear all historical web browsing logs."""
        with self._flush_lock:
            self.logs.clear()
            self._save_logs()
        return {"success": True, "message": "Web browsing logs successfully cleared."}

