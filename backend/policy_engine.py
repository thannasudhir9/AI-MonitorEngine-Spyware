"""
AegisShield - Access Control & Allow/Block Policy Engine
Manages whitelisted (trusted) and blacklisted (banned) processes, hashes,
and remote IP addresses with optional Windows Firewall integration.
"""

import os
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import DATABASE_DIR

RULES_FILE = DATABASE_DIR / "policy_rules.json"


class PolicyEngine:
    """Manages system allowlist and blocklist security policies."""

    def __init__(self):
        self._rules = self._load_rules()

    def _load_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load persistent rules from database."""
        default_rules = {
            "allowed_processes": [
                {
                    "id": "rule_allow_default_1",
                    "type": "name",
                    "value": "explorer.exe",
                    "comment": "Default Windows Shell",
                    "created_at": "2026-11-07T00:00:00"
                }
            ],
            "blocked_processes": [
                {
                    "id": "rule_block_default_1",
                    "type": "name",
                    "value": "wannacry.exe",
                    "comment": "Known Ransomware",
                    "created_at": "2026-11-07T00:00:00"
                }
            ],
            "blocked_ips": [
                {
                    "id": "rule_ip_default_1",
                    "type": "ip",
                    "value": "198.51.100.1",
                    "comment": "Example Blocked C2 IP",
                    "created_at": "2026-11-07T00:00:00"
                }
            ],
            "allowed_ips": []
        }

        if RULES_FILE.exists():
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k in default_rules:
                        if k not in data:
                            data[k] = default_rules[k]
                    return data
            except Exception:
                return default_rules
        return default_rules

    def _save_rules(self):
        """Save rules to disk."""
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(self._rules, f, indent=2)
        except Exception:
            pass

    def get_all_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Retrieve all active policy rules."""
        return self._rules

    def is_process_allowed(self, name: str, exe_path: str = "", sha256: str = "") -> bool:
        """Check if a process is explicitly whitelisted."""
        name_lower = (name or "").lower()
        exe_lower = (exe_path or "").lower()
        sha_lower = (sha256 or "").lower()

        for rule in self._rules.get("allowed_processes", []):
            val = rule["value"].lower().strip()
            rule_type = rule.get("type", "name")
            if rule_type == "name" and (val == name_lower or name_lower.endswith(val)):
                return True
            elif rule_type == "path" and (val == exe_lower or exe_lower.startswith(val)):
                return True
            elif rule_type == "hash" and val == sha_lower and len(val) >= 32:
                return True
        return False

    def is_process_blocked(self, name: str, exe_path: str = "", sha256: str = "") -> bool:
        """Check if a process is explicitly blacklisted."""
        name_lower = (name or "").lower()
        exe_lower = (exe_path or "").lower()
        sha_lower = (sha256 or "").lower()

        for rule in self._rules.get("blocked_processes", []):
            val = rule["value"].lower().strip()
            rule_type = rule.get("type", "name")
            if rule_type == "name" and (val == name_lower or name_lower.endswith(val)):
                return True
            elif rule_type == "path" and (val == exe_lower or exe_lower.startswith(val)):
                return True
            elif rule_type == "hash" and val == sha_lower and len(val) >= 32:
                return True
        return False

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if a remote IP address is banned."""
        if not ip:
            return False
        ip_clean = ip.strip()
        for rule in self._rules.get("blocked_ips", []):
            if rule["value"].strip() == ip_clean:
                return True
        return False

    def add_allow_rule(self, rule_type: str, value: str, comment: str = "") -> Dict[str, Any]:
        """Add an entry to the allowlist."""
        rule_id = f"allow_{int(time.time() * 1000)}"
        new_rule = {
            "id": rule_id,
            "type": rule_type,  # 'name', 'path', or 'hash'
            "value": value.strip(),
            "comment": comment or "User Whitelisted",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
        self._rules["allowed_processes"].append(new_rule)
        self._save_rules()
        return {"success": True, "message": f"Added '{value}' to allowlist.", "rule": new_rule}

    def add_block_rule(self, rule_type: str, value: str, comment: str = "") -> Dict[str, Any]:
        """Add an entry to the process blocklist."""
        rule_id = f"block_{int(time.time() * 1000)}"
        new_rule = {
            "id": rule_id,
            "type": rule_type,
            "value": value.strip(),
            "comment": comment or "User Blacklisted",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
        self._rules["blocked_processes"].append(new_rule)
        self._save_rules()
        return {"success": True, "message": f"Added '{value}' to blocklist.", "rule": new_rule}

    def add_ip_block_rule(self, ip: str, comment: str = "", apply_firewall: bool = True) -> Dict[str, Any]:
        """Block a remote IP address and optionally configure Windows Firewall rule."""
        ip = ip.strip()
        rule_id = f"ip_block_{int(time.time() * 1000)}"
        new_rule = {
            "id": rule_id,
            "type": "ip",
            "value": ip,
            "comment": comment or "Blocked Remote IP",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
        self._rules["blocked_ips"].append(new_rule)
        self._save_rules()

        firewall_msg = "Firewall rule skipped."
        if apply_firewall and os.name == 'nt':
            try:
                # Add outbound block rule via netsh
                rule_name = f"AegisShield_Block_{ip}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}"
                ]
                subprocess.run(cmd, capture_output=True, timeout=4)
                firewall_msg = f"Windows Firewall outbound block rule added for {ip}."
            except Exception as e:
                firewall_msg = f"Firewall command notice: {str(e)}"

        return {
            "success": True,
            "message": f"Banned IP {ip}. {firewall_msg}",
            "rule": new_rule
        }

    def delete_rule(self, rule_id: str) -> Dict[str, Any]:
        """Remove a rule by ID across all categories."""
        found = False
        removed_rule = None
        for cat in ["allowed_processes", "blocked_processes", "blocked_ips", "allowed_ips"]:
            new_list = []
            for r in self._rules.get(cat, []):
                if r["id"] == rule_id:
                    found = True
                    removed_rule = r
                else:
                    new_list.append(r)
            self._rules[cat] = new_list

        if found:
            self._save_rules()
            # If it was an IP block rule on Windows, try removing firewall rule
            if removed_rule and removed_rule.get("type") == "ip" and os.name == 'nt':
                try:
                    ip = removed_rule["value"]
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=AegisShield_Block_{ip}"],
                        capture_output=True, timeout=4
                    )
                except Exception:
                    pass
            return {"success": True, "message": f"Rule '{rule_id}' removed successfully."}
        return {"success": False, "message": "Rule not found."}

