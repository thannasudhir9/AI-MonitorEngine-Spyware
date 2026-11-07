"""
AegisShield - Multi-Vector Threat Detection Engine
Combines signature matching, LOLRMM tracking, masquerading detection,
command-line heuristics, PE binary analysis, and network telemetry.
"""

import os
import psutil
from typing import Dict, List, Any, Optional

from .config import (
    CRITICAL_SYSTEM_PROCESSES, TYPOSQUAT_PATTERNS, SUSPICIOUS_PATHS,
    SCORE_CRITICAL, SCORE_HIGH, SCORE_MEDIUM, SCORE_LOW
)
from .signatures_db import (
    RMM_DATABASE, TROJAN_RAT_DATABASE, TUNNEL_DATABASE,
    SUSPICIOUS_CMDLINE_PATTERNS, SUSPICIOUS_PARENT_CHILD
)
from .pe_analyzer import analyze_binary
from .network_monitor import scan_network_connections, get_process_network_summary
from .policy_engine import PolicyEngine


class ThreatDetector:
    """Core Threat Detection and Risk Scoring Engine."""

    def __init__(self):
        self._parent_cache: Dict[int, str] = {}
        self.policy_engine = PolicyEngine()

    def scan_all_processes(self, detailed_pe: bool = False) -> List[Dict[str, Any]]:
        """
        Enumerate and evaluate all running processes on the system.
        Returns a list of analyzed process records with threat scoring.
        """
        results = []
        network_cache = scan_network_connections()

        # Build parent cache first
        self._parent_cache.clear()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                self._parent_cache[proc.info["pid"]] = (proc.info["name"] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Scan each process
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "username", "cpu_percent", "memory_info", "create_time"]):
            try:
                analyzed = self.evaluate_process(proc, network_cache=network_cache, detailed_pe=detailed_pe)
                if analyzed:
                    results.append(analyzed)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        # Sort: Highest threat score first, then by CPU%
        results.sort(key=lambda x: (x["threat_score"], x["cpu_percent"]), reverse=True)
        return results

    def evaluate_process(
        self,
        proc: psutil.Process,
        network_cache: Optional[Dict[int, List[Dict[str, Any]]]] = None,
        detailed_pe: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate a single process across all detection vectors.
        """
        try:
            pid = proc.pid
            name = (proc.name() or "").strip()
            lower_name = name.lower()
            
            # Executable path
            try:
                exe_path = proc.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = ""
            lower_exe = exe_path.lower()

            # Command line
            try:
                cmdline_list = proc.cmdline() or []
                cmdline = " ".join(cmdline_list)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = ""
            lower_cmdline = cmdline.lower()

            # Parent PID & Parent Name
            try:
                ppid = proc.ppid()
                parent_name = self._parent_cache.get(ppid, "")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                ppid = 0
                parent_name = ""

            # User & Memory
            try:
                username = proc.username() or "SYSTEM/Unknown"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = "Protected/Unknown"

            try:
                mem_bytes = proc.memory_info().rss
                memory_mb = round(mem_bytes / (1024 * 1024), 2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                memory_mb = 0.0

            try:
                cpu_percent = proc.cpu_percent(interval=None)
            except Exception:
                cpu_percent = 0.0

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        # Tracking detection metrics
        threat_score = 0
        reasons: List[Dict[str, Any]] = []
        categories = set()
        matched_signatures = []

        # ==============================================================
        # PASS 1: Masquerading & Typosquatting Detection
        # ==============================================================
        if lower_name in CRITICAL_SYSTEM_PROCESSES:
            sys_rule = CRITICAL_SYSTEM_PROCESSES[lower_name]
            expected = sys_rule.get("expected_path")
            if expected and exe_path and not lower_exe.startswith(expected):
                threat_score += 95
                categories.add("Trojan / Masquerading")
                reasons.append({
                    "vector": "Masquerading System Process",
                    "severity": "CRITICAL",
                    "score": 95,
                    "detail": f"Process '{name}' is mimicking a Windows system binary but running from illegitimate path: {exe_path}"
                })

        for typo in TYPOSQUAT_PATTERNS:
            if typo in lower_name and lower_name not in CRITICAL_SYSTEM_PROCESSES:
                threat_score += 85
                categories.add("Trojan / Typosquatting")
                reasons.append({
                    "vector": "Typosquatted Binary Name",
                    "severity": "CRITICAL",
                    "score": 85,
                    "detail": f"Process name '{name}' appears to be spoofing a core system binary ({typo})."
                })
                break

        # ==============================================================
        # PASS 2: Known Threat / RAT / RMM / Tunnel Signatures
        # ==============================================================
        if lower_name in TROJAN_RAT_DATABASE:
            threat_meta = TROJAN_RAT_DATABASE[lower_name]
            threat_score += threat_meta["score"]
            categories.add(threat_meta["category"])
            matched_signatures.append(threat_meta["name"])
            reasons.append({
                "vector": "Known Malware Signature",
                "severity": threat_meta["severity"],
                "score": threat_meta["score"],
                "detail": f"Matches verified malware threat signature: {threat_meta['name']}. {threat_meta['description']}"
            })

        if lower_name in RMM_DATABASE:
            rmm_meta = RMM_DATABASE[lower_name]
            threat_score += rmm_meta["score"]
            categories.add(rmm_meta["category"])
            matched_signatures.append(rmm_meta["name"])
            reasons.append({
                "vector": "Remote Desktop / RMM Tool",
                "severity": rmm_meta["severity"],
                "score": rmm_meta["score"],
                "detail": f"Active Remote Monitoring & Control software: {rmm_meta['name']}. {rmm_meta['description']}"
            })

        if lower_name in TUNNEL_DATABASE:
            tunnel_meta = TUNNEL_DATABASE[lower_name]
            threat_score += tunnel_meta["score"]
            categories.add(tunnel_meta["category"])
            matched_signatures.append(tunnel_meta["name"])
            reasons.append({
                "vector": "Reverse Proxy / Ingress Tunnel",
                "severity": tunnel_meta["severity"],
                "score": tunnel_meta["score"],
                "detail": f"Reverse ingress tunnel tool: {tunnel_meta['name']}. {tunnel_meta['description']}"
            })

        # ==============================================================
        # PASS 3: Suspicious Execution Paths Heuristics
        # ==============================================================
        if exe_path:
            for susp_path in SUSPICIOUS_PATHS:
                if susp_path in lower_exe:
                    threat_score += 40
                    categories.add("Suspicious Execution Path")
                    reasons.append({
                        "vector": "High-Risk Execution Directory",
                        "severity": "HIGH",
                        "score": 40,
                        "detail": f"Process is executing from a known malware drop zone ({susp_path})."
                    })
                    break

        # ==============================================================
        # PASS 4: Command Line & LOLBin Abuse Heuristics
        # ==============================================================
        if lower_cmdline:
            for cmd_rule in SUSPICIOUS_CMDLINE_PATTERNS:
                if cmd_rule["pattern"] in lower_cmdline:
                    threat_score += cmd_rule["score"]
                    categories.add(cmd_rule["category"])
                    reasons.append({
                        "vector": f"Command-Line Anomaly: {cmd_rule['name']}",
                        "severity": cmd_rule["severity"],
                        "score": cmd_rule["score"],
                        "detail": cmd_rule["description"]
                    })

        # ==============================================================
        # PASS 5: Suspicious Parent-Child Process Relationship
        # ==============================================================
        if parent_name:
            for tree_rule in SUSPICIOUS_PARENT_CHILD:
                if parent_name in tree_rule["parent"] and lower_name in tree_rule["children"]:
                    threat_score += tree_rule["score"]
                    categories.add(tree_rule["category"])
                    reasons.append({
                        "vector": f"Suspicious Process Ancestry: {tree_rule['name']}",
                        "severity": tree_rule["severity"],
                        "score": tree_rule["score"],
                        "detail": f"Parent process '{parent_name}' spawned anomalous shell '{name}'."
                    })

        # ==============================================================
        # PASS 6: Network Telemetry & Socket Inspection
        # ==============================================================
        network_summary = get_process_network_summary(pid, network_cache)
        if network_summary["network_threat_score"] > 0:
            threat_score += network_summary["network_threat_score"]
            categories.add("Suspicious Network Activity")
            for flag in network_summary["network_flags"]:
                reasons.append({
                    "vector": "Network Telemetry Alert",
                    "severity": "HIGH",
                    "score": 35,
                    "detail": flag
                })

        # ==============================================================
        # PASS 7: PE Binary Static Analysis (Entropy & APIs)
        # ==============================================================
        pe_meta = {}
        if detailed_pe and exe_path and os.path.isfile(exe_path):
            pe_meta = analyze_binary(exe_path)
            if pe_meta.get("is_packed"):
                threat_score += 25
                categories.add("Packed / Obfuscated Binary")
                reasons.append({
                    "vector": "High File Entropy (Packed)",
                    "severity": "MEDIUM",
                    "score": 25,
                    "detail": f"Binary exhibits high Shannon entropy ({pe_meta.get('file_entropy')}), indicating crypter/packer evasion."
                })

            if pe_meta.get("api_score", 0) > 0:
                api_score = pe_meta["api_score"]
                threat_score += api_score
                api_names = [a["api"] for a in pe_meta.get("matched_apis", [])]
                reasons.append({
                    "vector": "Suspicious API Imports",
                    "severity": "HIGH" if api_score >= 30 else "MEDIUM",
                    "score": api_score,
                    "detail": f"Binary imports dangerous APIs ({', '.join(api_names[:4])})."
                })

        # ==============================================================
        # PASS 8: Access Control & Allow/Block Policy Enforcement
        # ==============================================================
        is_blocked = self.policy_engine.is_process_blocked(name, exe_path)
        has_blocked_ip_conn = any(
            self.policy_engine.is_ip_blocked(c.get("remote_ip", ""))
            for c in network_summary.get("connections", [])
        )
        is_allowed = self.policy_engine.is_process_allowed(name, exe_path)

        if is_blocked:
            threat_score = 100
            categories.add("Blacklisted Policy Violation")
            reasons.insert(0, {
                "vector": "Policy Blacklist Enforcement",
                "severity": "CRITICAL",
                "score": 100,
                "detail": f"Process '{name}' is explicitly banned by administrator security policy."
            })

        if has_blocked_ip_conn:
            threat_score = 100
            categories.add("Banned IP Communication")
            reasons.insert(0, {
                "vector": "Blocked IP Connection",
                "severity": "CRITICAL",
                "score": 100,
                "detail": "Process has an active socket connected to an administrator-blocked remote IP."
            })

        # Normalize total Threat Score (0 - 100)
        final_score = min(threat_score, 100)

        # Allowlist Override: If explicitly whitelisted and not blacklisted
        if is_allowed and not is_blocked and not has_blocked_ip_conn:
            final_score = 0
            reasons = [{
                "vector": "Policy Allowlist",
                "severity": "SAFE",
                "score": 0,
                "detail": "Process is explicitly trusted and whitelisted by user security policy."
            }]

        # Determine Severity Level
        if final_score >= SCORE_CRITICAL:
            severity = "CRITICAL"
        elif final_score >= SCORE_HIGH:
            severity = "HIGH"
        elif final_score >= SCORE_MEDIUM:
            severity = "MEDIUM"
        elif final_score >= SCORE_LOW:
            severity = "LOW"
        else:
            severity = "SAFE"

        # Determine Primary Category Label
        if is_allowed and final_score == 0:
            primary_cat = "TRUSTED WHITELIST"
        elif is_blocked or has_blocked_ip_conn:
            primary_cat = "BLOCKED BY POLICY"
        elif "Trojan / RAT" in categories or "Trojan / Masquerading" in categories or "Trojan / Typosquatting" in categories:
            primary_cat = "TROJAN"
        elif "Spyware / Infostealer" in categories:
            primary_cat = "SPYWARE"
        elif "Remote Desktop / RMM" in categories or "Remote Desktop / VNC" in categories:
            primary_cat = "REMOTE CONTROL"
        elif "CryptoMiner" in categories or "CryptoMiner / Trojan" in categories:
            primary_cat = "CRYPTOMINER"
        elif "Reverse Tunnel / Proxy" in categories:
            primary_cat = "REVERSE TUNNEL"
        elif final_score >= SCORE_MEDIUM:
            primary_cat = "SUSPICIOUS PROCESS"
        else:
            primary_cat = "NORMAL PROCESS"

        # Is process protected from termination?
        is_protected = False
        if lower_name in CRITICAL_SYSTEM_PROCESSES:
            sys_info = CRITICAL_SYSTEM_PROCESSES[lower_name]
            if not sys_info.get("allow_kill", True):
                # Only protected if running from expected legitimate system location
                expected = sys_info.get("expected_path")
                if not expected or lower_exe.startswith(expected):
                    is_protected = True

        return {
            "pid": pid,
            "name": name,
            "exe": exe_path,
            "cmdline": cmdline,
            "ppid": ppid,
            "parent_name": parent_name,
            "username": username,
            "memory_mb": memory_mb,
            "cpu_percent": cpu_percent,
            "threat_score": final_score,
            "severity": severity,
            "primary_category": primary_cat,
            "categories": list(categories),
            "matched_signatures": matched_signatures,
            "reasons": reasons,
            "is_threat": final_score >= SCORE_MEDIUM,
            "is_protected": is_protected,
            "network": network_summary,
            "pe_info": pe_meta
        }

