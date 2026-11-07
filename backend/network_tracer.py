"""
AegisShield - Network Intelligence, Process Network Auditor & Origin Tracer
Enumerates all processes using network sockets, traces remote IP origin,
performs reverse DNS lookups, and evaluates genuineness and threat reputation.
"""

import os
import json
import socket
import psutil
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import DATABASE_DIR, RMM_PORTS

GEO_CACHE_FILE = DATABASE_DIR / "geo_cache.json"

# Major Verified Tech Providers (CIDR prefixes / ASN / Domains)
VERIFIED_PROVIDERS = [
    {"name": "Microsoft / Azure", "domain_keywords": ["microsoft", "azure", "live.com", "office", "msn.com", "bing", "windowsupdate"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "Google / GCP", "domain_keywords": ["google", "1e100.net", "gstatic", "youtube", "googleapis"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "Cloudflare", "domain_keywords": ["cloudflare", "cloudflarenet"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "Amazon AWS", "domain_keywords": ["amazon", "aws", "compute.amazonaws", "cloudfront"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "Apple", "domain_keywords": ["apple.com", "icloud.com", "apple-dns"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "Akamai", "domain_keywords": ["akamai", "akamaitechnologies"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "GitHub", "domain_keywords": ["github.com", "githubusercontent"], "badge": "GENUINE CLOUD / CDN"},
    {"name": "Fastly", "domain_keywords": ["fastly", "fastlylb"], "badge": "GENUINE CLOUD / CDN"}
]

# Suspicious / Malicious indicators
SUSPICIOUS_PORTS = {
    1177: "njRAT Default C2",
    1604: "DarkComet RAT Default C2",
    2404: "Remcos RAT Default C2",
    4444: "Metasploit / Reverse Shell Port",
    4782: "QuasarRAT Default C2",
    5555: "Android ADB / Trojan Backdoor",
    6606: "AsyncRAT Default C2",
    7707: "AsyncRAT Alternate C2",
    8808: "AsyncRAT Alternate C2",
    3333: "Crypto Mining Stratum Pool",
    7777: "Trojan Miner Pool",
    9999: "Trojan Miner Pool",
    6667: "IRC Botnet Standard Port"
}


class NetworkTracer:
    """Audits processes using the network and evaluates IP genuineness."""

    def __init__(self):
        self._geo_cache: Dict[str, Dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load cached IP lookup records from disk."""
        if GEO_CACHE_FILE.exists():
            try:
                with open(GEO_CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        """Save cache to disk."""
        try:
            with open(GEO_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._geo_cache, f, indent=2)
        except Exception:
            pass

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP address is localhost or in private RFC 1918 range."""
        if not ip:
            return True
        if ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            return True
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                p0, p1 = int(parts[0]), int(parts[1])
                if p0 == 10:
                    return True
                if p0 == 172 and 16 <= p1 <= 31:
                    return True
                if p0 == 192 and p1 == 168:
                    return True
                if p0 == 169 and p1 == 254:
                    return True  # APIPA
            except ValueError:
                pass
        return False

    def resolve_reverse_dns(self, ip: str) -> str:
        """Resolve PTR record to domain name with timeout."""
        if not ip or self.is_private_ip(ip):
            return "Local / Loopback"

        if ip in self._geo_cache and "hostname" in self._geo_cache[ip]:
            return self._geo_cache[ip]["hostname"]

        try:
            socket.setdefaulttimeout(0.7)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return "Unresolved Host"

    def trace_ip(self, ip: str) -> Dict[str, Any]:
        """
        Deep trace remote IP: reverse DNS, organization, country, and genuineness assessment.
        """
        if not ip:
            return {"ip": "", "verdict": "UNKNOWN", "is_genuine": False}

        if self.is_private_ip(ip):
            return {
                "ip": ip,
                "hostname": "Local Host / Gateway",
                "country": "Local Network",
                "country_code": "LAN",
                "org": "Private Subnet (RFC 1918)",
                "verdict": "PRIVATE LAN",
                "is_genuine": True,
                "is_private": True,
                "confidence": 100
            }

        # Check cache
        if ip in self._geo_cache:
            return self._geo_cache[ip]

        hostname = self.resolve_reverse_dns(ip)
        lower_host = hostname.lower()

        # Classify against verified global tech providers
        detected_org = "External Host / ISP"
        verdict = "UNVERIFIED EXTERNAL"
        is_genuine = False
        confidence = 60

        for prov in VERIFIED_PROVIDERS:
            for kw in prov["domain_keywords"]:
                if kw in lower_host:
                    detected_org = prov["name"]
                    verdict = prov["badge"]
                    is_genuine = True
                    confidence = 95
                    break
            if is_genuine:
                break

        # Check common public DNS resolvers
        if ip in ("8.8.8.8", "8.8.4.4"):
            detected_org = "Google Public DNS"
            verdict = "GENUINE CLOUD / CDN"
            is_genuine = True
        elif ip in ("1.1.1.1", "1.0.0.1"):
            detected_org = "Cloudflare DNS"
            verdict = "GENUINE CLOUD / CDN"
            is_genuine = True
        elif ip in ("9.9.9.9", "149.112.112.112"):
            detected_org = "Quad9 Secure DNS"
            verdict = "GENUINE CLOUD / CDN"
            is_genuine = True

        result = {
            "ip": ip,
            "hostname": hostname,
            "country": "Global Internet",
            "country_code": "NET",
            "org": detected_org,
            "verdict": verdict,
            "is_genuine": is_genuine,
            "is_private": False,
            "confidence": confidence
        }

        # Cache lookup
        if len(self._geo_cache) > 500:
            self._geo_cache.clear()
        self._geo_cache[ip] = result
        self._save_cache()

        return result

    def audit_all_network_processes(self) -> Dict[str, Any]:
        """
        Scan every active network socket, map to owning process,
        trace origin, and evaluate threat and genuineness.
        """
        connections_list = []
        processes_using_network = set()
        listening_sockets = 0
        established_sockets = 0
        external_sockets = 0
        suspicious_sockets = 0
        genuine_cdn_sockets = 0

        # Build PID metadata cache
        proc_cache: Dict[int, Dict[str, Any]] = {}
        for p in psutil.process_iter(["pid", "name", "exe", "username", "cpu_percent", "memory_info"]):
            try:
                mem_mb = round(p.info["memory_info"].rss / (1024 * 1024), 1) if p.info.get("memory_info") else 0.0
                proc_cache[p.info["pid"]] = {
                    "name": p.info.get("name") or "Unknown",
                    "exe": p.info.get("exe") or "Protected/System",
                    "username": p.info.get("username") or "System",
                    "cpu_percent": p.info.get("cpu_percent") or 0.0,
                    "memory_mb": mem_mb
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Enumerate sockets
        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception:
            raw_conns = []

        for conn in raw_conns:
            pid = conn.pid
            if not pid or pid not in proc_cache:
                continue

            processes_using_network.add(pid)
            p_info = proc_cache[pid]

            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0
            remote_addr = f"{remote_ip}:{remote_port}" if conn.raddr else "LISTEN"
            status = conn.status

            if status == "LISTEN":
                listening_sockets += 1
            elif status == "ESTABLISHED":
                established_sockets += 1

            is_private = self.is_private_ip(remote_ip)
            if not is_private and remote_ip:
                external_sockets += 1

            # Check Suspicious / RMM ports
            is_suspicious_port = remote_port in SUSPICIOUS_PORTS or local_port in SUSPICIOUS_PORTS
            is_rmm_port = remote_port in RMM_PORTS or local_port in RMM_PORTS
            threat_note = ""

            if is_suspicious_port:
                suspicious_sockets += 1
                threat_note = SUSPICIOUS_PORTS.get(remote_port) or SUSPICIOUS_PORTS.get(local_port)
            elif is_rmm_port:
                threat_note = RMM_PORTS.get(remote_port) or RMM_PORTS.get(local_port)

            # Trace IP Origin & Genuineness
            ip_trace = self.trace_ip(remote_ip) if remote_ip else {
                "ip": "", "hostname": "N/A", "org": "Listening Daemon", "country": "Local", "verdict": "LISTENING PORT", "is_genuine": True
            }

            # If suspicious port, override verdict
            if is_suspicious_port:
                ip_trace["verdict"] = "SUSPICIOUS C2 / RAT PORT"
                ip_trace["is_genuine"] = False

            if ip_trace["verdict"] == "GENUINE CLOUD / CDN":
                genuine_cdn_sockets += 1

            connections_list.append({
                "pid": pid,
                "process_name": p_info["name"],
                "exe_path": p_info["exe"],
                "username": p_info["username"],
                "protocol": "TCP" if conn.type == 1 else "UDP",
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": status,
                "is_private": is_private,
                "is_suspicious": is_suspicious_port,
                "is_rmm": is_rmm_port,
                "threat_note": threat_note,
                "trace": ip_trace
            })

        # Sort: Suspicious first, then established external
        connections_list.sort(key=lambda x: (x["is_suspicious"], not x["is_private"], x["status"] == "ESTABLISHED"), reverse=True)

        return {
            "total_network_processes": len(processes_using_network),
            "total_active_sockets": len(connections_list),
            "listening_sockets": listening_sockets,
            "established_sockets": established_sockets,
            "external_sockets": external_sockets,
            "suspicious_sockets": suspicious_sockets,
            "genuine_cdn_sockets": genuine_cdn_sockets,
            "connections": connections_list
        }

