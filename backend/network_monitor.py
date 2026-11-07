"""
AegisShield - Network Socket & Remote Connection Monitor
Maps active TCP/UDP connections to processes, inspects listening ports,
and detects remote desktop sessions and unauthorized RAT beacons.
"""

from typing import Dict, List, Any, Optional
import psutil
from .config import RMM_PORTS

# Common Private Subnets
PRIVATE_IP_PREFIXES = ("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", 
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", 
                       "172.30.", "172.31.", "192.168.", "0.0.0.0", "::1", "::")


def is_public_ip(ip: str) -> bool:
    """Check if an IP address belongs to the public internet."""
    if not ip:
        return False
    return not any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def scan_network_connections() -> Dict[int, List[Dict[str, Any]]]:
    """
    Enumerate all network connections and group them by PID.
    Flags remote desktop ports, C2 beaconing, and established public sockets.
    """
    connections_by_pid: Dict[int, List[Dict[str, Any]]] = {}

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except Exception:
        # Gracefully handle environments where GetExtendedTcpTable is restricted
        return connections_by_pid

    for conn in raw_conns:
        pid = conn.pid
        if not pid:
            continue

        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        remote_ip = conn.raddr.ip if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else 0
        local_port = conn.laddr.port if conn.laddr else 0
        status = conn.status

        # Evaluate risk flags
        is_rmm_listening = local_port in RMM_PORTS
        is_rmm_connected = remote_port in RMM_PORTS
        is_c2_suspicious = remote_port in (1177, 1604, 2404, 4444, 4782, 5555, 6606, 7707, 8808, 3333)
        is_external = is_public_ip(remote_ip)

        conn_record = {
            "type": "TCP" if conn.type == 1 else "UDP",
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": status,
            "is_external": is_external,
            "is_rmm_port": is_rmm_listening or is_rmm_connected,
            "rmm_service_name": RMM_PORTS.get(local_port) or RMM_PORTS.get(remote_port),
            "is_suspicious_c2": is_c2_suspicious
        }

        if pid not in connections_by_pid:
            connections_by_pid[pid] = []
        connections_by_pid[pid].append(conn_record)

    return connections_by_pid


def get_process_network_summary(pid: int, conns_cache: Optional[Dict[int, List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
    """
    Analyze network posture for a single PID.
    Returns port counts, remote IPs, and threat score adjustments.
    """
    if conns_cache is None:
        conns_cache = scan_network_connections()

    proc_conns = conns_cache.get(pid, [])
    has_listening = any(c["status"] == "LISTEN" for c in proc_conns)
    has_established = any(c["status"] == "ESTABLISHED" for c in proc_conns)
    has_rmm_port = any(c["is_rmm_port"] for c in proc_conns)
    has_suspicious_c2 = any(c["is_suspicious_c2"] for c in proc_conns)
    has_public_outbound = any(c["is_external"] and c["status"] == "ESTABLISHED" for c in proc_conns)

    network_score = 0
    flags = []

    if has_suspicious_c2:
        network_score += 50
        flags.append("Connected to known malware C2 / Trojan / Mining port")

    if has_rmm_port:
        network_score += 35
        flags.append("Active Remote Desktop / RMM control port socket detected")

    if has_public_outbound and has_listening:
        network_score += 15
        flags.append("Simultaneous listening server and public outbound connection")

    return {
        "connections": proc_conns,
        "total_connections": len(proc_conns),
        "has_listening": has_listening,
        "has_established": has_established,
        "has_rmm_port": has_rmm_port,
        "has_suspicious_c2": has_suspicious_c2,
        "network_threat_score": min(network_score, 60),
        "network_flags": flags
    }

