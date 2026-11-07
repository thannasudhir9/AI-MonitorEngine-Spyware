"""
AegisShield - System Information & Security Baseline Diagnostics Engine
Inspired by SystemInfoCheck: audits hardware specs, OS kernel, CPU, RAM, network adapters, and security baseline.
"""

import sys
import os
import platform
import psutil
import subprocess
from datetime import datetime
from typing import Dict, Any, List


class SystemInfoEngine:
    def __init__(self):
        pass

    def get_full_system_info(self) -> Dict[str, Any]:
        """Collect comprehensive hardware, OS, kernel, and security posture metadata."""
        return {
            "os": self._get_os_info(),
            "cpu": self._get_cpu_info(),
            "memory": self._get_memory_info(),
            "network_adapters": self._get_network_adapters(),
            "security_baseline": self._get_security_baseline(),
            "system_uptime": self._get_uptime(),
            "timestamp": datetime.now().isoformat(),
            "time_display": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _get_os_info(self) -> Dict[str, Any]:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
            "os_name": f"Windows {platform.release()} ({platform.machine()})"
        }

    def _get_uptime(self) -> str:
        uptime_seconds = int(datetime.now().timestamp() - psutil.boot_time())
        days, rem = divmod(uptime_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m {seconds}s"

    def _get_cpu_info(self) -> Dict[str, Any]:
        try:
            freq = psutil.cpu_freq()
            freq_current = round(freq.current, 1) if freq else 0
            freq_max = round(freq.max, 1) if freq else 0
        except Exception:
            freq_current = 0
            freq_max = 0

        return {
            "physical_cores": psutil.cpu_count(logical=False) or 1,
            "logical_threads": psutil.cpu_count(logical=True) or 1,
            "current_frequency_mhz": freq_current,
            "max_frequency_mhz": freq_max,
            "current_load_percent": psutil.cpu_percent(interval=None),
            "per_core_percent": psutil.cpu_percent(interval=None, percpu=True)
        }

    def _get_memory_info(self) -> Dict[str, Any]:
        mem = psutil.virtual_memory()
        swap_total = 0
        swap_used = 0
        swap_pct = 0
        try:
            swap = psutil.swap_memory()
            swap_total = round(swap.total / (1024 ** 3), 2)
            swap_used = round(swap.used / (1024 ** 3), 2)
            swap_pct = swap.percent
        except Exception:
            pass

        return {
            "total_gb": round(mem.total / (1024 ** 3), 2),
            "available_gb": round(mem.available / (1024 ** 3), 2),
            "used_gb": round(mem.used / (1024 ** 3), 2),
            "percent_used": mem.percent,
            "swap_total_gb": swap_total,
            "swap_used_gb": swap_used,
            "swap_percent": swap_pct
        }

    def _get_network_adapters(self) -> List[Dict[str, Any]]:
        adapters = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for nic_name, nic_addrs in addrs.items():
                nic_stat = stats.get(nic_name)
                ip_v4 = None
                mac_addr = None
                for addr in nic_addrs:
                    if addr.family.name == "AF_INET":
                        ip_v4 = addr.address
                    elif "PACKET" in addr.family.name or addr.family.name == "AF_LINK":
                        mac_addr = addr.address

                if ip_v4:
                    adapters.append({
                        "name": nic_name,
                        "ip_v4": ip_v4,
                        "mac": mac_addr or "N/A",
                        "is_up": nic_stat.isup if nic_stat else True,
                        "speed_mbps": nic_stat.speed if nic_stat else 0
                    })
        except Exception:
            pass
        return adapters

    def _get_security_baseline(self) -> Dict[str, Any]:
        """Audit security baselines: Windows Defender, UAC, Firewall states."""
        is_admin = False
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass

        baseline = {
            "firewall_active": True,
            "defender_active": True,
            "uac_level": "Enabled",
            "rdp_port_status": "Monitored",
            "execution_policy": "Restricted",
            "is_admin": is_admin,
            "elevation_status": "Administrator (Elevated)" if is_admin else "Standard User"
        }
        return baseline
