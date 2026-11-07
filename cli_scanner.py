"""
AegisShield CLI - Terminal Threat Hunter, Process Eradicator & Network Origin Tracer
Usage:
    python cli_scanner.py --scan
    python cli_scanner.py --scan --kill
    python cli_scanner.py --network
    python cli_scanner.py --rmm
    python cli_scanner.py --allow <process_name>
    python cli_scanner.py --block <process_name_or_ip>
    python cli_scanner.py --rules
    python cli_scanner.py --email-report <recipient_email>
    python cli_scanner.py --kill-pid <PID>
    python cli_scanner.py --kill-tree <PID>
"""

import sys
import argparse
from datetime import datetime

from backend.detector import ThreatDetector
from backend.remediator import ThreatRemediator
from backend.persistence_hunter import get_all_persistence_entries
from backend.policy_engine import PolicyEngine
from backend.network_tracer import NetworkTracer
from backend.email_notifier import EmailNotifier


# ANSI Color formatting
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    print(f"""{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║       AEGISSHIELD EDR - ADVANCED PROCESS THREAT HUNTER       ║
    ║   Spyware • Antivirus • Remote Desktop • Trojan Eradicator   ║
    ║          Access Control • Network Tracer • Email Alerts      ║
    ╚══════════════════════════════════════════════════════════════╝{RESET}
    """)


def run_cli_scan(kill_mode: bool = False, min_score: int = 50):
    detector = ThreatDetector()
    remediator = ThreatRemediator()

    print(f"{CYAN}[*] Initiating deep system process scan...{RESET}")
    start_time = datetime.now()
    procs = detector.scan_all_processes(detailed_pe=True)
    duration = (datetime.now() - start_time).total_seconds()

    threats = [p for p in procs if p.get("is_threat")]
    rmm_tools = [p for p in procs if "REMOTE CONTROL" in p.get("primary_category", "")]

    print(f"{GREEN}[+] Scan Complete in {duration:.2f}s | Analyzed {len(procs)} processes | Found {len(threats)} threats | {len(rmm_tools)} RMM tools{RESET}\n")

    if not threats:
        print(f"{GREEN}[✓] System Clean: No high-risk threats detected.{RESET}")
    else:
        print(f"{RED}{BOLD}[!] DETECTED THREATS:{RESET}")
        print("-" * 80)
        for t in threats:
            score = t.get("threat_score")
            color = RED if score >= 80 else (YELLOW if score >= 50 else CYAN)
            print(f"{color}{BOLD}[PID {t['pid']}] {t['name']}{RESET} | Score: {color}{score}/100{RESET} | Category: {t['primary_category']}")
            print(f"    Path: {t['exe'] or 'Protected/In-Memory'}")
            print(f"    User: {t['username']} | RAM: {t['memory_mb']} MB | CPU: {t['cpu_percent']}%")
            for r in t["reasons"]:
                print(f"    {RED}• [{r['vector']}] {r['detail']}{RESET}")
            print("-" * 80)

        if kill_mode:
            print(f"\n{RED}[!] KILL MODE ACTIVE: Eradicating detected threats with score >= {min_score}...{RESET}")
            res = remediator.kill_all_threats(threats, min_score=min_score)
            print(f"{GREEN}[✓] {res['message']}{RESET}")
            for k in res["killed"]:
                print(f"    {GREEN}Killed PID {k['pid']}: {k['name']} ({k['category']}){RESET}")
            for e in res["errors"]:
                print(f"    {RED}Failed PID {e['pid']}: {e['name']} - {e['error']}{RESET}")


def run_network_audit():
    tracer = NetworkTracer()
    print(f"{CYAN}[*] Auditing active processes using network sockets & tracing origins...{RESET}")
    res = tracer.audit_all_network_processes()

    print(f"{GREEN}[+] Network Audit Complete:{RESET}")
    print(f"    Processes on Network: {res['total_network_processes']}")
    print(f"    Total Active Sockets: {res['total_active_sockets']}")
    print(f"    Outbound Sockets:     {res['established_sockets']}")
    print(f"    Listening Ports:      {res['listening_sockets']}")
    print(f"    Verified CDNs:        {res['genuine_cdn_sockets']}")
    print(f"    Suspicious Sockets:   {res['suspicious_sockets']}\n")

    conns = res["connections"]
    if not conns:
        print(f"{DIM}No active network connections found.{RESET}")
        return

    print(f"{BOLD}{'PROCESS (PID)':<22} {'LOCAL SOCKET':<20} {'REMOTE ENDPOINT':<22} {'GENUINENESS / VERDICT':<25} {'STATE'}{RESET}")
    print("-" * 100)
    for c in conns[:40]:
        verdict = c["trace"]["verdict"]
        color = GREEN if c["trace"]["is_genuine"] else (RED if c["is_suspicious"] else YELLOW)
        p_str = f"{c['process_name']} ({c['pid']})"
        print(f"{p_str:<22} {c['local_addr']:<20} {c['remote_addr']:<22} {color}{verdict:<25}{RESET} {c['status']}")
        if c.get("threat_note"):
            print(f"    {RED}↳ Alert: {c['threat_note']}{RESET}")
        if c["trace"]["hostname"] and c["trace"]["hostname"] != "Unresolved Host":
            print(f"    {DIM}↳ Hostname: {c['trace']['hostname']} ({c['trace']['org']}){RESET}")


def run_rmm_check():
    detector = ThreatDetector()
    print(f"{CYAN}[*] Scanning for active Remote Desktop, VNC, RMM & RAT software...{RESET}")
    procs = detector.scan_all_processes(detailed_pe=False)
    rmm_procs = [
        p for p in procs
        if "REMOTE CONTROL" in p.get("primary_category", "")
        or any("Remote Desktop" in r.get("vector", "") for r in p.get("reasons", []))
    ]

    if not rmm_procs:
        print(f"{GREEN}[✓] No active Remote Desktop or RMM tools detected.{RESET}")
    else:
        print(f"{YELLOW}{BOLD}[!] ACTIVE REMOTE DESKTOP / RMM SESSIONS:{RESET}")
        for r in rmm_procs:
            print(f"    PID {r['pid']}: {BOLD}{r['name']}{RESET} - {r['exe']}")
            conns = r.get("network", {}).get("connections", [])
            for c in conns:
                print(f"        {c['type']} {c['local_addr']} -> {c['remote_addr']} ({c['status']})")


def run_policy_rules():
    policy = PolicyEngine()
    rules = policy.get_all_rules()
    print(f"{CYAN}[*] Active Access Control & Firewall Policy Rules:{RESET}\n")

    print(f"{GREEN}{BOLD}Allowed Processes (Whitelist):{RESET}")
    for a in rules.get("allowed_processes", []):
        print(f"  • {BOLD}{a['value']}{RESET} [{a['type']}] - {a.get('comment')}")

    print(f"\n{RED}{BOLD}Blocked Processes (Blacklist):{RESET}")
    for b in rules.get("blocked_processes", []):
        print(f"  • {BOLD}{b['value']}{RESET} [{b['type']}] - {b.get('comment')}")

    print(f"\n{YELLOW}{BOLD}Banned IP Addresses (Firewall Block):{RESET}")
    for ip in rules.get("blocked_ips", []):
        print(f"  • {BOLD}{ip['value']}{RESET} - {ip.get('comment')}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="AegisShield Terminal Threat Hunter")
    parser.add_argument("--scan", action="store_true", help="Execute process threat scan")
    parser.add_argument("--kill", action="store_true", help="Automatically kill detected threats (use with --scan)")
    parser.add_argument("--network", action="store_true", help="Audit processes using network sockets and trace IP origins")
    parser.add_argument("--rmm", action="store_true", help="Check for Remote Desktop / RMM / VNC processes")
    parser.add_argument("--persistence", action="store_true", help="Check Windows Startup and Registry persistence")
    parser.add_argument("--rules", action="store_true", help="Display all active allowlist and blocklist rules")
    parser.add_argument("--allow", type=str, help="Add process name to trusted allowlist")
    parser.add_argument("--block", type=str, help="Add process name or IP address to blocklist")
    parser.add_argument("--email-report", type=str, help="Generate and send HTML security report to specified recipient email")
    parser.add_argument("--kill-pid", type=int, help="Forcefully terminate a single process by PID")
    parser.add_argument("--kill-tree", type=int, help="Forcefully terminate process and all child processes")
    parser.add_argument("--min-score", type=int, default=50, help="Minimum threat score to terminate (default 50)")

    args = parser.parse_args()

    remediator = ThreatRemediator()
    policy = PolicyEngine()

    if args.allow:
        res = policy.add_allow_rule("name", args.allow, comment="CLI Allowlist Entry")
        print(f"{GREEN}[✓] {res['message']}{RESET}")
        return

    if args.block:
        target = args.block.strip()
        is_ip = target.replace(".", "").isdigit() and target.count(".") == 3
        if is_ip:
            res = policy.add_ip_block_rule(target, comment="CLI IP Ban", apply_firewall=True)
        else:
            res = policy.add_block_rule("name", target, comment="CLI Process Ban")
        print(f"{RED}[✓] {res['message']}{RESET}")
        return

    if args.rules:
        run_policy_rules()
        return

    if args.network:
        run_network_audit()
        return

    if args.email_report:
        notifier = EmailNotifier()
        detector = ThreatDetector()
        tracer = NetworkTracer()
        print(f"{CYAN}[*] Compiling full security posture report for {args.email_report}...{RESET}")
        scan_data = detector.scan_all_processes(detailed_pe=False)
        threats = [p for p in scan_data if p.get("is_threat")]
        net_data = tracer.audit_all_network_processes()
        payload = {
            "threats": threats,
            "rmm_tools": [p for p in scan_data if "REMOTE CONTROL" in p.get("primary_category", "")],
            "total_processes": len(scan_data),
            "system_health_index": 100 - min(len(threats) * 25, 100),
            "network": net_data
        }
        html = notifier.generate_html_report(payload)
        subject = f"🛡️ AegisShield Security Audit - {len(threats)} Threats Detected"
        res = notifier.send_email(subject, html, recipient=args.email_report)
        if res["success"]:
            print(f"{GREEN}[✓] {res['message']}{RESET}")
        else:
            print(f"{RED}[✗] {res['message']}{RESET}")
        return

    if args.kill_pid:
        res = remediator.kill_process(args.kill_pid, force=True, reason="CLI Force Kill")
        if res["success"]:
            print(f"{GREEN}[✓] {res['message']}{RESET}")
        else:
            print(f"{RED}[✗] {res['message']}{RESET}")
        return

    if args.kill_tree:
        res = remediator.kill_process_tree(args.kill_tree, reason="CLI Tree Eradication")
        if res["success"]:
            print(f"{GREEN}[✓] {res['message']}{RESET}")
        else:
            print(f"{RED}[✗] {res['message']}{RESET}")
        return

    if args.rmm:
        run_rmm_check()
        return

    if args.persistence:
        print(f"{CYAN}[*] Scanning Windows Startup and Registry persistence...{RESET}")
        entries = get_all_persistence_entries()
        suspicious = [e for e in entries if e.get("is_suspicious")]
        print(f"[+] Total entries: {len(entries)} | Suspicious: {len(suspicious)}")
        for s in suspicious:
            print(f"{YELLOW}[!] {s['name']} - {s['target_path']}{RESET}")
        return

    # Default: Run full process scan
    run_cli_scan(kill_mode=args.kill, min_score=args.min_score)


if __name__ == "__main__":
    main()
