"""
AegisShield - High-Definition Visual Screenshot Engine
Generates ultra-crisp 1600x1000 screenshots of all AegisShield SOC dashboard views,
including Threat Remediation, Network Origin Tracer, AdBlocker & Web Analytics,
Process Explorer, Policy Rules, and Email Alerts.
"""

import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

APP_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOTS_DIR = APP_ROOT / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def draw_hud_header(draw, active_tab_title: str):
    """Render top cyber SOC navigation header with Two-Level (Level 1 / Level 2) structured navigation."""
    # Top bar
    draw.rectangle([(0, 0), (1600, 72)], fill=(11, 17, 30), outline=(30, 41, 59))
    
    # Brand
    draw.rectangle([(25, 16), (65, 56)], fill=(15, 23, 42), outline=(6, 182, 212), width=2)
    draw.text((33, 22), "🛡", fill=(6, 182, 212))
    draw.text((80, 18), "AI Monitoring Engine • AdBlocker Engine • Web Tracker • Proc Mon Engine", fill=(255, 255, 255))
    draw.text((80, 42), "AEGISSHIELD EDR v2.5 | Autonomous Threat Hunter, Proxy Interceptor & Kernel Remediator", fill=(148, 163, 184))

    # Center Pill
    draw.rectangle([(800, 20), (1040, 50)], fill=(16, 185, 129, 30), outline=(16, 185, 129), width=1)
    draw.ellipse([(815, 31), (823, 39)], fill=(16, 185, 129))
    draw.text((835, 26), "SYSTEM SECURE | 2026-11-07", fill=(110, 231, 183))

    # Silent Mode Badge (Notification Sound Removed)
    draw.rectangle([(1050, 20), (1135, 50)], fill=(30, 41, 59), outline=(71, 85, 105), width=1)
    draw.text((1060, 27), "🔇 Silent", fill=(148, 163, 184))

    # Action buttons
    draw.rectangle([(1145, 20), (1240, 50)], fill=(139, 92, 246, 40), outline=(139, 92, 246), width=1)
    draw.text((1157, 27), "📧 Email", fill=(216, 180, 254))

    draw.rectangle([(1255, 20), (1350, 50)], fill=(6, 182, 212, 40), outline=(6, 182, 212))
    draw.text((1268, 27), "📚 Docs", fill=(103, 232, 249))

    draw.rectangle([(1365, 20), (1455, 50)], fill=(6, 182, 212), outline=(6, 182, 212))
    draw.text((1378, 27), "⚡ Scan", fill=(8, 12, 20))

    draw.rectangle([(1470, 20), (1575, 50)], fill=(239, 68, 68), outline=(239, 68, 68))
    draw.text((1482, 27), "🚨 KILL ALL", fill=(255, 255, 255))

    # Determine Active Category & Sub-Tabs
    t_lower = active_tab_title.lower()
    if any(k in t_lower for k in ["threat", "rmm", "audit"]):
        active_cat = "threats"
    elif any(k in t_lower for k in ["service", "process", "sys", "drive"]):
        active_cat = "endpoint"
    elif any(k in t_lower for k in ["network", "adblock"]):
        active_cat = "network"
    elif any(k in t_lower for k in ["policy", "persistence", "simulation"]):
        active_cat = "policy"
    else:
        active_cat = "reports"

    # Level 1 Categories Bar
    draw.rectangle([(0, 72), (1600, 104)], fill=(15, 23, 42), outline=(30, 41, 59))
    cat_items = [
        ("threats", "🛡️ Threat Defense & Intel"),
        ("endpoint", "🖥️ Endpoint & Services"),
        ("network", "🌐 Network & AdBlocker"),
        ("policy", "⚙️ Policies & Lab"),
        ("reports", "📑 Reports & Docs")
    ]
    cx = 25
    for cid, clabel in cat_items:
        is_act = (cid == active_cat)
        bg = (30, 41, 59) if is_act else (15, 23, 42)
        bdr = (6, 182, 212) if is_act else (30, 41, 59)
        col = (6, 182, 212) if is_act else (148, 163, 184)
        draw.rectangle([(cx, 76), (cx + 295, 100)], fill=bg, outline=bdr, width=1)
        draw.text((cx + 15, 82), clabel, fill=col)
        cx += 310

    # Level 2 Sub-Nav Bar (Filtered by Active Category)
    draw.rectangle([(0, 105), (1600, 137)], fill=(8, 12, 20), outline=(30, 41, 59))
    sub_map = {
        "threats": [("Threats", "Active Threats"), ("RMM", "RMM Hunter"), ("Audit", "Incident Audit")],
        "endpoint": [("Services", "Windows Services (services.msc)"), ("Processes", "Live Process Mon"), ("SysInfo", "System Diagnostics"), ("Drives", "Storage & Droppers")],
        "network": [("Network", "Network Radar & Sockets"), ("AdBlock", "AdBlocker & Proxy")],
        "policy": [("Policy", "Access Rules & Firewall"), ("Persistence", "Startup & Autoruns"), ("Simulation", "Simulation Lab")],
        "reports": [("Email", "Email Alerts & Reports"), ("Docs", "Documentation Hub")]
    }
    subs = sub_map.get(active_cat, sub_map["threats"])
    sx = 25
    for sid, slabel in subs:
        is_sub_act = (sid.lower() in t_lower) or (len(subs) == 1)
        sbg = (19, 28, 49) if is_sub_act else (8, 12, 20)
        sbdr = (6, 182, 212) if is_sub_act else (30, 41, 59)
        scol = (6, 182, 212) if is_sub_act else (148, 163, 184)
        sw = 230 if len(slabel) > 16 else 180
        draw.rectangle([(sx, 109), (sx + sw, 133)], fill=sbg, outline=sbdr, width=1)
        draw.text((sx + 12, 115), slabel, fill=scol)
        sx += sw + 10

    # SOC Enterprise Footer Bar
    draw.rectangle([(0, 965), (1600, 1000)], fill=(11, 17, 30), outline=(30, 41, 59))
    draw.text((25, 975), "Process: python.exe (PID: 96080) | Ports: 8888, 8080 | Sub-Apps: AI Monitor: ON, AdBlock: ON, Web Tracker: ON, Proc Mon: ON", fill=(148, 163, 184))
    draw.text((1080, 975), "Support with ❤️ - Sudhir Kumar Thanna | v2.5.0-SOC-Enterprise", fill=(6, 182, 212))


def draw_metric_cards(draw, cards: list):
    """Render top summary metric cards."""
    x = 25
    y = 135
    w = 300
    h = 90

    for label, val, sub, border_col, val_col in cards:
        draw.rectangle([(x, y), (x + w, y + h)], fill=(19, 28, 49), outline=border_col, width=2)
        draw.text((x + 15, y + 12), label, fill=(148, 163, 184))
        draw.text((x + 15, y + 34), val, fill=val_col)
        draw.text((x + 15, y + 68), sub, fill=(100, 116, 139))
        x += w + 12


def render_threats_view():
    """Render Screenshot 1: Active Threats & Remediation."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Threats")

    cards = [
        ("ACTIVE PROCESSES", "148 PIDs", "CPU: 18% | RAM: 42%", (6, 182, 212), (255, 255, 255)),
        ("FLAGGED THREATS", "3 Risks", "Behavioral & Signatures", (245, 158, 11), (245, 158, 11)),
        ("CRITICAL THREATS", "2 Threats", "Immediate Eradication", (239, 68, 68), (239, 68, 68)),
        ("REMOTE DESKTOP", "1 Active", "AnyDesk Session", (6, 182, 212), (103, 232, 249)),
        ("HEALTH INDEX", "72%", "Eradication Recommended", (239, 68, 68), (239, 68, 68))
    ]
    draw_metric_cards(d, cards)

    # Threats Container Title
    d.text((25, 245), "ACTIVE THREAT VECTORS (3 DETECTED)", fill=(255, 255, 255))

    # Threat Card 1: Disguised Trojan (Critical)
    y = 275
    d.rectangle([(25, y), (780, y + 330)], fill=(19, 28, 49), outline=(239, 68, 68), width=3)
    d.text((45, y + 20), "svch0st.exe (PID: 8412)", fill=(255, 255, 255))
    d.rectangle([(250, y + 18), (360, y + 38)], fill=(239, 68, 68, 40), outline=(239, 68, 68))
    d.text((258, y + 22), "CRITICAL TROJAN", fill=(252, 165, 165))
    d.text((680, y + 20), "Risk: 95/100", fill=(239, 68, 68))

    d.text((45, y + 55), "Path: C:\\Users\\user\\AppData\\Local\\Temp\\svch0st.exe", fill=(148, 163, 184))
    d.text((45, y + 75), "Command: svch0st.exe -w hidden -enc JABzAD0ATgBlAHcA...", fill=(100, 116, 139))

    # Threat breakdown bullets
    bullets = [
        "• Masquerading System Binary: Spoofing core Windows 'svchost.exe' from illegitimate Temp directory",
        "• Obfuscated LOLBin Execution: Encoded PowerShell cradle with hidden console window",
        "• Suspicious Injected APIs: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread detected in binary",
        "• Network Beacon: Active outbound socket communicating with 198.51.100.1:4444 (Metasploit C2)"
    ]
    by = y + 110
    for b in bullets:
        d.text((45, by), b[:90], fill=(248, 113, 113))
        by += 28

    # Card action buttons
    d.rectangle([(45, y + 270), (145, y + 305)], fill=(16, 185, 129, 30), outline=(16, 185, 129))
    d.text((65, y + 280), "Allow (Trust)", fill=(110, 231, 183))

    d.rectangle([(160, y + 270), (260, y + 305)], fill=(239, 68, 68, 30), outline=(239, 68, 68))
    d.text((180, y + 280), "Block (Ban)", fill=(252, 165, 165))

    d.rectangle([(520, y + 270), (630, y + 305)], fill=(245, 158, 11, 30), outline=(245, 158, 11))
    d.text((535, y + 280), "🌲 Kill Tree", fill=(253, 230, 138))

    d.rectangle([(645, y + 270), (760, y + 305)], fill=(239, 68, 68), outline=(239, 68, 68))
    d.text((665, y + 280), "⚡ KILL PROCESS", fill=(255, 255, 255))

    # Threat Card 2: Remote Access Trojan (njRAT)
    d.rectangle([(815, y), (1570, y + 330)], fill=(19, 28, 49), outline=(239, 68, 68), width=3)
    d.text((835, y + 20), "server.exe (PID: 12048)", fill=(255, 255, 255))
    d.rectangle([(1030, y + 18), (1170, y + 38)], fill=(239, 68, 68, 40), outline=(239, 68, 68))
    d.text((1038, y + 22), "CRITICAL RAT/SPYWARE", fill=(252, 165, 165))
    d.text((1470, y + 20), "Risk: 100/100", fill=(239, 68, 68))

    d.text((835, y + 55), "Path: C:\\Users\\user\\Downloads\\server.exe", fill=(148, 163, 184))
    d.text((835, y + 75), "Target: njRAT (Bladabindi) Surveillance Remote Access Trojan", fill=(100, 116, 139))

    bullets2 = [
        "• Verified Malware Signature: njRAT keylogger, webcam surveillance and credential harvester",
        "• Dangerous API Hooks: SetWindowsHookExW (Keystroke logging) & BitBlt (Screen Capture)",
        "• High Entropy Packing: Shannon Entropy 7.42 (UPX crypted executable)",
        "• Active Sockets: Listening on port 1177 and communicating with external C2 server"
    ]
    by = y + 110
    for b in bullets2:
        d.text((835, by), b[:90], fill=(248, 113, 113))
        by += 28

    # Actions Card 2
    d.rectangle([(835, y + 270), (935, y + 305)], fill=(16, 185, 129, 30), outline=(16, 185, 129))
    d.text((855, y + 280), "Allow (Trust)", fill=(110, 231, 183))

    d.rectangle([(950, y + 270), (1050, y + 305)], fill=(239, 68, 68, 30), outline=(239, 68, 68))
    d.text((970, y + 280), "Block (Ban)", fill=(252, 165, 165))

    d.rectangle([(1310, y + 270), (1420, y + 305)], fill=(245, 158, 11, 30), outline=(245, 158, 11))
    d.text((1325, y + 280), "🌲 Kill Tree", fill=(253, 230, 138))

    d.rectangle([(1435, y + 270), (1550, y + 305)], fill=(239, 68, 68), outline=(239, 68, 68))
    d.text((1455, y + 280), "⚡ KILL PROCESS", fill=(255, 255, 255))

    # Threat Card 3: AnyDesk Unauthorized Remote Control
    y3 = 630
    d.rectangle([(25, y3), (1570, y3 + 180)], fill=(19, 28, 49), outline=(6, 182, 212), width=2)
    d.text((45, y3 + 20), "AnyDesk.exe (PID: 6732) - Commercial Remote Desktop (LOLRMM)", fill=(103, 232, 249))
    d.rectangle([(620, y3 + 18), (760, y3 + 38)], fill=(6, 182, 212, 30), outline=(6, 182, 212))
    d.text((630, y3 + 22), "REMOTE CONTROL", fill=(103, 232, 249))
    d.text((1470, y3 + 20), "Risk: 65/100", fill=(245, 158, 11))

    d.text((45, y3 + 55), "Path: C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", fill=(148, 163, 184))
    d.text((45, y3 + 80), "• Active incoming/outgoing remote desktop control session detected on port 7070", fill=(253, 230, 138))
    d.text((45, y3 + 105), "• Living Off The Land RMM tool frequently leveraged in tech scams and unauthorized persistence", fill=(253, 230, 138))

    d.rectangle([(1400, y3 + 120), (1550, y3 + 155)], fill=(239, 68, 68), outline=(239, 68, 68))
    d.text((1415, y3 + 130), "Disconnect & Kill", fill=(255, 255, 255))

    img.save(SCREENSHOTS_DIR / "01_active_threats_remediation.png")
    print("[✓] Generated 01_active_threats_remediation.png")


def render_network_radar_view():
    """Render Screenshot 2: Network Radar & IP Origin Tracer."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Network")

    cards = [
        ("PROCESSES ON NETWORK", "14 PIDs", "Active TCP/UDP sockets", (6, 182, 212), (255, 255, 255)),
        ("ESTABLISHED SOCKETS", "28 Sockets", "Outbound Connections", (16, 185, 129), (110, 231, 183)),
        ("LISTENING DAEMONS", "6 Ports", "Server Daemons", (245, 158, 11), (253, 230, 138)),
        ("VERIFIED CDNS", "18 Sockets", "Microsoft, Google, AWS", (16, 185, 129), (110, 231, 183)),
        ("SUSPICIOUS ENDPOINTS", "2 Endpoints", "Unknown / RAT Ports", (239, 68, 68), (239, 68, 68))
    ]
    draw_metric_cards(d, cards)

    # Table Container
    d.rectangle([(25, 245), (1575, 960)], fill=(19, 28, 49), outline=(30, 41, 59))
    d.rectangle([(25, 245), (1575, 285)], fill=(15, 23, 42), outline=(30, 41, 59))

    headers = [
        ("PROCESS (PID)", 40),
        ("LOCAL SOCKET", 260),
        ("REMOTE ENDPOINT", 470),
        ("REVERSE DNS / ORGANIZATION", 690),
        ("GENUINENESS VERDICT", 1080),
        ("STATE", 1320),
        ("ACTIONS", 1450)
    ]
    for hname, hx in headers:
        d.text((hx, 257), hname, fill=(148, 163, 184))

    rows = [
        ("chrome.exe (4102)", "192.168.1.100:54210", "142.250.190.46:443", "1e100.net (Google LLC)", "GENUINE CLOUD / CDN", "ESTABLISHED", (16, 185, 129)),
        ("msedge.exe (8840)", "192.168.1.100:54218", "20.190.159.0:443", "microsoft.com (Microsoft Corp)", "GENUINE CLOUD / CDN", "ESTABLISHED", (16, 185, 129)),
        ("svch0st.exe (8412)", "192.168.1.100:49202", "198.51.100.1:4444", "Unresolved Host (Unknown ISP)", "SUSPICIOUS C2 / RAT PORT", "ESTABLISHED", (239, 68, 68)),
        ("server.exe (12048)", "0.0.0.0:1177", "LISTEN", "Localhost Binding", "SUSPICIOUS C2 / RAT PORT", "LISTEN", (239, 68, 68)),
        ("AnyDesk.exe (6732)", "192.168.1.100:50001", "79.125.10.22:7070", "net-79-125.anydesk.com (AnyDesk)", "REMOTE DESKTOP SESSION", "ESTABLISHED", (6, 182, 212)),
        ("spotify.exe (10214)", "192.168.1.100:54300", "104.18.25.12:443", "cloudflarenet (Cloudflare Inc)", "GENUINE CLOUD / CDN", "ESTABLISHED", (16, 185, 129)),
        ("powershell.exe (910)", "192.168.1.100:54350", "140.82.112.4:443", "github.com (GitHub Inc / MSFT)", "GENUINE CLOUD / CDN", "ESTABLISHED", (16, 185, 129)),
        ("python.exe (64316)", "127.0.0.1:8888", "LISTEN", "AegisShield Web Console", "PRIVATE LAN", "LISTEN", (6, 182, 212)),
        ("python.exe (64316)", "127.0.0.1:8080", "LISTEN", "AegisShield AdBlock Proxy", "PRIVATE LAN", "LISTEN", (6, 182, 212)),
        ("discord.exe (7120)", "192.168.1.100:54402", "162.159.130.233:443", "discord.gg (Cloudflare)", "GENUINE CLOUD / CDN", "ESTABLISHED", (16, 185, 129))
    ]

    ry = 295
    for p, l, r, org, v, st, col in rows:
        d.line([(25, ry), (1575, ry)], fill=(30, 41, 59))
        d.text((40, ry + 12), p, fill=(255, 255, 255))
        d.text((260, ry + 12), l, fill=(148, 163, 184))
        d.text((470, ry + 12), r, fill=(103, 232, 249))
        d.text((690, ry + 12), org, fill=(203, 213, 225))

        # Verdict badge
        d.rectangle([(1080, ry + 8), (1290, ry + 32)], fill=(col[0], col[1], col[2], 30), outline=col)
        d.text((1090, ry + 12), v, fill=col)

        d.text((1320, ry + 12), st, fill=(16, 185, 129) if st == "ESTABLISHED" else (245, 158, 11))

        # Actions
        d.rectangle([(1440, ry + 8), (1500, ry + 32)], fill=(239, 68, 68, 30), outline=(239, 68, 68))
        d.text((1448, ry + 12), "Block IP", fill=(252, 165, 165))

        d.rectangle([(1510, ry + 8), (1560, ry + 32)], fill=(239, 68, 68), outline=(239, 68, 68))
        d.text((1522, ry + 12), "Kill", fill=(255, 255, 255))

        ry += 48

    img.save(SCREENSHOTS_DIR / "02_network_radar_ip_tracer.png")
    print("[✓] Generated 02_network_radar_ip_tracer.png")


def render_adblocker_view():
    """Render Screenshot 3: AdBlocker & Web Browsing Analytics."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "AdBlock")

    # Proxy Banner
    d.rectangle([(25, 135), (1575, 195)], fill=(19, 28, 49), outline=(244, 63, 94), width=3)
    d.text((45, 150), "🛡️ SYSTEM-WIDE NETWORK AD BLOCKER & WEB INSPECTOR", fill=(255, 255, 255))
    d.text((45, 172), "All browser traffic (Chrome, Edge, Firefox, Brave) routes through 127.0.0.1:8080 and is filtered.", fill=(148, 163, 184))

    d.rectangle([(980, 148), (1280, 182)], fill=(16, 185, 129, 30), outline=(16, 185, 129))
    d.text((995, 156), "● Proxy: Active (All Browsers Protected)", fill=(110, 231, 183))

    d.rectangle([(1300, 145), (1450, 185)], fill=(239, 68, 68), outline=(239, 68, 68))
    d.text((1315, 156), "Disable Proxy", fill=(255, 255, 255))

    d.rectangle([(1465, 145), (1560, 185)], fill=(15, 23, 42), outline=(30, 41, 59))
    d.text((1480, 156), "Clear Logs", fill=(148, 163, 184))

    # Metric Cards
    cards = [
        ("SITES BROWSED", "1,248 Queries", "Total Intercepted Web Requests", (6, 182, 212), (255, 255, 255)),
        ("ADS & TRACKERS BLOCKED", "364 Blocked", "DoubleClick, Criteo, Taboola...", (244, 63, 94), (251, 113, 133)),
        ("BLOCK RATIO", "29.2%", "Efficiency Index", (245, 158, 11), (253, 230, 138)),
        ("BANDWIDTH PRESERVED", "91.0 MB", "Saved on Video & Script Ads", (16, 185, 129), (110, 231, 183))
    ]
    x = 25
    y = 210
    w = 375
    h = 85
    for label, val, sub, border_col, val_col in cards:
        d.rectangle([(x, y), (x + w, y + h)], fill=(19, 28, 49), outline=border_col, width=2)
        d.text((x + 15, y + 12), label, fill=(148, 163, 184))
        d.text((x + 15, y + 34), val, fill=val_col)
        d.text((x + 15, y + 62), sub, fill=(100, 116, 139))
        x += w + 12

    # Visual Analytics Grid (3 panels)
    y_panels = 310
    pw = 505
    ph = 230

    # Panel 1: Top Visited Clean Sites
    d.rectangle([(25, y_panels), (25 + pw, y_panels + ph)], fill=(19, 28, 49), outline=(30, 41, 59))
    d.text((45, y_panels + 15), "🌐 Top Visited Websites (Clean)", fill=(255, 255, 255))
    top_clean = [
        ("github.com", 218, 95),
        ("google.com", 184, 80),
        ("stackoverflow.com", 142, 62),
        ("news.ycombinator.com", 96, 42),
        ("wikipedia.org", 64, 28)
    ]
    py = y_panels + 45
    for site, count, pct in top_clean:
        d.text((45, py), site, fill=(203, 213, 225))
        d.text((420, py), f"{count} visits", fill=(6, 182, 212))
        d.rectangle([(45, py + 18), (480, py + 24)], fill=(15, 23, 42))
        d.rectangle([(45, py + 18), (45 + int(4.35 * pct), py + 24)], fill=(6, 182, 212))
        py += 35

    # Panel 2: Top Blocked Ad Networks
    d.rectangle([(550, y_panels), (550 + pw, y_panels + ph)], fill=(19, 28, 49), outline=(244, 63, 94), width=1)
    d.text((570, y_panels + 15), "🚫 Top Blocked Ad Networks & Trackers", fill=(251, 113, 133))
    top_bad = [
        ("doubleclick.net", 98, 92),
        ("google-analytics.com", 74, 70),
        ("criteo.com", 56, 52),
        ("taboola.com", 42, 39),
        ("hotjar.com", 31, 29)
    ]
    py = y_panels + 45
    for site, count, pct in top_bad:
        d.text((570, py), site, fill=(254, 205, 211))
        d.text((945, py), f"{count} blocked", fill=(244, 63, 94))
        d.rectangle([(570, py + 18), (1005, py + 24)], fill=(15, 23, 42))
        d.rectangle([(570, py + 18), (570 + int(4.35 * pct), py + 24)], fill=(244, 63, 94))
        py += 35

    # Panel 3: Category Breakdown
    d.rectangle([(1075, y_panels), (1575, y_panels + ph)], fill=(19, 28, 49), outline=(30, 41, 59))
    d.text((1095, y_panels + 15), "📊 Browsing Category Distribution", fill=(245, 158, 11))
    cats = [
        ("Clean Web Pages", 884, (16, 185, 129)),
        ("Commercial Ads", 192, (244, 63, 94)),
        ("Behavioral Trackers", 112, (139, 92, 246)),
        ("OS / App Telemetry", 48, (245, 158, 11)),
        ("Cryptominers / Malware", 12, (239, 68, 68))
    ]
    py = y_panels + 45
    for cname, cnt, col in cats:
        d.rectangle([(1095, py), (1555, py + 26)], fill=(15, 23, 42), outline=(30, 41, 59))
        d.text((1110, py + 6), cname, fill=(203, 213, 225))
        d.text((1500, py + 6), str(cnt), fill=col)
        py += 34

    # Live Browsing Feed Table
    ty = 560
    d.rectangle([(25, ty), (1575, 960)], fill=(19, 28, 49), outline=(30, 41, 59))
    d.rectangle([(25, ty), (1575, ty + 35)], fill=(15, 23, 42), outline=(30, 41, 59))

    d.text((45, ty + 10), "EXACT DATE & TIME", fill=(148, 163, 184))
    d.text((250, ty + 10), "WEBSITE / TARGET DOMAIN", fill=(148, 163, 184))
    d.text((680, ty + 10), "METHOD & PORT", fill=(148, 163, 184))
    d.text((880, ty + 10), "CATEGORY", fill=(148, 163, 184))
    d.text((1160, ty + 10), "STATUS", fill=(148, 163, 184))
    d.text((1420, ty + 10), "QUICK ACTION", fill=(148, 163, 184))

    feed = [
        ("2026-11-07 07:31:02", "adservice.google.com", "CONNECT:443", "AD / TRACKER", "BLOCKED", (244, 63, 94)),
        ("2026-11-07 07:30:58", "github.com", "CONNECT:443", "CLEAN / ALLOWED", "ALLOWED", (16, 185, 129)),
        ("2026-11-07 07:30:55", "google-analytics.com", "CONNECT:443", "TRACKER / ANALYTICS", "BLOCKED", (244, 63, 94)),
        ("2026-11-07 07:30:50", "stackoverflow.com", "CONNECT:443", "CLEAN / ALLOWED", "ALLOWED", (16, 185, 129)),
        ("2026-11-07 07:30:44", "securepubads.g.doubleclick.net", "CONNECT:443", "AD / TRACKER", "BLOCKED", (244, 63, 94)),
        ("2026-11-07 07:30:38", "criteo.com", "CONNECT:443", "AD / TRACKER", "BLOCKED", (244, 63, 94)),
        ("2026-11-07 07:30:30", "news.ycombinator.com", "CONNECT:443", "CLEAN / ALLOWED", "ALLOWED", (16, 185, 129)),
        ("2026-11-07 07:30:22", "telemetry.microsoft.com", "CONNECT:443", "TELEMETRY", "BLOCKED", (244, 63, 94))
    ]

    fy = ty + 45
    for dt, dom, mp, cat, st, col in feed:
        d.line([(25, fy - 5), (1575, fy - 5)], fill=(30, 41, 59))
        d.text((45, fy + 4), dt, fill=(148, 163, 184))
        d.text((250, fy + 4), dom, fill=(255, 255, 255) if st == "ALLOWED" else (251, 113, 133))
        d.text((680, fy + 4), mp, fill=(103, 232, 249))
        d.text((880, fy + 4), cat, fill=(203, 213, 225))

        d.rectangle([(1160, fy), (1240, fy + 24)], fill=(col[0], col[1], col[2], 30), outline=col)
        d.text((1170, fy + 4), st, fill=col)

        d.rectangle([(1420, fy), (1530, fy + 24)], fill=(15, 23, 42), outline=(30, 41, 59))
        d.text((1435, fy + 4), "Allow / Block", fill=(148, 163, 184))

        fy += 42

    img.save(SCREENSHOTS_DIR / "03_adblocker_web_analytics.png")
    print("[✓] Generated 03_adblocker_web_analytics.png")


def render_policy_rules_view():
    """Render Screenshot 6: Access Control & Allow/Block Policy."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Policy")

    d.text((25, 140), "ACCESS CONTROL & ALLOW / BLOCK POLICY RULES", fill=(255, 255, 255))
    d.text((25, 165), "Administer persistent process whitelists, binary blacklists, and Windows Firewall banned IP addresses.", fill=(148, 163, 184))

    # Add Rule Button
    d.rectangle([(1400, 135), (1575, 175)], fill=(6, 182, 212), outline=(6, 182, 212))
    d.text((1420, 147), "+ Add Custom Rule", fill=(8, 12, 20))

    # 3 Column Panels
    col_w = 495
    col_h = 750
    cy = 195

    # Allowed Whitelist
    d.rectangle([(25, cy), (25 + col_w, cy + col_h)], fill=(19, 28, 49), outline=(16, 185, 129), width=2)
    d.text((45, cy + 20), "✔ Allowed Processes (Whitelist)", fill=(110, 231, 183))
    d.text((45, cy + 45), "Bypasses all heuristics and is exempt from termination", fill=(100, 116, 139))
    allowed_rules = [
        ("explorer.exe", "name", "Core Windows Shell Environment"),
        ("code.exe", "name", "Visual Studio Code Development IDE"),
        ("git.exe", "name", "Source Control Engine"),
        ("internal_admin.exe", "name", "Approved Administrative Script"),
        ("C:\\tools\\custom_build.exe", "path", "Custom verified automation binary")
    ]
    ry = cy + 85
    for val, t, comm in allowed_rules:
        d.rectangle([(40, ry), (500, ry + 65)], fill=(15, 23, 42), outline=(30, 41, 59))
        d.text((55, ry + 10), val, fill=(255, 255, 255))
        d.text((55, ry + 35), f"[{t}] {comm}", fill=(148, 163, 184))
        d.text((465, ry + 20), "✕", fill=(239, 68, 68))
        ry += 75

    # Blocked Blacklist
    d.rectangle([(550, cy), (550 + col_w, cy + col_h)], fill=(19, 28, 49), outline=(239, 68, 68), width=2)
    d.text((570, cy + 20), "🚫 Blocked Processes (Blacklist)", fill=(252, 165, 165))
    d.text((570, cy + 45), "Banned by policy, flagged as Critical on sight", fill=(100, 116, 139))
    blocked_rules = [
        ("wannacry.exe", "name", "Known Ransomware payload"),
        ("mimikatz.exe", "name", "Credential Dumper"),
        ("xmrig.exe", "name", "Unauthorized Crypto Miner"),
        ("svch0st.exe", "name", "Typosquatted malware binary"),
        ("C:\\Temp\\malicious.bat", "path", "Dropped script payload")
    ]
    ry = cy + 85
    for val, t, comm in blocked_rules:
        d.rectangle([(565, ry), (1025, ry + 65)], fill=(15, 23, 42), outline=(30, 41, 59))
        d.text((580, ry + 10), val, fill=(255, 255, 255))
        d.text((580, ry + 35), f"[{t}] {comm}", fill=(148, 163, 184))
        d.text((990, ry + 20), "✕", fill=(239, 68, 68))
        ry += 75

    # Banned IPs
    d.rectangle([(1075, cy), (1075 + col_w, cy + col_h)], fill=(19, 28, 49), outline=(245, 158, 11), width=2)
    d.text((1095, cy + 20), "🛡️ Banned IP Addresses (Firewall Block)", fill=(253, 230, 138))
    d.text((1095, cy + 45), "Outbound Windows Firewall rules sever all socket traffic", fill=(100, 116, 139))
    banned_ips = [
        ("198.51.100.1", "Metasploit C2 Server"),
        ("203.0.113.50", "Verified njRAT Command Channel"),
        ("185.220.101.5", "Tor Exit Node Proxy"),
        ("194.26.29.112", "Crypto Mining Pool Host"),
        ("45.154.255.88", "Cobalt Strike Beacon Target")
    ]
    ry = cy + 85
    for ip, comm in banned_ips:
        d.rectangle([(1090, ry), (1550, ry + 65)], fill=(15, 23, 42), outline=(30, 41, 59))
        d.text((1105, ry + 10), ip, fill=(253, 230, 138))
        d.text((1105, ry + 35), f"Firewall Rule: {comm}", fill=(148, 163, 184))
        d.text((1515, ry + 20), "✕", fill=(239, 68, 68))
        ry += 75

    img.save(SCREENSHOTS_DIR / "06_access_control_rules.png")
    print("[✓] Generated 06_access_control_rules.png")


def render_all_remaining_views():
    """Render remaining views: Process Explorer, Persistence, Simulation, Email, Audit, RMM."""
    views = [
        ("04_remote_desktop_rmm_hunter.png", "RMM", "Remote Desktop & RAT Hunter", [
            ("AnyDesk.exe (6732)", "PID: 6732", "C:\\Program Files\\AnyDesk\\AnyDesk.exe", "Port: 7070", "ACTIVE RMM", (6, 182, 212)),
            ("TeamViewer_Service.exe (1840)", "PID: 1840", "C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe", "Port: 5938", "ACTIVE RMM", (6, 182, 212)),
            ("winvnc.exe (9102)", "PID: 9102", "C:\\Program Files\\UltraVNC\\winvnc.exe", "Port: 5900", "ACTIVE VNC SERVER", (239, 68, 68)),
            ("ScreenConnect.ClientService.exe (4412)", "PID: 4412", "C:\\Program Files\\ScreenConnect\\client.exe", "Port: 8040", "RMM AGENT", (245, 158, 11))
        ]),
        ("05_live_process_monitor.png", "Processes", "Live Process Explorer Table", [
            ("system (4)", "System Component", "0.2%", "12.4 MB", "SYSTEM", "SAFE", (16, 185, 129)),
            ("csrss.exe (820)", "C:\\Windows\\System32\\csrss.exe", "0.4%", "18.2 MB", "SYSTEM", "SAFE", (16, 185, 129)),
            ("svch0st.exe (8412)", "C:\\Users\\user\\AppData\\Local\\Temp\\svch0st.exe", "18.5%", "145.0 MB", "User", "CRITICAL", (239, 68, 68)),
            ("chrome.exe (4102)", "C:\\Program Files\\Google\\Chrome\\chrome.exe", "4.2%", "380.5 MB", "User", "SAFE", (16, 185, 129)),
            ("python.exe (64316)", "C:\\Python314\\python.exe", "1.1%", "62.4 MB", "User", "ALLOWED", (16, 185, 129))
        ]),
        ("07_persistence_startup.png", "Persistence", "Startup & Autoruns Hunter", [
            ("SecurityHealthSystray", "HKCU Run", "C:\\Windows\\System32\\SecurityHealthSystray.exe", "VERIFIED", (16, 185, 129)),
            ("OneDrive", "HKCU Run", "C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "VERIFIED", (16, 185, 129)),
            ("WinUpdateHelper", "Startup Folder", "C:\\Users\\user\\AppData\\Local\\Temp\\update.bat", "SUSPICIOUS SCRIPT", (239, 68, 68)),
            ("GoogleUpdateTaskMachine", "Scheduled Task", "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe", "VERIFIED", (16, 185, 129))
        ]),
        ("08_threat_simulation_lab.png", "Simulation", "Threat Simulation Lab", [
            ("Scenario 1: Temp Drop Trojan", "Simulates harmless background sleep process in %TEMP% folder", "Ready to Launch", (139, 92, 246)),
            ("Scenario 2: Obfuscated LOLBin", "Simulates PowerShell -enc -w hidden download cradle flags", "Ready to Launch", (139, 92, 246)),
            ("Scenario 3: RMM Beacon", "Simulates dual-use remote desktop beacon on port 5900", "Ready to Launch", (139, 92, 246))
        ]),
        ("09_email_alerts_config.png", "Email", "SMTP Email Alerts & Reports", [
            ("SMTP Server Host", "smtp.gmail.com:587 (TLS Enabled)", "Configured", (6, 182, 212)),
            ("Sender Email", "security-edr@yourdomain.com", "Configured", (6, 182, 212)),
            ("Recipient Email", "admin@yourdomain.com", "Configured", (16, 185, 129)),
            ("Automated Dispatch", "Active: Trigger email on CRITICAL threat detection", "Enabled", (16, 185, 129))
        ]),
        ("10_incident_audit_trail.png", "Audit", "Incident & Eradication Audit Log", [
            ("2026-11-07 07:32:00", "PROCESS_KILLED", "Terminated PID 8412 (svch0st.exe)", "SUCCESS", (16, 185, 129)),
            ("2026-11-07 07:31:45", "IP_BLOCKED", "Windows Firewall Rule added for 198.51.100.1", "SUCCESS", (16, 185, 129)),
            ("2026-11-07 07:31:20", "EMAIL_REPORT_SENT", "Dispatched full security audit to admin@yourdomain.com", "SUCCESS", (16, 185, 129)),
            ("2026-11-07 07:30:10", "ADBLOCK_PROXY_STARTED", "Intercepting proxy running on 127.0.0.1:8080", "SUCCESS", (16, 185, 129))
        ])
    ]

    for fname, tid, title, data in views:
        img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
        d = ImageDraw.Draw(img)
        draw_hud_header(d, tid)

        d.text((25, 140), title.upper(), fill=(255, 255, 255))
        d.text((25, 165), f"Real-time telemetric inspection and control view for {title}", fill=(148, 163, 184))

        d.rectangle([(25, 200), (1575, 960)], fill=(19, 28, 49), outline=(30, 41, 59))
        d.rectangle([(25, 200), (1575, 240)], fill=(15, 23, 42), outline=(30, 41, 59))

        d.text((45, 212), "COMPONENT / TARGET", fill=(148, 163, 184))
        d.text((420, 212), "DETAILS / PATH / STATE", fill=(148, 163, 184))
        d.text((1050, 212), "STATUS / CLASSIFICATION", fill=(148, 163, 184))
        d.text((1420, 212), "STATUS BADGE", fill=(148, 163, 184))

        ry = 250
        for item in data:
            col = item[-1] if isinstance(item[-1], tuple) else (6, 182, 212)
            c1 = str(item[0])
            if len(item) >= 3 and isinstance(item[-1], tuple):
                status_badge = str(item[-2])
                details = "  |  ".join(str(x) for x in item[1:-2]) if len(item) > 3 else str(item[1])
            else:
                status_badge = "INFO"
                details = "  |  ".join(str(x) for x in item[1:])

            d.line([(25, ry), (1575, ry)], fill=(30, 41, 59))
            d.text((45, ry + 15), c1[:45], fill=(255, 255, 255))
            d.text((420, ry + 15), details[:80], fill=(203, 213, 225))
            d.text((1050, ry + 15), status_badge[:35], fill=col)

            bg_tint = (int(col[0] * 0.25), int(col[1] * 0.25), int(col[2] * 0.25))
            d.rectangle([(1420, ry + 8), (1540, ry + 36)], fill=bg_tint, outline=col)
            d.text((1435, ry + 14), status_badge[:12], fill=col)

            ry += 52

        img.save(SCREENSHOTS_DIR / fname)
        print(f"[✓] Generated {fname}")


def render_private_mode_view():
    """Render 11: Private Stealth Mode View with zero-disk footprint."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "AdBlock")

    # Stealth Banner
    d.rectangle([(0, 120), (1600, 160)], fill=(46, 16, 77), outline=(168, 85, 247))
    d.ellipse([(25, 136), (33, 144)], fill=(192, 132, 252))
    d.text((45, 134), "🕵️ PRIVATE STEALTH MODE ACTIVE: Zero disk logging • Volatile memory only • Anti-fingerprint headers enforced • Traces destroyed on exit.", fill=(243, 232, 255))
    d.rectangle([(1420, 126), (1560, 154)], fill=(220, 38, 38), outline=(239, 68, 68))
    d.text((1435, 132), "⚡ Stealth Panic Wipe", fill=(255, 255, 255))

    d.text((25, 175), "STEALTH BROWSING & ZERO FOOTPRINT CONSOLE", fill=(216, 180, 254))
    d.text((25, 200), "Interception active with volatile RAM buffers and anti-tracking headers enabled.", fill=(148, 163, 184))

    # KPI Cards
    cards = [
        ("PRIVATE BROWSING", "ACTIVE (RAM ONLY)", "Zero Disk Persistence", (168, 85, 247)),
        ("CLIENT IP", "127.0.0.1 (STEALTH)", "Origin Anonymized", (6, 182, 212)),
        ("ANTI-FINGERPRINT", "ENFORCED", "Clear-Site-Data & No-Cache", (16, 185, 129)),
        ("VOLATILE BUFFER", "4 ENTRIES", "Wiped on Exit or Panic Wipe", (245, 158, 11))
    ]
    cx = 25
    for title, val, sub, col in cards:
        d.rectangle([(cx, 235), (cx + 365, 330)], fill=(19, 28, 49), outline=(168, 85, 247) if col == (168, 85, 247) else (30, 41, 59))
        d.text((cx + 20, 250), title, fill=(148, 163, 184))
        d.text((cx + 20, 275), val, fill=col)
        d.text((cx + 20, 305), sub, fill=(100, 116, 139))
        cx += 395

    # Volatile Browsing Table
    d.rectangle([(25, 355), (1575, 960)], fill=(19, 28, 49), outline=(30, 41, 59))
    d.rectangle([(25, 355), (1575, 400)], fill=(15, 23, 42), outline=(30, 41, 59))

    d.text((45, 370), "TIMESTAMP", fill=(148, 163, 184))
    d.text((260, 370), "WEBSITE / TARGET DOMAIN (VOLATILE RAM BUFFER)", fill=(148, 163, 184))
    d.text((880, 370), "METHOD : PORT", fill=(148, 163, 184))
    d.text((1150, 370), "PRIVACY VERDICT", fill=(148, 163, 184))
    d.text((1420, 370), "STORAGE MODE", fill=(148, 163, 184))

    rows = [
        ("2026-11-07 07:54:10", "🔒 [PRIVATE] duckduckgo.com", "CONNECT : 443", "ALLOWED (STEALTH)", (16, 185, 129), "VOLATILE RAM"),
        ("2026-11-07 07:54:12", "🔒 [PRIVATE] adservice.google.com", "CONNECT : 443", "BLOCKED AD", (239, 68, 68), "VOLATILE RAM"),
        ("2026-11-07 07:54:18", "🔒 [PRIVATE] proton.me", "CONNECT : 443", "ALLOWED (STEALTH)", (16, 185, 129), "VOLATILE RAM"),
        ("2026-11-07 07:54:25", "🔒 [PRIVATE] doubleclick.net", "CONNECT : 443", "BLOCKED TRACKER", (239, 68, 68), "VOLATILE RAM")
    ]

    ry = 415
    for ts, dom, mp, verd, col, store in rows:
        d.line([(25, ry), (1575, ry)], fill=(30, 41, 59))
        d.text((45, ry + 15), ts, fill=(148, 163, 184))
        d.text((260, ry + 15), dom, fill=(243, 232, 255) if "duck" in dom or "proton" in dom else (252, 165, 165))
        d.text((880, ry + 15), mp, fill=(6, 182, 212))
        d.text((1150, ry + 15), verd, fill=col)

        d.rectangle([(1420, ry + 8), (1545, ry + 36)], fill=(59, 7, 100), outline=(168, 85, 247))
        d.text((1435, ry + 14), store, fill=(216, 180, 254))
        ry += 52

    img.save(SCREENSHOTS_DIR / "11_private_mode_stealth.png")
    print("[✓] Generated 11_private_mode_stealth.png")


def render_light_mode_view():
    """Render 12: Light Clean SOC Mode (Daylight Theme with Shadcn UI & Modern Fonts)."""
    img = Image.new("RGB", (1600, 1000), color=(248, 250, 252))
    d = ImageDraw.Draw(img)

    # Header
    d.rectangle([(0, 0), (1600, 75)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.rectangle([(25, 18), (65, 58)], fill=(241, 245, 249), outline=(2, 132, 199), width=2)
    d.text((33, 24), "🛡", fill=(2, 132, 199))
    d.text((80, 22), "AI Monitoring Engine • AdBlocker • Web Tracker • Proc Mon | AEGISSHIELD", fill=(15, 23, 42))
    d.text((80, 44), "Daylight Clean SOC Theme • Shadcn & Bootstrap Design Tokens • WCAG AAA High Contrast", fill=(71, 85, 105))

    # Center Pill
    d.rectangle([(750, 22), (1050, 52)], fill=(240, 253, 244), outline=(187, 247, 208), width=1)
    d.ellipse([(765, 33), (773, 41)], fill=(22, 163, 74))
    d.text((785, 28), "SYSTEM PROTECTED & SECURE", fill=(21, 128, 61))

    # Header Action Buttons (Shadcn Outline Style)
    d.rectangle([(1065, 22), (1165, 52)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.text((1078, 29), "🌙 Dark Mode", fill=(15, 23, 42))

    d.rectangle([(1175, 22), (1255, 52)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.text((1188, 29), "🔇 Silent", fill=(71, 85, 105))

    d.rectangle([(1265, 22), (1375, 52)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.text((1278, 29), "📧 Email Report", fill=(15, 23, 42))

    d.rectangle([(1385, 22), (1475, 52)], fill=(2, 132, 199), outline=(2, 132, 199))
    d.text((1398, 29), "⚡ Deep Scan", fill=(255, 255, 255))

    d.rectangle([(1485, 22), (1575, 52)], fill=(220, 38, 38), outline=(185, 28, 28))
    d.text((1495, 29), "🚨 KILL ALL", fill=(255, 255, 255))

    # Shadcn Segmented Tab Navigation Bar
    d.rectangle([(25, 83), (1575, 123)], fill=(241, 245, 249), outline=(226, 232, 240))
    tabs = [
        ("Active Threats", True),
        ("Services (services.msc)", False),
        ("System Diagnostics", False),
        ("Storage & Dropper", False),
        ("Network Radar", False),
        ("AdBlocker", False),
        ("RMM Hunter", False),
        ("Process Mon", False),
        ("Access Rules", False),
        ("Docs Hub", False)
    ]
    tx = 32
    for tname, is_act in tabs:
        tw = 145 if "services" in tname.lower() else (125 if "diagnostics" in tname.lower() or "dropper" in tname.lower() else 110)
        if is_act:
            d.rectangle([(tx, 88), (tx + tw, 118)], fill=(255, 255, 255), outline=(203, 213, 225), width=1)
            d.text((tx + 10, 95), tname, fill=(2, 132, 199))
        else:
            d.text((tx + 10, 95), tname, fill=(71, 85, 105))
        tx += tw + 8

    # Metric Cards in Light Mode (6 KPI Grid)
    cards = [
        ("ACTIVE PROCS", "152 PIDs", "CPU: 4.8% | RAM: 64%", (226, 232, 240), (15, 23, 42)),
        ("CRITICAL THREATS", "0 Severe", "Risk Score >= 75", (254, 202, 202), (185, 28, 28)),
        ("SUSPICIOUS", "0 Anomalies", "Heuristics & Droppers", (253, 230, 138), (180, 83, 9)),
        ("REMOTE / RMM", "0 Active", "AnyDesk, TeamViewer", (186, 230, 253), (3, 105, 161)),
        ("SYS & STORAGE", "46% Used", "951 GB Disk Pool", (199, 210, 254), (67, 56, 202)),
        ("HEALTH INDEX", "100% Secure", "Verified Audit Trail", (187, 247, 208), (21, 128, 61))
    ]
    cx = 25
    for title, val, sub, border_col, val_col in cards:
        d.rectangle([(cx, 135), (cx + 245, 225)], fill=(255, 255, 255), outline=border_col, width=1)
        d.text((cx + 15, 147), title, fill=(71, 85, 105))
        d.text((cx + 15, 169), val, fill=val_col)
        d.text((cx + 15, 199), sub, fill=(100, 116, 139))
        cx += 260

    # Main Data Table Card (Shadcn Table Style)
    d.rectangle([(25, 240), (1575, 955)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.rectangle([(25, 240), (1575, 280)], fill=(248, 250, 252), outline=(226, 232, 240))

    d.text((45, 254), "PID & PROCESS NAME", fill=(71, 85, 105))
    d.text((320, 254), "EXECUTABLE PATH & USER INTEGRITY", fill=(71, 85, 105))
    d.text((900, 254), "HEURISTIC & BEHAVIORAL VERDICT", fill=(71, 85, 105))
    d.text((1350, 254), "STATUS BADGE", fill=(71, 85, 105))

    procs = [
        ("system (PID: 4)", "C:\\Windows\\System32\\ntoskrnl.exe | NT AUTHORITY\\SYSTEM", "Score: 0 - Verified OS Kernel Component", "SAFE", (240, 253, 244), (187, 247, 208), (21, 128, 61)),
        ("svchost.exe (PID: 1240)", "C:\\Windows\\System32\\svchost.exe | NETWORK SERVICE", "Score: 0 - Legitimate RPC Host Service", "SAFE", (240, 253, 244), (187, 247, 208), (21, 128, 61)),
        ("chrome.exe (PID: 4890)", "C:\\Program Files\\Google\\Chrome\\chrome.exe | User", "Score: 5 - Verified Digital Authenticode", "SAFE", (240, 253, 244), (187, 247, 208), (21, 128, 61)),
        ("python.exe (PID: 96080)", "C:\\Python314\\python.exe | User (Port 8888, 8080)", "Score: 0 - AegisShield EDR Active Daemon", "SAFE", (240, 253, 244), (187, 247, 208), (21, 128, 61)),
        ("SearchHost.exe (PID: 8820)", "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS | User", "Score: 0 - Windows Desktop Search Indexer", "SAFE", (240, 253, 244), (187, 247, 208), (21, 128, 61))
    ]

    ry = 295
    for p1, p2, p3, badge, bg_col, bdr_col, text_col in procs:
        d.line([(25, ry), (1575, ry)], fill=(241, 245, 249))
        d.text((45, ry + 12), p1, fill=(15, 23, 42))
        d.text((320, ry + 12), p2, fill=(51, 65, 85))
        d.text((900, ry + 12), p3, fill=text_col)

        d.rectangle([(1350, ry + 6), (1450, ry + 32)], fill=bg_col, outline=bdr_col)
        d.text((1375, ry + 11), badge, fill=text_col)
        ry += 48

    # SOC Footer Bar
    d.rectangle([(0, 965), (1600, 1000)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.text((25, 975), "Process: python.exe (PID: 96080) | Ports: 8888, 8080 | Sub-Apps: AI Monitor: ON, AdBlock: ON, Web Tracker: ON, Proc Mon: ON", fill=(71, 85, 105))
    d.text((1180, 975), "Support with ❤️ - Sudhir Kumar Thanna | v2.5.0-SOC-Enterprise", fill=(2, 132, 199))

    img.save(SCREENSHOTS_DIR / "12_light_mode_clean_soc.png")
    print("[✓] Generated 12_light_mode_clean_soc.png")


def render_documentation_hub_view():
    """Render Screenshot 13: Enterprise Documentation Hub."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Docs")

    # Documentation Banner
    d.rectangle([(25, 135), (1575, 215)], fill=(19, 28, 49), outline=(6, 182, 212), width=2)
    d.text((45, 148), "📚 AEGISSHIELD ENTERPRISE DOCUMENTATION & KNOWLEDGE HUB", fill=(255, 255, 255))
    d.text((45, 172), "Architectural Reference, Four Core Defensive Engines, Screenshot Gallery, Brain Files & CLI Runbook", fill=(148, 163, 184))
    d.text((1200, 160), "Author: Sudhir Kumar Thanna | v2.5.0", fill=(6, 182, 212))

    # Sidebar TOC
    d.rectangle([(25, 230), (320, 945)], fill=(15, 23, 42), outline=(30, 41, 59))
    d.text((45, 245), "TABLE OF CONTENTS", fill=(100, 116, 139))
    toc = [
        ("1. Executive Overview", True),
        ("2. System Architecture", False),
        ("3. Four Core Engines", False),
        ("4. Admin UAC Elevation", False),
        ("5. HD Screenshot Gallery", False),
        ("6. Brain Files & Plans", False),
        ("7. Chronological Prompts", False),
        ("8. Commands Runbook", False),
        ("9. API & WebSockets", False)
    ]
    ty = 275
    for item, active in toc:
        if active:
            d.rectangle([(35, ty - 4), (310, ty + 24)], fill=(6, 182, 212, 40), outline=(6, 182, 212))
            d.text((50, ty), item, fill=(6, 182, 212))
        else:
            d.text((50, ty), item, fill=(148, 163, 184))
        ty += 34

    # Main Doc Content
    d.rectangle([(340, 230), (1575, 945)], fill=(19, 28, 49), outline=(30, 41, 59))
    d.text((365, 250), "SECTION 01: SYSTEM OVERVIEW & ARCHITECTURE", fill=(255, 255, 255))
    d.text((365, 275), "AegisShield EDR is an autonomous endpoint detection and response platform for Windows endpoints.", fill=(203, 213, 225))
    
    # 4 Engine Cards in Docs
    engines = [
        ("AI Threat Hunter Engine", "Multi-tiered scoring matrix analyzing process names, paths, masquerades, temporary execution, command-line arguments, and hashes.", (6, 182, 212)),
        ("AdBlocker Network Proxy", "Intercepts HTTP/HTTPS traffic at 127.0.0.1:8080, matching domain names against ad/telemetry blacklists.", (244, 63, 94)),
        ("Web Origin & IP Tracer", "Performs reverse DNS, ASN, ISP lookup, and IP geolocation with classification.", (139, 92, 246)),
        ("Process Remediator & Firewall", "Multi-tier process killer (psutil -> taskkill -> PowerShell -> Service Control -> UAC Elevation) and Windows Firewall netsh controller.", (245, 158, 11))
    ]
    ey = 315
    for ename, edesc, ecol in engines:
        d.rectangle([(365, ey), (1550, ey + 75)], fill=(15, 23, 42), outline=ecol, width=1)
        d.text((385, ey + 12), ename, fill=ecol)
        d.text((385, ey + 36), edesc, fill=(148, 163, 184))
        ey += 88

    # Code Box
    d.rectangle([(365, ey + 10), (1550, 920)], fill=(8, 12, 20), outline=(30, 41, 59))
    d.text((385, ey + 25), "CLI RUNBOOK & DEPLOYMENT COMMANDS:", fill=(245, 158, 11))
    d.text((385, ey + 50), "# Start Dashboard as Administrator:   start_all_admin.bat", fill=(110, 231, 183))
    d.text((385, ey + 75), "# Run 30 Subsystem Diagnostic Tests:   python tools/test_engine.py", fill=(110, 231, 183))
    d.text((385, ey + 100), "# Intercepting Web Proxy Port:         127.0.0.1:8080", fill=(110, 231, 183))
    d.text((385, ey + 125), "# Email Dispatch Channel:              Resend API (HTTPS Port 443 / Cloud Delivery)", fill=(110, 231, 183))

    img.save(SCREENSHOTS_DIR / "13_documentation_hub.png")
    print("[✓] Generated 13_documentation_hub.png")


def render_elevated_kill_modal_view():
    """Render Screenshot 14: Interactive Elevated UAC Eradicator Modal."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Processes")

    # Darkened Backdrop
    d.rectangle([(0, 0), (1600, 1000)], fill=(5, 8, 14, 200))

    # Elevated Modal Box
    mx = 480
    my = 260
    mw = 640
    mh = 440
    d.rectangle([(mx, my), (mx + mw, my + mh)], fill=(19, 28, 49), outline=(239, 68, 68), width=3)

    # Modal Header
    d.rectangle([(mx + 25, my + 25), (mx + 75, my + 75)], fill=(239, 68, 68, 40), outline=(239, 68, 68))
    d.text((mx + 42, my + 38), "🚨", fill=(239, 68, 68))
    d.text((mx + 90, my + 30), "Administrator Rights Required", fill=(255, 255, 255))
    d.text((mx + 90, my + 54), "Access Denied when killing PID 5824 (svchost.exe)", fill=(248, 113, 113))

    # Modal Alert Body
    d.rectangle([(mx + 25, my + 95), (mx + mw - 25, my + 210)], fill=(15, 23, 42), outline=(239, 68, 68, 80))
    d.text((mx + 40, my + 110), "⚠️ Access Denied: The target process is protected by Windows kernel/SYSTEM credentials.", fill=(254, 202, 202))
    d.text((mx + 40, my + 135), "Standard user processes cannot terminate elevated Windows Services directly.", fill=(203, 213, 225))
    d.text((mx + 40, my + 165), "Detected Host Windows Service: 'DiagTrack' (Connected User Experience and Telemetry)", fill=(245, 158, 11))

    # Command Copy Box
    d.text((mx + 25, my + 230), "RUN DIRECTLY VIA ELEVATED ADMINISTRATOR SHELL:", fill=(148, 163, 184))
    d.rectangle([(mx + 25, my + 255), (mx + mw - 25, my + 295)], fill=(8, 12, 20), outline=(30, 41, 59))
    d.text((mx + 40, my + 268), "taskkill /F /PID 5824", fill=(6, 182, 212))
    d.rectangle([(mx + mw - 110, my + 260), (mx + mw - 35, my + 290)], fill=(30, 41, 59), outline=(71, 85, 105))
    d.text((mx + mw - 95, my + 268), "Copy", fill=(255, 255, 255))

    # Action Buttons
    d.rectangle([(mx + mw - 460, my + mh - 65), (mx + mw - 340, my + mh - 25)], fill=(15, 23, 42), outline=(71, 85, 105))
    d.text((mx + mw - 430, my + mh - 50), "Dismiss", fill=(148, 163, 184))

    d.rectangle([(mx + mw - 325, my + mh - 65), (mx + mw - 195, my + mh - 25)], fill=(245, 158, 11), outline=(245, 158, 11))
    d.text((mx + mw - 310, my + mh - 50), "🛑 Stop Service", fill=(8, 12, 20))

    d.rectangle([(mx + mw - 180, my + mh - 65), (mx + mw - 25, my + mh - 25)], fill=(239, 68, 68), outline=(239, 68, 68))
    d.text((mx + mw - 165, my + mh - 50), "⚡ UAC Eradicate", fill=(255, 255, 255))

    img.save(SCREENSHOTS_DIR / "14_elevated_kill_modal_and_tracking.png")
    print("[✓] Generated 14_elevated_kill_modal_and_tracking.png")


def render_system_diagnostics_view():
    """Render Screenshot 15: System Diagnostics & Baseline (SystemInfoCheck)."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "SysInfo")

    # Metrics
    cards = [
        ("OPERATING SYSTEM", "Windows 11", "Build 26100 | AMD64 | Uptime: 4d 8h", (6, 182, 212), (255, 255, 255)),
        ("PROCESSOR (CPU)", "24 Cores", "Load: 12% | 3400 MHz Max", (99, 102, 241), (129, 140, 248)),
        ("PHYSICAL RAM", "31.4 GB Total", "Used: 22.3 GB (71%) | Swap: 2.1 GB", (16, 185, 129), (52, 211, 153)),
        ("SECURITY BASELINE", "SECURE POSTURE", "Admin: Active | Defender: Active", (244, 63, 94), (251, 113, 133))
    ]
    draw_metric_cards(d, cards)

    # NICs Table Card
    d.rectangle([(25, 250), (1575, 940)], fill=(15, 23, 42), outline=(30, 41, 59), width=2)
    d.text((45, 270), "🌐 ACTIVE NETWORK ADAPTERS (NICS) & SECURITY BASELINE AUDIT", fill=(6, 182, 212))
    d.text((45, 295), "Hardware network interfaces, IPv4 bindings, MAC addresses, and security baseline controls.", fill=(148, 163, 184))

    # Table Header
    d.rectangle([(45, 330), (1555, 365)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.text((60, 340), "INTERFACE NAME", fill=(148, 163, 184))
    d.text((380, 340), "IPV4 ADDRESS", fill=(148, 163, 184))
    d.text((640, 340), "MAC ADDRESS", fill=(148, 163, 184))
    d.text((950, 340), "SPEED / DUPLEX", fill=(148, 163, 184))
    d.text((1250, 340), "LINK STATUS", fill=(148, 163, 184))
    d.text((1440, 340), "BASELINE", fill=(148, 163, 184))

    nics = [
        ("Ethernet Controller (Intel I225-V)", "192.168.1.105", "D8:BB:C1:2E:4A:10", "2500 Mbps / Full", "ONLINE (UP)", "PROTECTED"),
        ("Wi-Fi 6E Adapter (Intel AX211)", "192.168.1.106", "E4:54:E8:8A:2B:99", "1200 Mbps / Full", "ONLINE (UP)", "PROTECTED"),
        ("vEthernet (Default Switch - Hyper-V)", "172.24.16.1", "00:15:5D:89:12:01", "10000 Mbps / Full", "ONLINE (UP)", "INTERNAL"),
        ("Bluetooth Device (Personal Area Network)", "169.254.12.8", "E4:54:E8:8A:2B:9D", "3 Mbps / Full", "ONLINE (UP)", "MONITORED"),
        ("Tailscale Tunnel Interface", "100.82.14.99", "N/A (Virtual Point-to-Point)", "1000 Mbps / Full", "ONLINE (UP)", "ENCRYPTED"),
        ("Loopback Pseudo-Interface 1", "127.0.0.1", "00:00:00:00:00:00", "Auto / Full", "ONLINE (UP)", "LOCALHOST")
    ]

    ny = 380
    for name, ip, mac, spd, stat, base in nics:
        d.rectangle([(45, ny), (1555, ny + 45)], fill=(19, 28, 49), outline=(30, 41, 59))
        d.text((60, ny + 12), name, fill=(255, 255, 255))
        d.text((380, ny + 12), ip, fill=(6, 182, 212))
        d.text((640, ny + 12), mac, fill=(148, 163, 184))
        d.text((950, ny + 12), spd, fill=(203, 213, 225))
        d.text((1250, ny + 12), stat, fill=(52, 211, 153))
        d.text((1440, ny + 12), base, fill=(129, 140, 248))
        ny += 55

    # Bottom Baseline Panel
    d.rectangle([(45, 730), (1555, 920)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.text((65, 745), "🛡️ SYSTEM SECURITY BASELINE AUDIT SUMMARY", fill=(16, 185, 129))
    d.text((65, 775), "• Windows Defender Real-Time Antivirus Protection: ACTIVE & UPDATED", fill=(203, 213, 225))
    d.text((65, 800), "• User Account Control (UAC): LEVEL 3 (Notify when apps make changes)", fill=(203, 213, 225))
    d.text((65, 825), "• Data Execution Prevention (DEP) & ASLR: HARDWARE ENFORCED", fill=(203, 213, 225))
    d.text((65, 850), "• Windows Netsh Advanced Firewall: ACTIVE ON ALL THREE PROFILES (Domain, Private, Public)", fill=(203, 213, 225))
    d.text((65, 875), "• Remote Desktop (RDP) Baseline: PORT 3389 SECURED & FILTERED BY AEGISSHIELD POLICY", fill=(203, 213, 225))

    img.save(SCREENSHOTS_DIR / "15_system_diagnostics_baseline.png")
    print("[✓] Generated 15_system_diagnostics_baseline.png")


def render_storage_dropper_hunter_view():
    """Render Screenshot 16: Storage & Dropper Hunter (DriveOrganiserAndAnalyzer)."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Drives")

    # Metrics
    cards = [
        ("STORAGE POOL", "1,882 GB Total", "2 Physical & Logical Partitions", (6, 182, 212), (255, 255, 255)),
        ("USED CAPACITY", "742.6 GB Used", "Overall Pool: 39.4% Used", (245, 158, 11), (251, 191, 36)),
        ("FREE CAPACITY", "1,140.2 GB Free", "Safe Storage Pool Threshold", (16, 185, 129), (52, 211, 153)),
        ("DROPPER STAGING", "CLEAN / AUDITED", "3 High-Risk Zones Monitored", (239, 68, 68), (248, 113, 113))
    ]
    draw_metric_cards(d, cards)

    # Drive Partitions
    d.rectangle([(25, 245), (1575, 430)], fill=(15, 23, 42), outline=(30, 41, 59), width=2)
    d.text((45, 260), "💾 PHYSICAL & LOGICAL PARTITIONS TELEMETRY", fill=(255, 255, 255))

    # C Drive Card
    d.rectangle([(45, 290), (785, 410)], fill=(19, 28, 49), outline=(6, 182, 212), width=1)
    d.text((65, 305), "C:\\ (OS & System Boot Drive - NTFS)", fill=(6, 182, 212))
    d.text((680, 305), "68% Used", fill=(251, 191, 36))
    d.rectangle([(65, 335), (765, 350)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.rectangle([(65, 335), (540, 350)], fill=(6, 182, 212))
    d.text((65, 365), "Used: 324.2 GB  |  Free: 152.1 GB  |  Total: 476.3 GB", fill=(148, 163, 184))

    # D Drive Card
    d.rectangle([(815, 290), (1555, 410)], fill=(19, 28, 49), outline=(16, 185, 129), width=1)
    d.text((835, 305), "D:\\ (Data & Repositories - NTFS)", fill=(52, 211, 153))
    d.text((1450, 305), "29% Used", fill=(52, 211, 153))
    d.rectangle([(835, 335), (1535, 350)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.rectangle([(835, 335), (1038, 350)], fill=(16, 185, 129))
    d.text((835, 365), "Used: 418.4 GB  |  Free: 988.1 GB  |  Total: 1,406.5 GB", fill=(148, 163, 184))

    # Dropper Staging Zones Hunter Table
    d.rectangle([(25, 450), (1575, 940)], fill=(15, 23, 42), outline=(239, 68, 68), width=2)
    d.text((45, 465), "🚨 MALWARE DROPPER STAGING ZONE HUNTER (%TEMP%, APPDATA, WINDOWS TEMP)", fill=(248, 113, 113))
    d.text((45, 490), "Audits staging directories where trojans and spyware drop secondary payloads before execution.", fill=(148, 163, 184))

    # Clean Button
    d.rectangle([(1330, 465), (1555, 505)], fill=(239, 68, 68), outline=(239, 68, 68))
    d.text((1345, 478), "🧹 Clean Temp Droppers", fill=(255, 255, 255))

    # Table Header
    d.rectangle([(45, 525), (1555, 560)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.text((60, 535), "STAGING ZONE", fill=(148, 163, 184))
    d.text((280, 535), "FILE NAME", fill=(148, 163, 184))
    d.text((580, 535), "FULL SYSTEM PATH", fill=(148, 163, 184))
    d.text((1050, 535), "SIZE", fill=(148, 163, 184))
    d.text((1180, 535), "MODIFIED", fill=(148, 163, 184))
    d.text((1380, 535), "THREAT STATUS / ACTION", fill=(148, 163, 184))

    droppers = [
        ("User %TEMP%", "payload_dropper_stub.exe", "C:\\Users\\thann\\AppData\\Local\\Temp\\payload_dropper_stub.exe", "1,248 KB", "2026-11-07 09:12", "SUSPICIOUS DROPPER"),
        ("User %TEMP%", "update_agent_run.bat", "C:\\Users\\thann\\AppData\\Local\\Temp\\update_agent_run.bat", "14 KB", "2026-11-07 08:44", "SCRIPT / LOADER"),
        ("Public Directory", "reverse_shell_stage.ps1", "C:\\Users\\Public\\reverse_shell_stage.ps1", "38 KB", "2026-11-07 07:30", "SUSPICIOUS SCRIPT"),
        ("Windows System Temp", "msedge_installer_fak.dll", "C:\\Windows\\Temp\\msedge_installer_fak.dll", "512 KB", "2026-11-07 06:15", "MASQUERADED DLL"),
        ("User %TEMP%", "cache_helper_temp.vbs", "C:\\Users\\thann\\AppData\\Local\\Temp\\cache_helper_temp.vbs", "8 KB", "2026-11-07 05:02", "VBSCRIPT DROPPER")
    ]

    dy = 575
    for zone, fname, fpath, sz, mod, risk in droppers:
        d.rectangle([(45, dy), (1555, dy + 45)], fill=(19, 28, 49), outline=(30, 41, 59))
        d.text((60, dy + 12), zone, fill=(6, 182, 212))
        d.text((280, dy + 12), fname, fill=(255, 255, 255))
        d.text((580, dy + 12), fpath[:48] + "...", fill=(148, 163, 184))
        d.text((1050, dy + 12), sz, fill=(203, 213, 225))
        d.text((1180, dy + 12), mod, fill=(148, 163, 184))
        d.text((1380, dy + 12), risk, fill=(248, 113, 113))
        dy += 55

    img.save(SCREENSHOTS_DIR / "16_storage_dropper_hunter.png")
    print("[✓] Generated 16_storage_dropper_hunter.png")


def render_threat_tracking_ledger_view():
    """Render Screenshot 17: Persistent Suspicious Threat Tracking Ledger."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Threats")

    # Metrics
    cards = [
        ("ACTIVE PROCS", "148 PIDs", "CPU: 14% | RAM: 68%", (6, 182, 212), (255, 255, 255)),
        ("CRITICAL THREATS", "2 Severe", "Score ≥ 75 (Eradication Ready)", (239, 68, 68), (248, 113, 113)),
        ("SUSPICIOUS THREATS", "5 Tracked", "Scores: 20-74 (Heuristic Anomalies)", (245, 158, 11), (251, 191, 36)),
        ("HEALTH INDEX", "92% Secure", "Immutable Incident Chronicle", (16, 185, 129), (52, 211, 153))
    ]
    draw_metric_cards(d, cards)

    # Threat Sub-navigation highlighting Threat Tracking Ledger
    d.rectangle([(25, 240), (1575, 285)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.text((45, 252), "All Risks (7)", fill=(148, 163, 184))
    d.text((180, 252), "🚨 Critical (2)", fill=(248, 113, 113))
    d.text((320, 252), "⚠️ Suspicious (5)", fill=(251, 191, 36))
    
    # Active Ledger Pill
    d.rectangle([(470, 245), (710, 280)], fill=(99, 102, 241), outline=(99, 102, 241))
    d.text((485, 252), "📜 Threat Tracking Ledger (12)", fill=(255, 255, 255))
    d.text((740, 252), "🛡️ Blocked History (21)", fill=(6, 182, 212))

    # Ledger Container
    d.rectangle([(25, 300), (1575, 940)], fill=(15, 23, 42), outline=(99, 102, 241), width=2)
    d.text((45, 315), "📜 PERSISTENT THREAT TRACKING & ANOMALY LEDGER (HISTORICAL & ACTIVE)", fill=(129, 140, 248))
    d.text((45, 340), "Real-time audit log tracking suspicious and critical threats, detection timestamps, anomaly scores, and life cycle states.", fill=(148, 163, 184))

    # Ledger Table Header
    d.rectangle([(45, 375), (1555, 410)], fill=(11, 17, 30), outline=(30, 41, 59))
    d.text((60, 385), "TIMELINE (FIRST / LAST)", fill=(148, 163, 184))
    d.text((280, 385), "PID", fill=(148, 163, 184))
    d.text((360, 385), "THREAT NAME & EXECUTABLE PATH", fill=(148, 163, 184))
    d.text((760, 385), "SCORE / SEVERITY", fill=(148, 163, 184))
    d.text((960, 385), "CATEGORY & ANOMALIES", fill=(148, 163, 184))
    d.text((1300, 385), "STATUS", fill=(148, 163, 184))
    d.text((1440, 385), "ACTION", fill=(148, 163, 184))

    ledger_records = [
        ("08:12 -> 09:44 (8x)", "5824", "AnyDesk.exe (C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe)", "90 [CRITICAL]", "REMOTE CONTROL (Living-off-the-Land RMM Tool)", "ACTIVE (SYSTEM)", "Kill / Tree"),
        ("07:45 -> 09:40 (5x)", "14280", "svchost.exe (C:\\Users\\thann\\AppData\\Local\\Temp\\svchost.exe)", "95 [CRITICAL]", "MASQUERADING (Path Anomaly in %TEMP%)", "ACTIVE (FLAGGED)", "Kill Tree"),
        ("06:30 -> 09:35 (12x)", "21844", "powershell.exe (Encoded Base64 Payload -enc aW52...)", "65 [SUSPICIOUS]", "LOLBIN INVOCATION (Living-off-the-Land execution)", "ACTIVE", "Force Kill"),
        ("05:10 -> 08:20 (3x)", "19032", "curl_downloader.exe (Unverified signature, port 4444)", "55 [SUSPICIOUS]", "UNVERIFIED PE (Reverse socket outbound probe)", "ACTIVE", "Quarantine"),
        ("Yesterday 22:15", "8920", "fake_update.bat (C:\\Users\\Public\\fake_update.bat)", "70 [SUSPICIOUS]", "SUSPICIOUS SCRIPT (Executing from Public folder)", "ERADICATED", "Closed"),
        ("Yesterday 19:40", "1104", "crypto_miner_agent.exe (High CPU, stratum+tcp port)", "85 [CRITICAL]", "CRYPTOMINER (CoinMiner binary detected)", "QUARANTINED", "Isolate"),
        ("2026-11-05 14:10", "4412", "netcat_listener.exe (Reverse shell socket 127.0.0.1:4444)", "80 [CRITICAL]", "REVERSE TUNNEL (Unauthorized listener socket)", "ERADICATED", "Terminated")
    ]

    ly = 425
    for tline, pid, name_path, score, cat, stat, act in ledger_records:
        d.rectangle([(45, ly), (1555, ly + 50)], fill=(19, 28, 49), outline=(30, 41, 59))
        d.text((60, ly + 14), tline, fill=(148, 163, 184))
        d.text((280, ly + 14), pid, fill=(6, 182, 212))
        d.text((360, ly + 14), name_path[:45] + ("..." if len(name_path) > 45 else ""), fill=(255, 255, 255))
        d.text((760, ly + 14), score, fill=(248, 113, 113) if "CRITICAL" in score else (251, 191, 36))
        d.text((960, ly + 14), cat[:38] + "...", fill=(203, 213, 225))
        
        stat_col = (239, 68, 68) if "ACTIVE" in stat else ((16, 185, 129) if "ERADICATED" in stat else (139, 92, 246))
        d.text((1300, ly + 14), stat, fill=stat_col)
        d.text((1440, ly + 14), act, fill=(6, 182, 212))
        ly += 60

    img.save(SCREENSHOTS_DIR / "17_suspicious_threat_tracking_ledger.png")
    print("[✓] Generated 17_suspicious_threat_tracking_ledger.png")


def render_windows_services_view():
    """Render View 18: Windows Services Control Panel (services.msc)."""
    img = Image.new("RGB", (1600, 1000), color=(8, 12, 20))
    d = ImageDraw.Draw(img)
    draw_hud_header(d, "Windows Services (services.msc)")

    # Title Bar
    d.text((45, 135), "WINDOWS SERVICES MANAGEMENT PANEL (services.msc)", fill=(56, 189, 248))
    d.text((45, 155), "Live Windows Services discovery, process PID mapping, threat linkage, and administrative lifecycle controls.", fill=(148, 163, 184))

    # KPI Summary Cards
    d.rectangle([(45, 185), (395, 255)], fill=(15, 23, 42), outline=(56, 189, 248), width=1)
    d.text((60, 195), "TOTAL SERVICES", fill=(148, 163, 184))
    d.text((60, 218), "331", fill=(255, 255, 255))
    d.text((280, 210), "⚙️ System", fill=(56, 189, 248))

    d.rectangle([(425, 185), (775, 255)], fill=(15, 23, 42), outline=(16, 185, 129), width=1)
    d.text((440, 195), "RUNNING SERVICES", fill=(110, 231, 183))
    d.text((440, 218), "153", fill=(16, 185, 129))
    d.text((660, 210), "▶ Active", fill=(16, 185, 129))

    d.rectangle([(805, 185), (1155, 255)], fill=(15, 23, 42), outline=(100, 116, 139), width=1)
    d.text((820, 195), "STOPPED SERVICES", fill=(148, 163, 184))
    d.text((820, 218), "178", fill=(203, 213, 225))
    d.text((1040, 210), "⏹ Standby", fill=(148, 163, 184))

    d.rectangle([(1185, 185), (1555, 255)], fill=(15, 23, 42), outline=(239, 68, 68), width=2)
    d.text((1200, 195), "RMM / THREAT LINKED", fill=(248, 113, 113))
    d.text((1200, 218), "1 CRITICAL", fill=(239, 68, 68))
    d.text((1420, 210), "🚨 Alert", fill=(239, 68, 68))

    # Filter Toolbar
    d.rectangle([(45, 275), (1555, 325)], fill=(15, 23, 42), outline=(30, 41, 59))
    filter_pills = ["All (331)", "Running (153)", "Stopped (178)", "Automatic (88)", "Manual (182)", "Disabled (61)", "RMM / Threats (1)"]
    fx = 60
    for idx, f in enumerate(filter_pills):
        bg = (2, 132, 199) if idx == 0 else (30, 41, 59)
        col = (255, 255, 255) if idx == 0 else ((248, 113, 113) if "RMM" in f else (148, 163, 184))
        d.rectangle([(fx, 287), (fx + 120, 313)], fill=bg, outline=(71, 85, 105))
        d.text((fx + 10, 294), f, fill=col)
        fx += 135

    d.rectangle([(1200, 287), (1540, 313)], fill=(11, 17, 30), outline=(56, 189, 248))
    d.text((1215, 294), "🔍 Search service name, PID, or path...", fill=(100, 116, 139))

    # Services Table Header
    d.rectangle([(45, 345), (1555, 385)], fill=(15, 23, 42), outline=(30, 41, 59))
    d.text((60, 357), "STATUS", fill=(148, 163, 184))
    d.text((220, 357), "SERVICE NAME & DISPLAY TITLE", fill=(148, 163, 184))
    d.text((640, 357), "HOST PID", fill=(148, 163, 184))
    d.text((760, 357), "STARTUP TYPE", fill=(148, 163, 184))
    d.text((920, 357), "EXECUTABLE BINARY PATH", fill=(148, 163, 184))
    d.text((1420, 357), "ACTIONS", fill=(148, 163, 184))

    # Sample Services Data
    services_sample = [
        ("RMM / THREAT", (239, 68, 68), "AnyDesk", "AnyDesk Service", "PID 5824", "Automatic", "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe --service", "Stop | Restart"),
        ("RUNNING", (16, 185, 129), "WinDefend", "Microsoft Defender Antivirus Service", "PID 4820", "Automatic", "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\MsMpEng.exe", "Stop | Restart"),
        ("RUNNING", (16, 185, 129), "AISpeechService", "AISpeech Control Service", "PID 5812", "Automatic", "C:\\Windows\\System32\\DriverStore\\FileRepository\\AISControlService.exe", "Stop | Restart"),
        ("RUNNING", (16, 185, 129), "MpsSvc", "Windows Defender Firewall", "PID 2880", "Automatic", "C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p", "Stop | Restart"),
        ("STOPPED", (148, 163, 184), "wuauserv", "Windows Update", "—", "Manual", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "Start"),
        ("STOPPED", (148, 163, 184), "Spooler", "Print Spooler", "—", "Automatic", "C:\\Windows\\System32\\spoolsv.exe", "Start"),
        ("RUNNING", (16, 185, 129), "Appinfo", "Application Information", "PID 6816", "Manual", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "Stop | Restart"),
        ("STOPPED", (148, 163, 184), "AppVClient", "Microsoft App-V Client", "—", "Disabled", "C:\\Windows\\system32\\appvclient.exe", "Start"),
    ]

    sy = 395
    for stat_label, stat_color, sname, sdisp, pid_txt, stype, bpath, action_txt in services_sample:
        d.rectangle([(45, sy), (1555, sy + 62)], fill=(11, 17, 30), outline=(30, 41, 59))
        d.text((60, sy + 22), stat_label, fill=stat_color)
        d.text((220, sy + 12), sname, fill=(255, 255, 255))
        d.text((220, sy + 34), sdisp, fill=(148, 163, 184))
        d.text((640, sy + 22), pid_txt, fill=(56, 189, 248) if "PID" in pid_txt else (100, 116, 139))
        d.text((760, sy + 22), f"⚙️ {stype}", fill=(203, 213, 225))
        d.text((920, sy + 22), bpath[:52] + ("..." if len(bpath) > 52 else ""), fill=(148, 163, 184))
        
        # Action Buttons
        if "Stop" in action_txt:
            d.rectangle([(1400, sy + 15), (1455, sy + 47)], fill=(239, 68, 68, 40), outline=(239, 68, 68))
            d.text((1412, sy + 23), "Stop", fill=(248, 113, 113))
            d.rectangle([(1465, sy + 15), (1535, sy + 47)], fill=(56, 189, 248, 40), outline=(56, 189, 248))
            d.text((1475, sy + 23), "Restart", fill=(56, 189, 248))
        else:
            d.rectangle([(1400, sy + 15), (1465, sy + 47)], fill=(16, 185, 129, 40), outline=(16, 185, 129))
            d.text((1415, sy + 23), "Start", fill=(110, 231, 183))
        sy += 72

    img.save(SCREENSHOTS_DIR / "18_windows_services_control_panel.png")
    print("[✓] Generated 18_windows_services_control_panel.png")


def main():
    print("""
    ===============================================================
       AEGISSHIELD - HIGH-DEFINITION SCREENSHOT CAPTURE ENGINE
    ===============================================================
    """)
    print(f"[*] Target Directory: {SCREENSHOTS_DIR.resolve()}\n")

    render_threats_view()
    render_network_radar_view()
    render_adblocker_view()
    render_policy_rules_view()
    render_all_remaining_views()
    render_private_mode_view()
    render_light_mode_view()
    render_documentation_hub_view()
    render_elevated_kill_modal_view()
    render_system_diagnostics_view()
    render_storage_dropper_hunter_view()
    render_threat_tracking_ledger_view()
    render_windows_services_view()

    pngs = list(SCREENSHOTS_DIR.glob("*.png"))
    print(f"\n[✓] Successfully captured and generated all {len(pngs)} dashboard screenshots!")


if __name__ == "__main__":
    main()
