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
    """Render top cyber SOC navigation header and status badges."""
    # Top bar
    draw.rectangle([(0, 0), (1600, 75)], fill=(11, 17, 30), outline=(30, 41, 59))
    
    # Brand
    draw.rectangle([(25, 18), (65, 58)], fill=(15, 23, 42), outline=(6, 182, 212), width=2)
    draw.text((33, 24), "🛡", fill=(6, 182, 212))
    draw.text((80, 20), "AI Monitoring Engine • AdBlocker Engine • Web Tracker • Proc Mon Engine", fill=(255, 255, 255))
    draw.text((80, 44), "AEGISSHIELD EDR v2.5 | Autonomous Threat Hunter, Proxy Interceptor & Kernel Remediator", fill=(148, 163, 184))

    # Center Pill
    draw.rectangle([(820, 22), (1120, 52)], fill=(16, 185, 129, 30), outline=(16, 185, 129), width=1)
    draw.ellipse([(835, 33), (843, 41)], fill=(16, 185, 129))
    draw.text((855, 28), "SYSTEM SECURE | 2026-11-07 08:30:00", fill=(110, 231, 183))

    # Action buttons
    draw.rectangle([(1140, 22), (1240, 52)], fill=(139, 92, 246, 40), outline=(139, 92, 246), width=1)
    draw.text((1152, 29), "📧 Email", fill=(216, 180, 254))

    draw.rectangle([(1255, 22), (1350, 52)], fill=(6, 182, 212, 40), outline=(6, 182, 212))
    draw.text((1268, 29), "📚 Docs", fill=(103, 232, 249))

    draw.rectangle([(1365, 22), (1455, 52)], fill=(6, 182, 212), outline=(6, 182, 212))
    draw.text((1378, 29), "⚡ Scan", fill=(8, 12, 20))

    draw.rectangle([(1470, 22), (1575, 52)], fill=(239, 68, 68), outline=(239, 68, 68))
    draw.text((1482, 29), "🚨 KILL ALL", fill=(255, 255, 255))

    # Secondary Navigation Tab Bar
    draw.rectangle([(0, 75), (1600, 120)], fill=(8, 12, 20), outline=(30, 41, 59))
    tabs = [
        ("Threats", "Active Threats"),
        ("Network", "Network Radar"),
        ("AdBlock", "AdBlocker"),
        ("RMM", "RMM Hunter"),
        ("Processes", "Process Mon"),
        ("Policy", "Access Control"),
        ("Persistence", "Startup & Run"),
        ("Simulation", "Simulation Lab"),
        ("Email", "Email Alerts"),
        ("Audit", "Incident Audit"),
        ("Docs", "Documentation")
    ]

    x = 25
    for tid, tlabel in tabs:
        is_active = (tid.lower() in active_tab_title.lower())
        bg_col = (19, 28, 49) if is_active else (8, 12, 20)
        border_col = (6, 182, 212) if is_active else (30, 41, 59)
        text_col = (6, 182, 212) if is_active else (148, 163, 184)

        draw.rectangle([(x, 83), (x + 130, 119)], fill=bg_col, outline=border_col, width=2 if is_active else 1)
        draw.text((x + 10, 92), tlabel[:16], fill=text_col)
        x += 140

    # SOC Enterprise Footer Bar
    draw.rectangle([(0, 965), (1600, 1000)], fill=(11, 17, 30), outline=(30, 41, 59))
    draw.text((25, 975), "Process: python.exe (PID: 69360) | Ports: 8888, 8080 | Sub-Apps: AI Monitor: ON, AdBlock: ON, Web Tracker: ON, Proc Mon: ON", fill=(148, 163, 184))
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
    """Render 12: Light Clean SOC Mode (Daylight Theme)."""
    img = Image.new("RGB", (1600, 1000), color=(248, 250, 252))
    d = ImageDraw.Draw(img)

    # Header
    d.rectangle([(0, 0), (1600, 75)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.rectangle([(25, 18), (65, 58)], fill=(241, 245, 249), outline=(2, 132, 199), width=2)
    d.text((33, 24), "🛡", fill=(2, 132, 199))
    d.text((80, 22), "AEGISSHIELD EDR v2.0 (LIGHT SOC MODE)", fill=(15, 23, 42))
    d.text((80, 44), "Daylight Clean SOC Theme - All Subsystems Operational", fill=(100, 116, 139))

    # Center Pill
    d.rectangle([(620, 22), (980, 52)], fill=(236, 253, 245), outline=(16, 185, 129), width=1)
    d.ellipse([(635, 33), (643, 41)], fill=(16, 185, 129))
    d.text((655, 28), "SYSTEM PROTECTED & SECURE | 2026-11-07 07:55:00", fill=(5, 150, 105))

    # Header Buttons
    d.rectangle([(1020, 22), (1130, 52)], fill=(254, 243, 199), outline=(245, 158, 11))
    d.text((1035, 29), "🌙 Dark Mode", fill=(180, 83, 9))

    d.rectangle([(1145, 22), (1265, 52)], fill=(243, 232, 255), outline=(168, 85, 247))
    d.text((1158, 29), "📧 Email Report", fill=(126, 34, 206))

    d.rectangle([(1280, 22), (1390, 52)], fill=(2, 132, 199), outline=(2, 132, 199))
    d.text((1295, 29), "⚡ Deep Scan", fill=(255, 255, 255))

    d.rectangle([(1405, 22), (1575, 52)], fill=(239, 68, 68), outline=(220, 38, 38))
    d.text((1420, 29), "🚨 KILL ALL THREATS", fill=(255, 255, 255))

    # Tab bar
    d.rectangle([(0, 75), (1600, 120)], fill=(241, 245, 249), outline=(226, 232, 240))
    d.text((45, 90), "[Active Threats]", fill=(2, 132, 199))
    d.text((180, 90), "Network Radar", fill=(100, 116, 139))
    d.text((315, 90), "AdBlocker & Analytics", fill=(100, 116, 139))
    d.text((490, 90), "Remote Control Hunter", fill=(100, 116, 139))
    d.text((670, 90), "Process Monitor", fill=(100, 116, 139))

    # Metric Cards in Light Mode
    cards = [
        ("ACTIVE THREATS", "0 DETECTED", "All Host Trees Clean", (5, 150, 105)),
        ("SYSTEM HEALTH", "100%", "Optimal Security Integrity", (5, 150, 105)),
        ("ACTIVE PROCESSES", "144 RUNNING", "Verified Executable Paths", (2, 132, 199)),
        ("NETWORK SOCKETS", "18 MONITORED", "Legitimate CDN Endpoints", (2, 132, 199))
    ]
    cx = 25
    for title, val, sub, col in cards:
        d.rectangle([(cx, 140), (cx + 365, 235)], fill=(255, 255, 255), outline=(226, 232, 240))
        d.text((cx + 20, 155), title, fill=(100, 116, 139))
        d.text((cx + 20, 180), val, fill=col)
        d.text((cx + 20, 210), sub, fill=(148, 163, 184))
        cx += 395

    # Main Table
    d.rectangle([(25, 260), (1575, 960)], fill=(255, 255, 255), outline=(226, 232, 240))
    d.rectangle([(25, 260), (1575, 305)], fill=(241, 245, 249), outline=(226, 232, 240))

    d.text((45, 275), "PID & BINARY NAME", fill=(71, 85, 105))
    d.text((350, 275), "EXECUTABLE PATH & USER", fill=(71, 85, 105))
    d.text((1050, 275), "THREAT SCORE & HEURISTIC CLASSIFICATION", fill=(71, 85, 105))
    d.text((1420, 275), "STATUS BADGE", fill=(71, 85, 105))

    procs = [
        ("system (PID: 4)", "C:\\Windows\\System32\\ntoskrnl.exe | NT AUTHORITY\\SYSTEM", "Score: 0 - Verified OS Kernel Component", "SAFE", (5, 150, 105)),
        ("svchost.exe (PID: 1240)", "C:\\Windows\\System32\\svchost.exe | NETWORK SERVICE", "Score: 0 - Legitimate RPC Host Service", "SAFE", (5, 150, 105)),
        ("chrome.exe (PID: 4890)", "C:\\Program Files\\Google\\Chrome\\chrome.exe | User", "Score: 5 - Verified Digital Authenticode", "SAFE", (5, 150, 105)),
        ("python.exe (PID: 35612)", "C:\\Python314\\python.exe | User", "Score: 0 - AegisShield Daemon Process", "SAFE", (5, 150, 105))
    ]

    ry = 320
    for p1, p2, p3, badge, col in procs:
        d.line([(25, ry), (1575, ry)], fill=(241, 245, 249))
        d.text((45, ry + 15), p1, fill=(15, 23, 42))
        d.text((350, ry + 15), p2, fill=(51, 65, 85))
        d.text((1050, ry + 15), p3, fill=col)

        d.rectangle([(1420, ry + 8), (1540, ry + 36)], fill=(236, 253, 245), outline=col)
        d.text((1445, ry + 14), badge, fill=col)
        ry += 55

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

    pngs = list(SCREENSHOTS_DIR.glob("*.png"))
    print(f"\n[✓] Successfully captured and generated all {len(pngs)} dashboard screenshots!")


if __name__ == "__main__":
    main()
