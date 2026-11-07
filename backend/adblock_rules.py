"""
AegisShield - Curated Ad, Tracker, Telemetry & Malware Domain Rules
Derived from StevenBlack/hosts, EasyList, AdGuard DNS, and Peter Lowe's Blocklist.
Provides sub-domain and wildcard pattern matching with O(1) domain set lookup.
"""

from typing import Set, Tuple, Dict, Any

# Primary Advertising Networks & Exchanges
AD_DOMAINS: Set[str] = {
    # Google Ad Ecosystem
    "doubleclick.net", "adservice.google.com", "pagead2.googlesyndication.com",
    "googleadservices.com", "tpc.googlesyndication.com", "partnerad.l.google.com",
    "admob.com", "googleads.g.doubleclick.net", "afs.googlesyndication.com",
    
    # Major Commercial Ad Networks & Supply-Side Platforms
    "adnxs.com", "ib.adnxs.com", "secure.adnxs.com",
    "criteo.com", "static.criteo.net", "bidder.criteo.com",
    "taboola.com", "trc.taboola.com", "cdn.taboola.com",
    "outbrain.com", "widgets.outbrain.com", "log.outbrain.com",
    "pubmatic.com", "ads.pubmatic.com",
    "rubiconproject.com", "optimized-by.rubiconproject.com",
    "openx.net", "us-u.openx.net",
    "casalemedia.com", "popads.net", "propellerads.com",
    "mgid.com", "revcontent.com", "adroll.com", "smartadserver.com",
    "bidswitch.net", "moatads.com", "yieldmo.com", "inmobi.com",
    "adcolony.com", "applovin.com", "unityads.unity3d.com", "ironsrc.com",
    "exponential.com", "sovrn.com", "media.net", "adtechus.com",
    "zergnet.com", "adblade.com", "sharethrough.com", "triplelift.com",
    "gumgum.com", "teads.tv", "conversantmedia.com", "clicksor.com"
}

# Behavioral Trackers, Analytics & Fingerprinting Endpoints
TRACKER_DOMAINS: Set[str] = {
    # Analytics & Behavioral Tracking
    "google-analytics.com", "ssl.google-analytics.com", "analytics.google.com",
    "hotjar.com", "static.hotjar.com", "script.hotjar.com",
    "clarity.ms", "c.clarity.ms",
    "segment.io", "api.segment.io", "cdn.segment.com",
    "mixpanel.com", "api.mixpanel.com",
    "amplitude.com", "api.amplitude.com",
    "crazyegg.com", "script.crazyegg.com",
    "fullstory.com", "rs.fullstory.com",
    "quantserve.com", "pixel.quantserve.com",
    "scorecardresearch.com", "sb.scorecardresearch.com",
    "chartbeat.com", "static.chartbeat.com",
    "newrelic.com", "bam.nr-data.net", "js-agent.newrelic.com",
    "heap.io", "heapanalytics.com", "cdn.heapanalytics.com",
    "kissmetrics.com", "mouseflow.com", "luckyorange.com",
    
    # Social Tracking & Retargeting Pixels
    "pixel.facebook.com", "an.facebook.com", "analytics.tiktok.com",
    "ads.twitter.com", "analytics.twitter.com", "ads-twitter.com",
    "pixel.wp.com", "stats.wp.com", "ad.pinterest.com",
    "snap.licdn.com", "tr.snapchat.com", "sc-static.net"
}

# Device Telemetry & Diagnostic Snooping
TELEMETRY_DOMAINS: Set[str] = {
    "telemetry.microsoft.com", "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com", "watson.telemetry.microsoft.com",
    "telemetry.urs.microsoft.com", "diagnostics.support.microsoft.com",
    "feedback.microsoft.com", "pipe.aria.microsoft.com",
    "metrics.icloud.com", "diagnostics.apple.com",
    "telemetry.mozilla.org", "incoming.telemetry.mozilla.org"
}

# Malware, Crypto-mining & Phishing Domains
MALWARE_DOMAINS: Set[str] = {
    "coinhive.com", "coin-hive.com", "authedmine.com", "crypto-loot.com",
    "minr.pw", "webminepool.com", "jsecoin.com", "cryptoloot.pro",
    "tracking-click.online", "malware-traffic-analysis.net", "ransomware-tracker.test"
}

# Substring / Keyword triggers for ad blocking
AD_KEYWORD_PATTERNS = [
    "-analytics.", "analytics.", "googleads", "pagead", "doubleclick",
    "adservice", "adsystem", "adnxs", "tracking-pixel", "adserver",
    "adtech", "affiliate-tracking", "popads", "propellerads",
    "/ads/", "adclick.", "adserver.", "adlog.", "beacon."
]


def check_domain_reputation(domain: str) -> Tuple[bool, str, str]:
    """
    Evaluate if a domain should be blocked.
    Returns: (is_blocked: bool, category: str, reason: str)
    """
    if not domain:
        return False, "CLEAN", "Empty domain"

    clean_domain = domain.lower().split(":")[0].strip().rstrip(".")

    # Exact match in Malware
    if clean_domain in MALWARE_DOMAINS:
        return True, "MALWARE / SCAM", "Known malicious or crypto-mining domain"

    # Exact match in Ads
    if clean_domain in AD_DOMAINS:
        return True, "AD / TRACKER", f"Known commercial advertising network: {clean_domain}"

    # Exact match in Trackers
    if clean_domain in TRACKER_DOMAINS:
        return True, "TRACKER / ANALYTICS", f"Behavioral tracking / analytics beacon: {clean_domain}"

    # Exact match in Telemetry
    if clean_domain in TELEMETRY_DOMAINS:
        return True, "TELEMETRY", f"Device telemetry & diagnostics endpoint: {clean_domain}"

    # Sub-domain matching (e.g., 'ad.doubleclick.net' -> 'doubleclick.net')
    parts = clean_domain.split(".")
    if len(parts) >= 2:
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in AD_DOMAINS:
                return True, "AD / TRACKER", f"Sub-domain of blocked ad network: {parent}"
            if parent in TRACKER_DOMAINS:
                return True, "TRACKER / ANALYTICS", f"Sub-domain of tracking service: {parent}"
            if parent in TELEMETRY_DOMAINS:
                return True, "TELEMETRY", f"Sub-domain of telemetry endpoint: {parent}"
            if parent in MALWARE_DOMAINS:
                return True, "MALWARE / SCAM", f"Sub-domain of malware host: {parent}"

    # Keyword heuristic matching
    for kw in AD_KEYWORD_PATTERNS:
        if kw in clean_domain:
            return True, "AD / TRACKER", f"Matches advertising/tracking keyword: {kw}"

    return False, "CLEAN / ALLOWED", "Domain is verified or not on blocklists"

