"""
AegisShield - Web Browsing Analytics & Ad-Block Metrics
Computes browsing metrics, top visited sites, blocked ad networks,
category distributions, and bandwidth savings.
"""

from collections import Counter
from typing import Dict, List, Any
from .web_traffic_logger import WebTrafficLogger


class WebAnalytics:
    """Calculates comprehensive web traffic and ad-blocking statistics."""

    def __init__(self):
        self.logger = WebTrafficLogger()

    def get_analytics(self) -> Dict[str, Any]:
        """Aggregate real-time metrics across all logged web traffic."""
        logs = self.logger.get_logs(limit=3000)

        total_requests = len(logs)
        total_blocked = sum(1 for r in logs if r["is_blocked"])
        total_allowed = total_requests - total_blocked

        block_rate = round((total_blocked / total_requests * 100), 1) if total_requests > 0 else 0.0

        # Estimated bandwidth saved (approx 250 KB per blocked ad/tracker banner/script)
        mb_saved = round((total_blocked * 256) / 1024, 2)

        # Top Visited Clean Domains
        clean_domains = [r["domain"] for r in logs if not r["is_blocked"]]
        top_clean = Counter(clean_domains).most_common(10)
        top_visited = [{"domain": d, "count": count} for d, count in top_clean]

        # Top Blocked Ad Domains
        blocked_domains = [r["domain"] for r in logs if r["is_blocked"]]
        top_bad = Counter(blocked_domains).most_common(10)
        top_blocked = [{"domain": d, "count": count} for d, count in top_bad]

        # Categorical Distribution
        categories = Counter(r["category"] for r in logs)
        category_breakdown = [{"category": cat, "count": count} for cat, count in categories.most_common()]

        # Activity Timeline (Group by Date Hour or Date Minute)
        time_counts = Counter(r["date_time"][:13] + ":00" for r in logs)  # e.g. "2026-11-07 07:00"
        timeline = [{"time": t, "count": count} for t, count in sorted(time_counts.items())[-12:]]

        return {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "total_allowed": total_allowed,
            "block_rate_percent": block_rate,
            "estimated_mb_saved": mb_saved,
            "top_visited_domains": top_visited,
            "top_blocked_domains": top_blocked,
            "category_breakdown": category_breakdown,
            "timeline": timeline
        }

