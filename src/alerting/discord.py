"""Discord webhook alerter."""
from __future__ import annotations

import os
from typing import Optional

import requests

from ..utils.logger import get_logger

log = get_logger("mini_siem.alerting.discord")

_COLOR = {"low": 0x3498DB, "medium": 0xF1C40F, "high": 0xE67E22, "critical": 0xE74C3C}


class DiscordAlerter:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.enabled = bool(self.webhook)

    def send(self, alert: dict) -> None:
        if not self.enabled:
            return
        sev = alert.get("severity", "medium")
        enrichment = alert.get("enrichment") or {}

        fields = [
            {"name": "Severity", "value": sev.upper(), "inline": True},
            {"name": "MITRE", "value": str(alert.get("mitre")), "inline": True},
            {"name": "Source IP", "value": str(alert.get("source_ip")), "inline": True},
            {"name": "User", "value": str(alert.get("user")), "inline": True},
            {"name": "Match count", "value": str(alert.get("match_count")), "inline": True},
            {"name": "Timestamp", "value": str(alert.get("timestamp")), "inline": True},
        ]
        if enrichment:
            fields.append({
                "name": "AbuseIPDB",
                "value": (
                    f"Score: {enrichment.get('abuse_confidence_score')} | "
                    f"Country: {enrichment.get('country_code')} | "
                    f"ISP: {enrichment.get('isp')}"
                ),
                "inline": False,
            })

        payload = {
            "embeds": [
                {
                    "title": f"Mini-SIEM Alert: {alert.get('rule_name')}",
                    "description": alert.get("description"),
                    "color": _COLOR.get(sev, 0xF1C40F),
                    "fields": fields,
                }
            ]
        }
        try:
            requests.post(self.webhook, json=payload, timeout=6)
        except Exception as exc:
            log.warning("Discord webhook failed: %s", exc)
