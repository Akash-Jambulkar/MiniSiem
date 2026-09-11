"""Slack Incoming Webhook alerter. Formats a rich block-kit message."""
from __future__ import annotations

import os
from typing import Optional

import requests

from ..utils.logger import get_logger

log = get_logger("mini_siem.alerting.slack")


class SlackAlerter:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
        self.enabled = bool(self.webhook)

    def send(self, alert: dict) -> None:
        if not self.enabled:
            return
        sev = (alert.get("severity") or "medium").upper()
        emoji = {"LOW": ":information_source:", "MEDIUM": ":warning:",
                 "HIGH": ":rotating_light:", "CRITICAL": ":sos:"}.get(sev, ":warning:")
        enrichment = alert.get("enrichment") or {}
        enrichment_line = ""
        if enrichment:
            enrichment_line = (
                f"*Abuse score:* {enrichment.get('abuse_confidence_score')} | "
                f"*Country:* {enrichment.get('country_code')} | "
                f"*ISP:* {enrichment.get('isp')}"
            )

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} Mini-SIEM Alert: {alert.get('rule_name')}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:* {sev}"},
                        {"type": "mrkdwn", "text": f"*MITRE:* {alert.get('mitre')}"},
                        {"type": "mrkdwn", "text": f"*Source IP:* {alert.get('source_ip')}"},
                        {"type": "mrkdwn", "text": f"*User:* {alert.get('user')}"},
                        {"type": "mrkdwn", "text": f"*Count:* {alert.get('match_count')}"},
                        {"type": "mrkdwn", "text": f"*When:* {alert.get('timestamp')}"},
                    ],
                },
            ]
        }
        if enrichment_line:
            payload["blocks"].append(
                {"type": "section", "text": {"type": "mrkdwn", "text": enrichment_line}}
            )
        payload["blocks"].append(
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f":memo: {alert.get('description')}"}
            ]}
        )

        try:
            requests.post(self.webhook, json=payload, timeout=6)
        except Exception as exc:
            log.warning("Slack webhook failed: %s", exc)
