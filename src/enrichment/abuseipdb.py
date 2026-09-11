"""AbuseIPDB IP-reputation enrichment.

Free tier: 1,000 checks/day (limiter resets at 00:00 UTC). Cache aggressively.
Returns None if no API key is configured or on network failure - detection
still runs; enrichment is optional context.
"""
from __future__ import annotations

import os
from typing import Optional

import requests

from ..utils.logger import get_logger
from .cache import EnrichmentCache

log = get_logger("mini_siem.enrichment.abuseipdb")

_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher:
    def __init__(self, api_key: str | None = None, cache: EnrichmentCache | None = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.cache = cache or EnrichmentCache()
        self.enabled = bool(self.api_key)

    def enrich(self, ip: str) -> Optional[dict]:
        if not ip:
            return None
        cached = self.cache.get("abuseipdb", ip)
        if cached is not None:
            return cached
        if not self.enabled:
            return None
        try:
            r = requests.get(
                _URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=8,
            )
            r.raise_for_status()
            data = r.json().get("data", {})
        except Exception as exc:
            log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None

        result = {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "usage_type": data.get("usageType"),
        }
        self.cache.set("abuseipdb", ip, result)
        return result
