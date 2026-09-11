"""SQLite-backed enrichment cache to respect API rate limits.

AbuseIPDB free tier is 1,000 checks/day; caching by IP is essential.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional


class EnrichmentCache:
    def __init__(self, path: str | Path = "enrichment_cache.sqlite", ttl_seconds: int = 86_400):
        self.path = str(path)
        self.ttl = ttl_seconds
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enrichment (
                    provider TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    fetched_at INTEGER NOT NULL,
                    PRIMARY KEY (provider, key)
                )
                """
            )

    def get(self, provider: str, key: str) -> Optional[dict]:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT value, fetched_at FROM enrichment WHERE provider = ? AND key = ?",
                (provider, key),
            ).fetchone()
        if not row:
            return None
        value, fetched_at = row
        if time.time() - fetched_at > self.ttl:
            return None
        return json.loads(value)

    def set(self, provider: str, key: str, value: dict) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "REPLACE INTO enrichment (provider, key, value, fetched_at) VALUES (?, ?, ?, ?)",
                (provider, key, json.dumps(value), int(time.time())),
            )
