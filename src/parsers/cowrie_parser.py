"""Cowrie SSH honeypot JSON log parser."""
from __future__ import annotations

import json


_LOGIN_FAIL = "cowrie.login.failed"
_LOGIN_OK = "cowrie.login.success"
_CMD = "cowrie.command.input"


def parse_cowrie_line(line: str) -> dict | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    eid = entry.get("eventid")
    ip = entry.get("src_ip")
    user = entry.get("username")
    ts = entry.get("timestamp")

    if eid == _LOGIN_FAIL:
        return {
            "timestamp": ts,
            "event_type": "ssh_failed_login",
            "user": user,
            "source_ip": ip,
            "source": "cowrie",
            "raw": line,
        }
    if eid == _LOGIN_OK:
        return {
            "timestamp": ts,
            "event_type": "ssh_accepted_login",
            "user": user,
            "source_ip": ip,
            "source": "cowrie",
            "raw": line,
        }
    if eid == _CMD:
        return {
            "timestamp": ts,
            "event_type": "attacker_command",
            "user": user,
            "source_ip": ip,
            "command": entry.get("input"),
            "source": "cowrie",
            "raw": line,
        }
    return None
