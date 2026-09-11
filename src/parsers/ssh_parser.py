"""Linux auth.log SSH parser.

Extracts failed logins, accepted logins, and account creation events into an
ECS-flavored schema: {timestamp, source_ip, user, event_type, source, raw}.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

# Failed: "Failed password for [invalid user ]<user> from <ip> port <n> ssh2"
_SSH_FAIL = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Accepted: "Accepted password for <user> from <ip> port <n> ssh2"
_SSH_OK = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# New user creation: "useradd[1234]: new user: name=alice, ..."
_USERADD = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+useradd\[\d+\]:\s+new user: name=(?P<user>\S+?),"
)


def _parse_syslog_ts(raw: str) -> str:
    """Syslog timestamps omit the year. Assume current year, return ISO 8601 UTC."""
    try:
        year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def parse_ssh_line(line: str) -> dict | None:
    m = _SSH_FAIL.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "event_type": "ssh_failed_login",
            "user": m.group("user"),
            "source_ip": m.group("ip"),
            "source": "auth.log",
            "raw": line.strip(),
        }
    m = _SSH_OK.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "event_type": "ssh_accepted_login",
            "user": m.group("user"),
            "source_ip": m.group("ip"),
            "source": "auth.log",
            "raw": line.strip(),
        }
    m = _USERADD.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "event_type": "user_created",
            "user": m.group("user"),
            "source_ip": None,
            "source": "auth.log",
            "raw": line.strip(),
        }
    return None
