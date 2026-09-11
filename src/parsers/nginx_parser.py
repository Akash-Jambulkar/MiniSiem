"""Nginx / Apache combined-log format parser."""
from __future__ import annotations

import re
from datetime import datetime

_NGINX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) \S+ \S+ '
    r'\[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)


def _parse_ts(raw: str) -> str:
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()


def parse_nginx_line(line: str) -> dict | None:
    m = _NGINX.search(line)
    if not m:
        return None
    status = int(m.group("status"))
    path = m.group("path")
    method = m.group("method")

    if method == "POST" and "/login" in path and status in (401, 403):
        event_type = "web_login_failed"
    elif method == "POST" and "/login" in path and status in (200, 302):
        event_type = "web_login_success"
    else:
        event_type = "web_request"

    return {
        "timestamp": _parse_ts(m.group("ts")),
        "event_type": event_type,
        "source_ip": m.group("ip"),
        "http_method": method,
        "http_path": path,
        "http_status": status,
        "user_agent": m.group("agent"),
        "source": "nginx",
        "raw": line.strip(),
    }
