from .ssh_parser import parse_ssh_line
from .nginx_parser import parse_nginx_line
from .cowrie_parser import parse_cowrie_line

__all__ = ["parse_ssh_line", "parse_nginx_line", "parse_cowrie_line", "parse_any"]


def parse_any(line: str, source: str = "auto") -> dict | None:
    """Try each parser; return the first structured event that matches."""
    if source in ("auto", "ssh", "auth"):
        ev = parse_ssh_line(line)
        if ev:
            return ev
    if source in ("auto", "nginx", "apache", "web"):
        ev = parse_nginx_line(line)
        if ev:
            return ev
    if source in ("auto", "cowrie"):
        ev = parse_cowrie_line(line)
        if ev:
            return ev
    return None
