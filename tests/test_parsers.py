from src.parsers import parse_any
from src.parsers.ssh_parser import parse_ssh_line
from src.parsers.nginx_parser import parse_nginx_line
from src.parsers.cowrie_parser import parse_cowrie_line


def test_ssh_failed_login():
    line = ("Mar  5 02:14:00 victim-01 sshd[2000]: "
            "Failed password for root from 203.0.113.42 port 40000 ssh2")
    ev = parse_ssh_line(line)
    assert ev is not None
    assert ev["event_type"] == "ssh_failed_login"
    assert ev["source_ip"] == "203.0.113.42"
    assert ev["user"] == "root"


def test_ssh_invalid_user_login():
    line = ("Mar  5 02:14:08 victim-01 sshd[2004]: "
            "Failed password for invalid user test from 203.0.113.42 port 40004 ssh2")
    ev = parse_ssh_line(line)
    assert ev is not None
    assert ev["user"] == "test"


def test_ssh_accepted_login():
    line = ("Mar  5 02:14:45 victim-01 sshd[2100]: "
            "Accepted password for root from 203.0.113.42 port 40099 ssh2")
    ev = parse_ssh_line(line)
    assert ev is not None
    assert ev["event_type"] == "ssh_accepted_login"


def test_useradd_event():
    line = ("Mar  5 02:15:30 victim-01 useradd[2101]: "
            "new user: name=svcbackup, UID=0, GID=0, home=/root, shell=/bin/bash")
    ev = parse_ssh_line(line)
    assert ev is not None
    assert ev["event_type"] == "user_created"
    assert ev["user"] == "svcbackup"


def test_nginx_credential_stuffing():
    line = ('203.0.113.99 - - [05/Mar/2026:03:00:00 +0000] '
            '"POST /login HTTP/1.1" 401 48 "-" "python-requests/2.31.0"')
    ev = parse_nginx_line(line)
    assert ev is not None
    assert ev["event_type"] == "web_login_failed"
    assert ev["source_ip"] == "203.0.113.99"


def test_nginx_scanner_ua():
    line = ('198.51.100.221 - - [05/Mar/2026:03:02:00 +0000] '
            '"GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.7.11#stable"')
    ev = parse_nginx_line(line)
    assert ev is not None
    assert "sqlmap" in ev["user_agent"]


def test_cowrie_login_failed():
    line = ('{"timestamp": "2026-03-05T04:00:00Z", "eventid": "cowrie.login.failed", '
            '"src_ip": "203.0.113.42", "username": "root", "password": "123456", "session": "s1"}')
    ev = parse_cowrie_line(line)
    assert ev is not None
    assert ev["event_type"] == "ssh_failed_login"


def test_cowrie_command():
    line = ('{"timestamp": "2026-03-05T04:00:35Z", "eventid": "cowrie.command.input", '
            '"src_ip": "203.0.113.42", "username": "root", "input": "uname -a", "session": "s1"}')
    ev = parse_cowrie_line(line)
    assert ev is not None
    assert ev["event_type"] == "attacker_command"
    assert ev["command"] == "uname -a"


def test_parse_any_dispatch():
    ssh_line = ("Mar  5 02:14:00 h sshd[1]: "
                "Failed password for root from 203.0.113.42 port 1 ssh2")
    assert parse_any(ssh_line)["event_type"] == "ssh_failed_login"

    web_line = ('203.0.113.99 - - [05/Mar/2026:03:00:00 +0000] '
                '"GET /index.html HTTP/1.1" 200 1 "-" "curl/8"')
    assert parse_any(web_line)["event_type"] == "web_request"

    assert parse_any("garbage") is None
