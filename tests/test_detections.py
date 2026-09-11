from datetime import datetime, timedelta, timezone

from src.detections.engine import DetectionEngine


def _ev(event_type: str, ip: str, user: str, seconds_offset: int = 0, **extra) -> dict:
    ts = datetime(2026, 3, 5, 2, 14, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds_offset)
    return {
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "source_ip": ip,
        "user": user,
        **extra,
    }


def test_threshold_rule_fires_on_bruteforce():
    rule = {
        "id": "bf", "name": "BF", "severity": "high", "mitre": "T1110.001",
        "logic": {"type": "threshold", "match": {"event_type": "ssh_failed_login"},
                  "group_by": "source_ip", "window_seconds": 60, "threshold": 5},
    }
    engine = DetectionEngine([rule])
    alerts = []
    for i in range(6):
        alerts += engine.process(_ev("ssh_failed_login", "1.1.1.1", "root", i * 5))
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "bf"
    assert alerts[0]["match_count"] >= 5


def test_threshold_rule_does_not_fire_below_threshold():
    rule = {
        "id": "bf", "name": "BF", "severity": "high",
        "logic": {"type": "threshold", "match": {"event_type": "ssh_failed_login"},
                  "group_by": "source_ip", "window_seconds": 60, "threshold": 5},
    }
    engine = DetectionEngine([rule])
    alerts = []
    for i in range(4):
        alerts += engine.process(_ev("ssh_failed_login", "1.1.1.1", "root", i * 5))
    assert alerts == []


def test_distinct_users_password_spraying():
    rule = {
        "id": "spray", "name": "Spray", "severity": "high",
        "logic": {"type": "distinct_users", "match": {"event_type": "ssh_failed_login"},
                  "group_by": "source_ip", "distinct_field": "user",
                  "window_seconds": 600, "threshold": 5},
    }
    engine = DetectionEngine([rule])
    alerts = []
    for i, u in enumerate(["a", "b", "c", "d", "e"]):
        alerts += engine.process(_ev("ssh_failed_login", "2.2.2.2", u, i * 10))
    assert len(alerts) == 1
    assert alerts[0]["distinct_count"] == 5


def test_conditional_successful_bruteforce():
    rule = {
        "id": "sbf", "name": "SBF", "severity": "critical",
        "logic": {"type": "conditional",
                  "match": {"event_type": "ssh_failed_login"},
                  "follow_match": {"event_type": "ssh_accepted_login"},
                  "group_by": "source_ip", "window_seconds": 120, "threshold": 5},
    }
    engine = DetectionEngine([rule])
    alerts = []
    for i in range(5):
        alerts += engine.process(_ev("ssh_failed_login", "3.3.3.3", "root", i * 2))
    alerts += engine.process(_ev("ssh_accepted_login", "3.3.3.3", "root", 20))
    assert any(a["rule_id"] == "sbf" for a in alerts)


def test_field_match_regex_user_agent():
    rule = {
        "id": "ua", "name": "UA", "severity": "medium",
        "logic": {"type": "field_match",
                  "match": {"user_agent": {"regex": "(sqlmap|nikto)"}}},
    }
    engine = DetectionEngine([rule])
    ev = _ev("web_request", "4.4.4.4", None, 0)
    ev["user_agent"] = "sqlmap/1.7"
    alerts = engine.process(ev)
    assert len(alerts) == 1

    ev2 = _ev("web_request", "4.4.4.4", None, 0)
    ev2["user_agent"] = "Mozilla/5.0"
    assert engine.process(ev2) == []


def test_cooldown_dedupes_repeated_alerts():
    rule = {
        "id": "bf", "name": "BF", "severity": "high",
        "logic": {"type": "threshold", "match": {"event_type": "ssh_failed_login"},
                  "group_by": "source_ip", "window_seconds": 60, "threshold": 3},
    }
    engine = DetectionEngine([rule])
    alerts = []
    for i in range(10):
        alerts += engine.process(_ev("ssh_failed_login", "5.5.5.5", "root", i))
    # Only one alert should fire within the cooldown window even though threshold is
    # exceeded on every subsequent event.
    assert len(alerts) == 1
