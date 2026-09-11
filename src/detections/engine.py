"""Detection engine: sliding-window rules over structured events.

A rule is a YAML dict with these fields:

    id: ssh_bruteforce
    name: SSH brute force
    description: >=5 failed SSH logins from same IP in 60s
    severity: high
    mitre: T1110.001
    logic:
      type: threshold          # threshold | conditional | distinct_users | field_match
      match:                   # event fields that must match (exact or "in" list)
        event_type: ssh_failed_login
      group_by: source_ip
      window_seconds: 60
      threshold: 5

Supported rule logic types:
    threshold        - N matching events from same group in W seconds
    distinct_users   - N distinct values of `distinct_field` in W seconds (spraying)
    conditional      - N of type A followed by >=1 of type B in W seconds (successful BF)
    field_match      - single event matches a field predicate (regex / value / in-list)
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional


def _parse_iso(ts: str | None) -> float:
    if not ts:
        return datetime.now(timezone.utc).timestamp()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


def _event_matches(event: dict, match: dict | None) -> bool:
    if not match:
        return True
    for key, expected in match.items():
        actual = event.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, dict) and "regex" in expected:
            if actual is None or not re.search(expected["regex"], str(actual), re.IGNORECASE):
                return False
        else:
            if actual != expected:
                return False
    return True


class DetectionEngine:
    def __init__(self, rules: List[dict]):
        self.rules = rules
        # Per-rule state: {rule_id: {group_key: deque[(ts, event)]}}
        self._state: Dict[str, Dict[Any, Deque]] = defaultdict(lambda: defaultdict(deque))
        # Cooldown to dedupe repeated alerts for the same key within window.
        self._last_alert: Dict[str, Dict[Any, float]] = defaultdict(dict)

    def process(self, event: dict) -> List[dict]:
        """Feed one event through all rules; return list of alerts fired."""
        alerts: List[dict] = []
        now = _parse_iso(event.get("timestamp"))
        for rule in self.rules:
            alert = self._apply_rule(rule, event, now)
            if alert:
                alerts.append(alert)
        return alerts

    def _apply_rule(self, rule: dict, event: dict, now: float) -> Optional[dict]:
        logic = rule.get("logic", {})
        rtype = logic.get("type", "threshold")

        if rtype == "field_match":
            if _event_matches(event, logic.get("match")):
                return self._build_alert(rule, event, count=1, extra={})
            return None

        if not _event_matches(event, logic.get("match")):
            # For conditional rules, we still care about the "trigger" branch.
            if rtype != "conditional":
                return None

        window = int(logic.get("window_seconds", 60))
        group_by = logic.get("group_by", "source_ip")
        key = event.get(group_by)
        if key is None:
            return None

        state = self._state[rule["id"]][key]
        state.append((now, event))
        while state and now - state[0][0] > window:
            state.popleft()

        if rtype == "threshold":
            threshold = int(logic.get("threshold", 5))
            if len(state) >= threshold:
                if self._should_alert(rule["id"], key, now, window):
                    return self._build_alert(
                        rule, event, count=len(state), extra={"group_key": key}
                    )

        elif rtype == "distinct_users":
            threshold = int(logic.get("threshold", 10))
            field = logic.get("distinct_field", "user")
            distinct = {ev.get(field) for _, ev in state if ev.get(field)}
            if len(distinct) >= threshold:
                if self._should_alert(rule["id"], key, now, window):
                    return self._build_alert(
                        rule,
                        event,
                        count=len(state),
                        extra={
                            "group_key": key,
                            "distinct_users": sorted(distinct)[:20],
                            "distinct_count": len(distinct),
                        },
                    )

        elif rtype == "conditional":
            # Rule requires N of `match` type A and >=1 of `follow_match` type B.
            follow_match = logic.get("follow_match")
            threshold = int(logic.get("threshold", 5))
            a_events = [ev for _, ev in state if _event_matches(ev, logic.get("match"))]
            b_events = [ev for _, ev in state if _event_matches(ev, follow_match)]
            if len(a_events) >= threshold and b_events:
                if self._should_alert(rule["id"], key, now, window):
                    return self._build_alert(
                        rule,
                        event,
                        count=len(a_events),
                        extra={
                            "group_key": key,
                            "success_user": b_events[-1].get("user"),
                            "failed_attempts": len(a_events),
                        },
                    )

        elif rtype == "distinct_ports":
            threshold = int(logic.get("threshold", 15))
            field = logic.get("distinct_field", "dest_port")
            distinct = {ev.get(field) for _, ev in state if ev.get(field) is not None}
            if len(distinct) >= threshold:
                if self._should_alert(rule["id"], key, now, window):
                    return self._build_alert(
                        rule,
                        event,
                        count=len(state),
                        extra={
                            "group_key": key,
                            "distinct_ports": sorted(distinct)[:30],
                            "distinct_count": len(distinct),
                        },
                    )

        return None

    def _should_alert(self, rule_id: str, key: Any, now: float, window: int) -> bool:
        last = self._last_alert[rule_id].get(key, 0.0)
        if now - last < window:
            return False
        self._last_alert[rule_id][key] = now
        return True

    def _build_alert(self, rule: dict, event: dict, count: int, extra: dict) -> dict:
        return {
            "timestamp": event.get("timestamp"),
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name"),
            "description": rule.get("description"),
            "severity": rule.get("severity", "medium"),
            "mitre": rule.get("mitre"),
            "mitre_tactic": rule.get("mitre_tactic"),
            "source_ip": event.get("source_ip"),
            "user": event.get("user"),
            "event_type": event.get("event_type"),
            "match_count": count,
            "trigger_event": event,
            **extra,
        }
