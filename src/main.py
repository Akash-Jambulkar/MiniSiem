"""Mini-SIEM entrypoint.

Usage:
    python -m src.main --input data/samples/auth.log --source ssh
    python -m src.main --input data/samples/nginx_access.log --source nginx
    python -m src.main --input data/samples/cowrie.json --source cowrie --follow
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List

from dotenv import load_dotenv

from .alerting import ConsoleAlerter, DiscordAlerter, SlackAlerter
from .collectors.file_tailer import follow, read_batch
from .detections import DetectionEngine, load_rules
from .enrichment import AbuseIPDBEnricher
from .parsers import parse_any
from .utils.logger import get_logger

log = get_logger("mini_siem.main")

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _should_alert(sev: str, min_sev: str) -> bool:
    return _SEVERITY_ORDER.get(sev, 1) >= _SEVERITY_ORDER.get(min_sev, 1)


def _write_jsonl(path: str | Path, record: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def run(
    input_path: str,
    source: str,
    follow_file: bool,
    rules_dir: str,
    enrich: bool,
    min_severity: str,
    events_out: str,
    alerts_out: str,
) -> int:
    rules = load_rules(rules_dir)
    log.info("Loaded %d detection rules from %s", len(rules), rules_dir)
    engine = DetectionEngine(rules)
    console = ConsoleAlerter()
    slack = SlackAlerter()
    discord = DiscordAlerter()
    enricher = AbuseIPDBEnricher() if enrich else None

    lines = follow(input_path) if follow_file else read_batch(input_path)

    events = 0
    alerts_fired: List[dict] = []
    for line in lines:
        event = parse_any(line, source=source)
        if not event:
            continue
        events += 1
        _write_jsonl(events_out, event)

        for alert in engine.process(event):
            if not _should_alert(alert.get("severity", "medium"), min_severity):
                continue
            if enricher and alert.get("source_ip"):
                enrichment = enricher.enrich(alert["source_ip"])
                if enrichment:
                    alert["enrichment"] = enrichment
            alerts_fired.append(alert)
            _write_jsonl(alerts_out, alert)
            console.send(alert)
            slack.send(alert)
            discord.send(alert)

    log.info(
        "Processed %d events, fired %d alerts (min severity=%s)",
        events, len(alerts_fired), min_severity,
    )
    return 0


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Mini-SIEM detection pipeline")
    parser.add_argument("--input", required=True, help="path to log file")
    parser.add_argument("--source", default="auto",
                        choices=["auto", "ssh", "auth", "nginx", "apache", "web", "cowrie"])
    parser.add_argument("--follow", action="store_true", help="tail file like tail -f")
    parser.add_argument("--rules", default="rules", help="rules directory")
    parser.add_argument("--no-enrich", action="store_true", help="skip AbuseIPDB lookup")
    parser.add_argument("--min-severity",
                        default=os.environ.get("MINI_SIEM_ALERT_MIN_SEVERITY", "medium"),
                        choices=list(_SEVERITY_ORDER.keys()))
    parser.add_argument("--events-out",
                        default=os.environ.get("MINI_SIEM_EVENTS_OUT", "data/output/events.jsonl"))
    parser.add_argument("--alerts-out",
                        default=os.environ.get("MINI_SIEM_ALERTS_OUT", "data/output/alerts.jsonl"))
    args = parser.parse_args()

    return run(
        input_path=args.input,
        source=args.source,
        follow_file=args.follow,
        rules_dir=args.rules,
        enrich=not args.no_enrich,
        min_severity=args.min_severity,
        events_out=args.events_out,
        alerts_out=args.alerts_out,
    )


if __name__ == "__main__":
    raise SystemExit(main())
