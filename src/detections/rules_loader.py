"""Load YAML detection rules from a directory."""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml


def load_rules(rules_dir: str | Path) -> List[dict]:
    rules_dir = Path(rules_dir)
    rules: List[dict] = []
    for path in sorted(rules_dir.glob("*.yml")):
        with open(path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        if not isinstance(rule, dict):
            continue
        rule["__path__"] = str(path)
        rules.append(rule)
    return rules
