"""File collectors: batch (read whole file) and follow (tail like tail -f)."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator


def read_batch(path: str | Path) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                yield line


def follow(path: str | Path, poll_interval: float = 0.5) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line = line.rstrip("\n")
            if line:
                yield line
