from __future__ import annotations

import itertools
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
_counters: dict[str, itertools.count] = {}


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def next_id(prefix: str, width: int = 4) -> str:
    """Human-readable sequential identifiers. A cryptographic random component
    is added where the identifier itself is a security token (session nonces,
    request ids), never for human-facing record numbers."""
    with _lock:
        counter = _counters.setdefault(prefix, itertools.count(1))
        value = next(counter)
    return f"{prefix}-{value:0{width}d}"


def sync_counter(prefix: str, observed: int) -> None:
    with _lock:
        current = _counters.setdefault(prefix, itertools.count(1))
        while next(current) <= observed:
            pass


def case_id(sequence: int) -> str:
    year = datetime.now(timezone.utc).year
    return f"CASE-{year}-{sequence:03d}"
