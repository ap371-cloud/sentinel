"""Prints the permission that guards every console-facing route, so the frontend
can gate navigation on the same rules the backend enforces.

    python scripts/route_permissions.py
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.api import auth, decryption, documents, forensics, ledger, security  # noqa: E402

PATTERN = re.compile(
    r'@router\.(?:get|post|delete|put)\("([^"]+)"(.*?)\)\s*\n(?:async )?def \w+\((.*?)\n\n',
    re.S,
)
GUARD = re.compile(r'(permitted|readable|writable)\("([^"]+)"\)')

rows: list[tuple[str, str]] = []
for module in (auth, documents, decryption, forensics, ledger, security):
    source = inspect.getsource(module)
    for match in PATTERN.finditer(source):
        route, between, params = match.groups()
        blob = between + " " + params
        guard = GUARD.search(blob)
        if guard:
            tag = f"{guard.group(1)}:{guard.group(2)}"
        elif "current_recipient" in blob:
            tag = "authenticated"
        else:
            tag = "public"
        rows.append((route, tag))

for route, tag in sorted(rows):
    print(f"{route:<50} {tag}")
