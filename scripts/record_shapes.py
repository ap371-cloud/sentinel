"""Prints the field names the service layer emits for records that a freshly
seeded deployment leaves empty, so the console can bind to real columns.

    python scripts/record_shapes.py
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.api import forensics, ledger, security  # noqa: E402
from app.security import attack_lab, incident_engine  # noqa: E402
from app.services import (  # noqa: E402
    approval_service, audit_service, decryption_service, forensic_service,
    identity_service,
)
from app.ledger import chain as ledger_chain  # noqa: E402

TARGETS = [
    ("approval row", approval_service, "describe"),
    ("session row", decryption_service, "describe_session"),
    ("investigation row", forensic_service, "describe_case"),
    ("incident row", incident_engine, "describe"),
    ("audit row", audit_service, "describe"),
    ("device", identity_service, "describe_device"),
    ("identity", identity_service, "to_public"),
    ("attack scenario", attack_lab, "SCENARIOS"),
]

for label, module, name in TARGETS:
    fn = getattr(module, name, None)
    if fn is None:
        candidates = [n for n in dir(module) if not n.startswith("_")]
        print(f"\n### {label}: no '{name}', candidates: {candidates[:14]}")
        continue
    print(f"\n{'=' * 70}\n### {label}  ->  {module.__name__}.{name}\n{'=' * 70}")
    print(inspect.getsource(fn)[:2400])

print(f"\n{'=' * 70}\n### ledger chain describe helpers\n{'=' * 70}")
for name in dir(ledger_chain):
    if "describe" in name or name.startswith("to_"):
        fn = getattr(ledger_chain, name)
        if callable(fn):
            print(f"\n--- {name} ---")
            print(inspect.getsource(fn)[:1200])
