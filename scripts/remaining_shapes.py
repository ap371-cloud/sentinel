"""Prints the attack-lab scenario keys, the ledger transaction serialisation and the
commander dashboard sections, which a freshly seeded deployment leaves empty.

    python scripts/remaining_shapes.py
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.api import ledger as ledger_api  # noqa: E402
from app.security import attack_lab  # noqa: E402
from app.services import command_service  # noqa: E402

print("=" * 70)
print("### attack lab scenario keys")
print("=" * 70)
for entry in attack_lab.ATTACK_SCENARIOS:
    if isinstance(entry, dict):
        for key, value in entry.items():
            if isinstance(value, dict):
                print(f"  {key}")
                print(f"      title            : {value.get('title')}")
                print(f"      what_it_does     : {str(value.get('what_it_does'))[:90]}")
                print(f"      expected_detection: {str(value.get('expected_detection'))[:90]}")
    else:
        print(f"  {entry}")

for name in ("run",):
    fn = getattr(attack_lab, name, None)
    if fn:
        print(f"\n--- attack_lab.{name} return shape ---")
        source = inspect.getsource(fn)
        tail = source[-1400:]
        print(tail)

print("\n" + "=" * 70)
print("### ledger transaction + block serialisation")
print("=" * 70)
source = inspect.getsource(ledger_api)
for match in re.finditer(r'def (list_transactions|transaction_detail|_tx|_block)\(.*?\n\n', source, re.S):
    print(f"\n--- {match.group(1)} ---")
    print(match.group(0)[:1600])

print("\n" + "=" * 70)
print("### commander dashboard sections")
print("=" * 70)
for name in ("dashboard", "topology", "air_gap", "watermark_engine", "posture"):
    fn = getattr(command_service, name, None)
    if fn is None:
        continue
    print(f"\n--- command_service.{name} ---")
    print(inspect.getsource(fn)[:1800])
