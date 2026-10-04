"""Prints the response shape of every endpoint the redesigned console reads, using
whichever demonstration identity is authorised to see it. The frontend types are
then written against observed reality rather than assumption.

    python scripts/ui_contract_probe.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

for _folder in ("data", "ledger", "evidence", "keys"):
    _target = ROOT / _folder
    if _target.exists():
        shutil.rmtree(_target, ignore_errors=True)
    _target.mkdir(parents=True, exist_ok=True)

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

CREDS = {
    "COMMANDER-001": "Commander!2026",
    "SECURITY-001": "Security!2026",
    "ADMIN-001": "Admin!2026",
    "RECIPIENT-001": "Recipient1!2026",
    "INVESTIGATOR-001": "Investigator!2026",
    "AUDITOR-001": "Auditor!2026",
    "LEDGER-001": "Ledger!2026",
}


def shape(value, depth: int = 0):
    if depth > 2:
        return "…"
    if isinstance(value, dict):
        return {k: shape(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [shape(value[0], depth + 1)] if value else []
    return type(value).__name__


def dump(label: str, payload, limit: int = 1500) -> None:
    print(f"\n### {label}")
    print(json.dumps(shape(payload), indent=2, default=str)[:limit])


with TestClient(app) as client:
    tokens = {}
    for rid, pw in CREDS.items():
        response = client.post("/auth/login", json={"recipient_id": rid, "password": pw})
        if response.status_code == 200:
            tokens[rid] = response.json()["token"]
        else:
            print(f"login failed for {rid}: {response.status_code}")

    def get(label: str, path: str, who: str = "COMMANDER-001"):
        token = tokens.get(who)
        response = client.get(path, headers={"Authorization": f"Bearer {token}"})
        print(f"\n===== {label}  [{who}]  {path}  ->  {response.status_code}")
        if response.status_code != 200:
            print("    " + response.text[:200])
            return None
        body = response.json()
        dump(label, body)
        return body

    def post(label: str, path: str, payload: dict, who: str = "COMMANDER-001"):
        token = tokens.get(who)
        response = client.post(path, json=payload, headers={"Authorization": f"Bearer {token}"})
        print(f"\n===== {label}  [{who}]  {path}  ->  {response.status_code}")
        if response.status_code != 200:
            print("    " + response.text[:200])
            return None
        body = response.json()
        dump(label, body)
        return body

    get("whoami", "/auth/whoami")
    get("ai health", "/ai/health")
    get("lockdown", "/lockdown")
    get("approvals", "/approvals")
    get("audit", "/audit?limit=3")
    get("lab scenarios", "/security-lab/scenarios")
    get("robustness", "/watermarks/robustness")
    get("ai clusters", "/ai/clusters?limit=3")
    get("incidents", "/incidents")
    get("investigations", "/investigations")
    get("sessions", "/sessions", who="RECIPIENT-001")
    get("recipients", "/recipients", who="ADMIN-001")
    get("devices", "/devices", who="SECURITY-001")
    get("ledger verify", "/ledger/verify", who="AUDITOR-001")
    get("ledger blocks", "/ledger/blocks")

    docs = get("documents", "/documents")
    if docs:
        first = docs["documents"][0]["document_id"]
        get("document detail", f"/documents/{first}")

    sessions = client.get("/sessions", headers={"Authorization": f"Bearer {tokens['RECIPIENT-001']}"}).json()
    if sessions.get("sessions"):
        sid = sessions["sessions"][0]["session_id"]
        get("session detail", f"/sessions/{sid}", who="RECIPIENT-001")

    post("ai briefing", "/ai/briefing", {"limit": 5})
    post("lab simulate", "/security-lab/simulate", {"scenario": "watermark_strip"}, who="SECURITY-001")

print("\n\nDONE")
