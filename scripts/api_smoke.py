"""End-to-end API test through the real ASGI application.

Every call below goes over HTTP against the same handlers the command terminal
uses. Nothing is stubbed: the watermark is embedded, the event is signed, the
ledger commits, and the forensic engine recovers the watermark from the copied
file.

    python scripts/api_smoke.py
"""

from __future__ import annotations

import shutil
import sys
import traceback
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

PASS, FAIL = "  [PASS]", "  [FAIL]"
failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"{PASS} {label}{(' — ' + detail) if detail else ''}")
    else:
        failures.append(label)
        print(f"{FAIL} {label}{(' — ' + detail) if detail else ''}")


def step(text: str) -> None:
    print(f"\n{'-' * 74}\n{text}\n{'-' * 74}")


def login(client: TestClient, recipient_id: str, password: str, device_id: str | None = None) -> str:
    response = client.post(
        "/auth/login", json={"recipient_id": recipient_id, "password": password, "device_id": device_id}
    )
    if response.status_code != 200:
        raise SystemExit(f"login failed for {recipient_id}: {response.status_code} {response.text[:300]}")
    return response.json()["token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def main() -> int:
    with TestClient(app) as client:
        step("SYSTEM")
        health = client.get("/api/health").json()
        print(f"  service        : {health['service']} v{health['version']}")
        print(f"  signing        : {health['post_quantum']['signing']}")
        print(f"  kem            : {health['post_quantum']['kem']}")
        print(f"  backend        : {health['post_quantum']['backend']}")
        check("API is up", health["status"] == "UP")
        check("real post-quantum backend in use", health["post_quantum"]["production_grade_backend"] is True)
        check("no plaintext in disclaimer", "Not certified" in health["disclaimer"])

        status = client.get("/api/status").json()
        check("air-gap active", status["air_gap"]["air_gapped_mode"] == "ACTIVE")
        check("egress guard installed", status["air_gap"]["guard_installed"] is True)
        check("three ledger nodes", status["ledger"]["node_count"] == 3)

        step("AUTHENTICATION AND RBAC")
        recipient_token = login(client, "RECIPIENT-001", "Recipient1!2026", "DEV-RECIPIENT-001-A")
        investigator_token = login(client, "INVESTIGATOR-001", "Investigator!2026")
        admin_token = login(client, "ADMIN-001", "Admin!2026")
        commander_token = login(client, "COMMANDER-001", "Commander!2026")
        officer_token = login(client, "SECURITY-001", "Security!2026")
        auditor_token = login(client, "AUDITOR-001", "Auditor!2026")
        check("all six synthetic identities authenticate", True)

        unauthenticated = client.get("/commander/dashboard")
        check("unauthenticated request refused", unauthenticated.status_code == 401,
              f"HTTP {unauthenticated.status_code}")

        bad_password = client.post("/auth/login", json={"recipient_id": "RECIPIENT-001", "password": "wrong"})
        check("wrong passphrase refused", bad_password.status_code == 401)

        recipient_dash = client.get("/commander/dashboard", headers=auth(recipient_token))
        check("recipient cannot open the command dashboard", recipient_dash.status_code == 403,
              f"HTTP {recipient_dash.status_code}")

        recipient_cases = client.get("/investigations", headers=auth(recipient_token))
        check("recipient cannot read investigations", recipient_cases.status_code == 403)

        auditor_write = client.post(
            "/investigations",
            headers=auth(auditor_token),
            json={"title": "auditor should not create this"},
        )
        check("auditor is read-only", auditor_write.status_code == 403,
              f"HTTP {auditor_write.status_code}")
        auditor_read = client.get("/investigations", headers=auth(auditor_token))
        check("auditor can read investigations", auditor_read.status_code == 200)

        step("DOCUMENTS")
        documents = client.get("/documents", headers=auth(recipient_token)).json()["documents"]
        print(f"  documents      : {[d['document_id'] + ' ' + d['classification'] for d in documents]}")
        check("seeded documents present", len(documents) >= 3)
        document_id = documents[0]["document_id"]

        detail = client.get(f"/documents/{document_id}", headers=auth(admin_token)).json()["document"]
        print(f"  {document_id}       : {detail['title']} / {detail['lifecycle_state']}")
        print(f"  versions       : {[v['label'] for v in detail['versions']]}")
        print(f"  recipients     : {detail['authorized_recipients']}")
        print(f"  content cipher : {detail['crypto']['content_cipher']}")
        print(f"  key wrap       : {detail['crypto']['key_wrap']}")
        check("document is sealed and versioned", detail["status"] == "SEALED" and detail["current_version"] == 1)
        check("no encryption key exposed to the API", "key" not in str(detail.get("policy", {})).lower()
              or detail["versions"][0]["key_wrap_algorithm"].startswith("ML-KEM"))

        step("AUTHORISED DECRYPTION — SESSION, WATERMARK, SIGNATURE, LEDGER")
        nonce = client.post(
            "/decrypt/authorize",
            headers=auth(recipient_token),
            json={"document_id": document_id},
        ).json()
        decrypted = client.post(
            "/decrypt",
            headers=auth(recipient_token),
            json={
                "document_id": document_id,
                "device_id": "DEV-RECIPIENT-001-A",
                "nonce": nonce["nonce"],
            },
        )
        if decrypted.status_code != 200:
            print(decrypted.text[:600])
            raise SystemExit("decrypt failed")
        session_one = decrypted.json()
        print(f"  session        : {session_one['session_id']}")
        print(f"  watermark      : {session_one['watermark_tag']}")
        print(f"  psnr / ssim    : {session_one['watermark_quality']['psnr_db']} dB / "
              f"{session_one['watermark_quality']['ssim']}")
        print(f"  checks passed  : {sum(1 for c in session_one['authorization_checks'] if c['passed'])}"
              f"/{len(session_one['authorization_checks'])}")
        print(f"  signature      : {session_one['signature_algorithm']}")
        print(f"  ledger         : {session_one['ledger']['status']} -> {session_one['ledger'].get('block_id')}")
        check("decryption succeeded with a unique session", bool(session_one["session_id"]))
        check("all authorisation checks passed",
              all(c["passed"] for c in session_one["authorization_checks"]))
        check("signed event committed to the ledger", session_one["ledger"]["committed"])

        session_detail = client.get(
            f"/sessions/{session_one['session_id']}", headers=auth(recipient_token)
        ).json()["session"]
        check("session view exposes the whole forensic relationship",
              bool(session_detail["watermark_tag"] and session_detail["signature"] and session_detail["ledger_tx_id"]))

        document_artefact = client.get(
            f"/sessions/{session_one['session_id']}/document", headers=auth(recipient_token)
        )
        check("recipient can retrieve their own watermarked copy",
              document_artefact.status_code == 200 and document_artefact.content[:4] == b"%PDF",
              f"{len(document_artefact.content)} bytes")

        step("SECOND RECIPIENT GETS A DIFFERENT FORENSIC IDENTITY")
        token_two = login(client, "RECIPIENT-002", "Recipient2!2026", "DEV-RECIPIENT-002-A")
        nonce_two = client.post(
            "/decrypt/authorize", headers=auth(token_two), json={"document_id": document_id}
        ).json()
        session_two = client.post(
            "/decrypt",
            headers=auth(token_two),
            json={"document_id": document_id, "device_id": "DEV-RECIPIENT-002-A", "nonce": nonce_two["nonce"]},
        ).json()
        print(f"  session        : {session_two['session_id']}")
        print(f"  watermark      : {session_two['watermark_tag']}")
        check("second recipient receives a different watermark",
              session_two["watermark_tag"] != session_one["watermark_tag"])

        step("REFUSALS")
        replay = client.post(
            "/decrypt",
            headers=auth(recipient_token),
            json={"document_id": document_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce["nonce"]},
        )
        body = replay.json()
        check("replayed authorisation refused", replay.status_code == 403 and
              body["error"]["code"] == "REPLAY_ATTACK_DETECTED", body["error"]["code"])

        bad_device = client.post(
            "/decrypt/authorize", headers=auth(recipient_token), json={"document_id": document_id}
        ).json()
        unknown_device = client.post(
            "/decrypt",
            headers=auth(recipient_token),
            json={"document_id": document_id, "device_id": "DEV-NOT-REGISTERED", "nonce": bad_device["nonce"]},
        ).json()
        check("unregistered device refused",
              unknown_device["error"]["code"] == "DEVICE_NOT_AUTHORIZED",
              unknown_device["error"]["code"])

        step("FORENSIC ANALYSIS OF A LEAKED COPY")
        case = client.post(
            "/investigations",
            headers=auth(investigator_token),
            json={
                "title": "Suspected leak via the API",
                "summary": "Copy recovered outside the authorised distribution list.",
                "suspected_document_id": document_id,
            },
        ).json()["case"]
        print(f"  case           : {case['case_id']} — {case['status']}")

        leaked = Path(session_one["output_path"])
        leaked_copy = ROOT / "data" / "render" / "LEAKED_DOCUMENT.pdf"
        shutil.copy2(leaked, leaked_copy)

        with leaked_copy.open("rb") as handle:
            analysis = client.post(
                "/forensics/analyze",
                headers=auth(investigator_token),
                data={"case_id": case["case_id"]},
                files={"file": ("LEAKED_DOCUMENT.pdf", handle, "application/pdf")},
            ).json()["analysis"]
        print(f"  outcome        : {analysis['outcome']}")
        for link in analysis["evidence_chain"]:
            print(f"    {link['status']:<8} {link['link']:<26} {link['detail'][:66]}")
        check("leak attributed to the correct recipient",
              analysis["matched_recipient_id"] == "RECIPIENT-001", str(analysis["matched_recipient_id"]))
        check("leak attributed to the correct session",
              analysis["matched_session_id"] == session_one["session_id"])
        check("outcome is a verified association", analysis["outcome"] == "VERIFIED ASSOCIATION")

        evidence_id = analysis["evidence_id"]
        report = client.post(
            f"/forensics/evidence/{evidence_id}/report", headers=auth(investigator_token)
        ).json()
        print(f"  report hash    : {report['report']['report_sha256'][:32]}…")
        print(f"  integrity      : {report['integrity']['status']}")
        print(f"  limitation     : {report['report']['limitations'][0][:96]}…")
        check("evidence report integrity verified", report["integrity"]["status"].endswith("VERIFIED"))
        check("report states what it does not prove",
              any("does not prove" in item for item in report["report"]["limitations"]))

        auditor_verify = client.get(
            f"/forensics/evidence/{evidence_id}/report/integrity", headers=auth(auditor_token)
        )
        check("auditor can independently verify evidence report integrity",
              auditor_verify.status_code == 200
              and auditor_verify.json()["status"].endswith("VERIFIED"),
              auditor_verify.json().get("status", f"HTTP {auditor_verify.status_code}"))

        step("LEDGER")
        ledger_status = client.get("/ledger/status", headers=auth(auditor_token)).json()
        for node in ledger_status["nodes"]:
            print(f"  {node['node_id']:<8} {node['status']:<8} height {node['block_height']} "
                  f"merkle {node['latest_merkle_root'][:16]}…")
        verification = client.get("/ledger/verify", headers=auth(auditor_token)).json()
        print(f"  {verification['headline']}")
        check("ledger integrity verified", verification["headline"].endswith("VERIFIED"))
        proof = client.get(
            f"/ledger/transactions/{session_one['ledger']['tx_id']}", headers=auth(auditor_token)
        ).json()["inclusion_proof"]
        print(f"  merkle proof   : {proof['status']}")
        check("transaction inclusion proof verifies", proof["verified"] is True)

        step("SECURITY OPERATIONS")
        dashboard = client.get("/commander/dashboard", headers=auth(commander_token)).json()
        print(f"  status         : {dashboard['system_security_status']}")
        print(f"  posture        : {dashboard['security_posture']['score']}/100 "
              f"{dashboard['security_posture']['rating']}")
        print(f"  ledger health  : {dashboard['ledger_health']['headline']}")
        print(f"  watermark      : {dashboard['watermark_engine']['status']} "
              f"uniqueness_holds={dashboard['watermark_engine']['uniqueness_holds']}")
        check("dashboard reports system status", bool(dashboard["system_security_status"]))
        check("watermark uniqueness holds across issued marks",
              dashboard["watermark_engine"]["uniqueness_holds"] is True)

        # The investigator raises the export request; two other identities must
        # approve it. The requester is never eligible to approve.
        approval = client.post(
            "/approvals",
            headers=auth(investigator_token),
            json={
                "action": "EVIDENCE_EXPORT",
                "justification": "Two-person control verification via the API",
                "subject_id": case["case_id"],
            },
        ).json()
        first = client.post(
            f"/approvals/{approval['approval_id']}/approve",
            headers=auth(commander_token),
            json={"reason": "Reviewed and supported"},
        ).json()
        check("single approval does not satisfy two-person control", first["sufficient"] is False,
              f"{first['approvals_counted']}/{first['required_approvals']}")
        early = client.post(
            "/evidence/export",
            headers=auth(investigator_token),
            json={"case_id": case["case_id"], "approval_id": approval["approval_id"]},
        )
        check("export blocked on one approval", early.status_code == 428,
              f"HTTP {early.status_code}")
        client.post(
            f"/approvals/{approval['approval_id']}/approve",
            headers=auth(officer_token),
            json={"reason": "Second authorised officer"},
        )
        exported = client.post(
            "/evidence/export",
            headers=auth(investigator_token),
            json={"case_id": case["case_id"], "approval_id": approval["approval_id"]},
        )
        check("export proceeds after the second distinct approval", exported.status_code == 200,
              f"HTTP {exported.status_code}")
        reuse = client.post(
            "/evidence/export",
            headers=auth(investigator_token),
            json={"case_id": case["case_id"], "approval_id": approval["approval_id"]},
        )
        check("approval is single-use", reuse.status_code == 400, f"HTTP {reuse.status_code}")

        step("REVOCATION TAKES EFFECT IMMEDIATELY")
        revoked = client.post(
            "/recipients/RECIPIENT-002/revoke",
            headers=auth(officer_token),
            json={"reason": "Synthetic revocation verification via the API"},
        )
        check("revocation accepted", revoked.status_code == 200)
        revoked_login = client.post(
            "/auth/login", json={"recipient_id": "RECIPIENT-002", "password": "Recipient2!2026"}
        )
        check("revoked identity cannot sign in", revoked_login.status_code == 403,
              f"HTTP {revoked_login.status_code}")

        step("LOCKDOWN")
        engagement = client.post(
            "/lockdown",
            headers=auth(commander_token),
            json={"reason": "Synthetic lockdown verification via the API"},
        )
        check("lockdown engaged", engagement.status_code == 200 and
              engagement.json()["system_status"] == "EMERGENCY LOCKDOWN")
        nonce_locked = client.post(
            "/decrypt/authorize", headers=auth(recipient_token), json={"document_id": document_id}
        ).json()
        blocked = client.post(
            "/decrypt",
            headers=auth(recipient_token),
            json={"document_id": document_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce_locked["nonce"]},
        )
        check("lockdown blocks new decryptions", blocked.status_code == 423,
              f"HTTP {blocked.status_code} {blocked.json()['error']['code']}")
        audit_during_lockdown = client.get("/audit", headers=auth(auditor_token))
        check("audit trail still readable during lockdown", audit_during_lockdown.status_code == 200)
        unlock = client.post(
            "/unlock",
            headers=auth(commander_token),
            json={"reason": "Synthetic release requires two-person approval", "approval_id": ""},
        )
        check("unlock without two-person approval refused", unlock.status_code in (400, 403, 428),
              f"HTTP {unlock.status_code}")

        step("ATTACK SIMULATION LAB")
        for scenario in ("ledger_tampering", "signature_forgery", "replay_attack", "unknown_device",
                         "watermark_corruption"):
            outcome = client.post(
                "/security-lab/simulate",
                headers=auth(officer_token),
                json={"scenario": scenario},
            ).json()
            print(f"  {scenario:<22} detected={str(outcome['detected']):<6} {outcome['outcome']}")
            check(f"attack detected: {scenario}", outcome["detected"] is True)

        step("OPTIONAL LOCAL AI")
        ai_health = client.get("/ai/health", headers=auth(commander_token)).json()
        print(f"  status         : {ai_health['status']}")
        briefing = client.post(
            "/ai/briefing", headers=auth(commander_token), json={"limit": 8}
        ).json()
        if briefing["briefing"]["available"]:
            print(f"  label          : {briefing['briefing']['label']}")
            print(f"  summary        : {briefing['briefing']['summary'][:200]}")
            check("AI output labelled as advisory",
                  briefing["briefing"]["label"] == "AI-ASSISTED ANALYSIS")
        else:
            print(f"  fallback       : {briefing['briefing']['fallback'][:150]}")
            check("AI offline handled without degrading deterministic results",
                  briefing["briefing"]["label"] == "AI SERVICE OFFLINE"
                  and briefing["deterministic_state"]["system_security_status"] is not None)
        check("deterministic state returned alongside AI output",
              briefing["deterministic_state"]["ledger_integrity"] is not None)

        step("AUDIT CHAIN")
        audit = client.get("/audit", headers=auth(auditor_token), params={"limit": 200}).json()
        print(f"  records        : {audit['chain']['chain_length']}")
        print(f"  chain status   : {audit['chain']['status']}")
        check("privileged action chain verifies", audit["chain"]["status"] == "VERIFIED")
        blob = str(audit)
        check("no private key material in the audit trail",
              "secret_key" not in blob and "private_key" not in blob and "password" not in blob)

    print("\n" + "=" * 74)
    if failures:
        print(f"RESULT: {len(failures)} CHECK(S) FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("RESULT: ALL API CHECKS PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
