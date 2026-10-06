"""Forensic chain policy binding and confidence gating (Phase 18).

Step 10 of the forensic chain binds the signed decryption event to the policy
version it claims was in force. A binding is only trusted when that version was
actually issued before the event, and attribution is never claimed when the
distributed version cannot be compared or the policy cannot be bound.
"""

from __future__ import annotations

import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.config import ForensicOutcome
from app.core.timeutil import utcnow
from app.models.security import Policy
from app.services import decryption_service, forensic_service, identity_service


def decrypt(db, recipient_id: str, document_id: str, device_id: str) -> dict:
    nonce = decryption_service.issue_nonce(db, recipient_id=recipient_id, document_id=document_id)
    return decryption_service.decrypt(
        db,
        actor=identity_service.get(db, recipient_id),
        document_id=document_id,
        device_id=device_id,
        nonce=nonce["nonce"],
    )


class TestPolicyBinding:
    def test_event_without_a_policy_version_is_unknown(self, db):
        binding = forensic_service.policy_binding(db, {}, utcnow())
        assert binding["status"] == "UNKNOWN"

    def test_version_that_was_never_issued_fails(self, db):
        binding = forensic_service.policy_binding(db, {"policy_version": "POL-999.0"}, utcnow())
        assert binding["status"] == "FAIL"
        assert "never issued" in binding["detail"]

    def test_retroactive_binding_is_rejected(self, db):
        policy_at = datetime.now(timezone.utc) - timedelta(days=2)
        db.add(
            Policy(
                policy_id="POL-0.99",
                policy_version="POL-0.99",
                name="late policy",
                body="{}",
                device_access_policy="ALLOW",
                replay_window_seconds=45,
                break_glass_enabled=True,
                high_risk_actions="[]",
                active=False,
                updated_by="ADMIN-001",
                updated_at=policy_at,
            )
        )
        db.flush()
        occurred_at = datetime.now(timezone.utc) - timedelta(days=3)
        binding = forensic_service.policy_binding(db, {"policy_version": "POL-0.99"}, occurred_at)
        assert binding["status"] == "FAIL"
        assert "retroactive" in binding["detail"]

    def test_current_policy_binds_cleanly(self, db):
        db.add(
            Policy(
                policy_id="POL-7.1",
                policy_version="POL-7.1",
                name="bindable policy",
                body="{}",
                device_access_policy="ALLOW",
                replay_window_seconds=45,
                break_glass_enabled=True,
                high_risk_actions="[]",
                active=False,
                updated_by="ADMIN-001",
                updated_at=datetime.now(timezone.utc) - timedelta(days=1),
            )
        )
        db.flush()
        payload = {"policy_version": "POL-7.1", "something": "else"}
        binding = forensic_service.policy_binding(db, payload, utcnow())
        assert binding["status"] == "PASS"
        assert binding["evidence"]["policy_version"] == "POL-7.1"


class TestChainLinksAndGating:
    @pytest.fixture()
    def leak(self, db, brief_id, tmp_path):
        result = decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        investigator = identity_service.get(db, "INVESTIGATOR-001")
        case = forensic_service.open_case(
            db, investigator=investigator, title="policy binding leak",
            suspected_document_id=brief_id,
        )
        leaked = tmp_path / "POLICY_BINDING_LEAK.pdf"
        shutil.copy2(result["output_path"], leaked)
        evidence = forensic_service.store_evidence(
            db, case=case, investigator=investigator,
            leaked_path=leaked, original_filename="POLICY_BINDING_LEAK.pdf",
        )
        return evidence, investigator

    def test_chain_binds_the_event_to_its_policy_version(self, db, leak):
        evidence, _ = leak
        analysis = forensic_service.analyze(db, evidence=evidence)
        assert analysis["outcome"] == ForensicOutcome.VERIFIED_ASSOCIATION
        policy_link = next(
            l for l in analysis["evidence_chain"] if l["link"] == "POLICY VERIFICATION"
        )
        assert policy_link["status"] == "PASS"
        assert policy_link["evidence"]["policy_hash"]
        assert policy_link["evidence"]["policy_version"]

    def test_report_carries_the_policy_binding(self, db, leak):
        evidence, investigator = leak
        forensic_service.analyze(db, evidence=evidence)
        report = forensic_service.build_report(db, evidence=evidence, investigator=investigator)
        assert report["policy"]["binding_verified"] is True
        assert report["policy"]["evidence"]["policy_hash"]

    def test_unverifiable_document_never_claims_attribution(self, db, leak, monkeypatch):
        evidence, _ = leak
        monkeypatch.setattr(
            forensic_service,
            "content_similarity",
            lambda *a, **k: {"original_available": False, "psnr_db": None, "pages": []},
        )
        analysis = forensic_service.analyze(db, evidence=evidence)
        assert analysis["outcome"] == ForensicOutcome.PARTIALLY_VERIFIED
        match_link = next(
            l for l in analysis["evidence_chain"] if l["link"] == "DOCUMENT VERSION MATCH"
        )
        assert match_link["status"] == "UNKNOWN"