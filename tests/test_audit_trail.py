"""Structured audit trail columns and filters (Phase 19).

The audit log stays append-only and hash-chained; the new query-first columns
are copies of fields the record payload already carries. Old rows keep their
NULL columns untouched, which is what lets a chain written before the upgrade
still verify alongside chain rows written after it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.conftest import headers

from app.core.exceptions import AuthorizationDenied
from app.services import audit_service, decryption_service, identity_service, seed_service, document_service


def decrypt(db, recipient_id: str, document_id: str, device_id: str) -> str:
    nonce = decryption_service.issue_nonce(
        db, recipient_id=recipient_id, document_id=document_id
    )
    return decryption_service.decrypt(
        db,
        actor=identity_service.get(db, recipient_id),
        document_id=document_id,
        device_id=device_id,
        nonce=nonce["nonce"],
    )["session_id"]


class TestStructuredColumns:
    def test_a_decryption_record_carries_the_context_columns(self, db, brief_id):
        session_id = decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        records = audit_service.search(db, action="DOCUMENT_DECRYPTED", session_id=session_id)
        newest = records[-1]
        assert newest["device_id"] == "DEV-RECIPIENT-001-A"
        assert newest["document_id"] == brief_id
        assert newest["session_id"] == session_id
        assert newest["document_hash"] and len(newest["document_hash"]) == 64
        assert newest["policy_version"]
        assert newest["severity"] == "INFO"

    def test_a_denied_decryption_carries_reason_and_document(self, db):
        actor = identity_service.get(db, "ADMIN-001")
        source = seed_service.synthetic_document("AUDIT DENY", "CONFIDENTIAL", "BRAVO", "AUDIT-TEST", sections=1)
        document_id = document_service.create_document(
            db,
            actor=actor,
            source=source,
            title="AUDIT DENY",
            classification="CONFIDENTIAL",
            unit="BRAVO",
            recipient_ids=["RECIPIENT-002"],
        )["document_id"]
        recipient = identity_service.get(db, "RECIPIENT-001")
        nonce = decryption_service.issue_nonce(db, recipient_id="RECIPIENT-001", document_id=document_id)
        with pytest.raises(AuthorizationDenied):
            decryption_service.decrypt(
                db,
                actor=recipient,
                document_id=document_id,
                device_id="DEV-RECIPIENT-001-A",
                nonce=nonce["nonce"],
            )
        records = audit_service.search(db, action="DECRYPT_DENIED", document_id=document_id)
        newest = records[-1]
        assert newest["reason"]
        assert newest["severity"] == "WARN"
        assert newest["document_id"] == document_id

    def test_failed_login_records_carry_severity(self, db):
        with pytest.raises(Exception):
            identity_service.authenticate(db, recipient_id="RECIPIENT-001", password="surely-wrong")
        records = audit_service.search(db, action="LOGIN_FAILED", actor_id="RECIPIENT-001")
        assert records[-1]["severity"] == "WARN"


class TestChainSurvivesTheUpgrade:
    def test_mixed_chain_still_verifies(self, db, brief_id):
        decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        status = audit_service.verify_chain(db)["status"]
        assert status == "VERIFIED"

    def test_tampering_a_structured_column_breaks_the_chain(self, db, brief_id):
        """The append-only trigger does not guard the new audit columns, so a
        direct UPDATE slips through it; the hash chain must still catch it.
        The row is restored afterwards so the shared database stays clean."""
        from sqlalchemy import update

        decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        records = audit_service.search(db, action="DOCUMENT_DECRYPTED")
        target = records[-1]
        original = target["severity"]
        assert audit_service.verify_chain(db)["status"] == "VERIFIED"

        db.execute(
            update(audit_service.AuditRecord)
            .where(audit_service.AuditRecord.audit_id == target["audit_id"])
            .values(severity="HIGH")
        )
        db.flush()
        assert audit_service.verify_chain(db)["status"] == "TAMPER DETECTED"

        db.execute(
            update(audit_service.AuditRecord)
            .where(audit_service.AuditRecord.audit_id == target["audit_id"])
            .values(severity=original)
        )
        db.flush()
        assert audit_service.verify_chain(db)["status"] == "VERIFIED"


class TestAuditFilters:
    def test_filtered_route_narrows_without_breaking_verification(self, client, tokens):
        body = client.get(
            "/audit",
            headers=headers(tokens["auditor"]),
            params={"action": "LOGIN_FAILED", "actor_id": "RECIPIENT-001"},
        ).json()
        assert body["chain"]["status"] == "VERIFIED"
        assert body["privileged_actions"]
        assert all(r["action"] == "LOGIN_FAILED" for r in body["privileged_actions"])

    def test_device_filter_returns_only_that_device(self, db, client, tokens, brief_id):
        decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        body = client.get(
            "/audit",
            headers=headers(tokens["auditor"]),
            params={"action": "DOCUMENT_DECRYPTED", "device_id": "DEV-RECIPIENT-001-A"},
        ).json()
        assert body["privileged_actions"]
        assert all(r["device_id"] == "DEV-RECIPIENT-001-A" for r in body["privileged_actions"])
        assert body["filters_applied"]["device_id"] == "DEV-RECIPIENT-001-A"