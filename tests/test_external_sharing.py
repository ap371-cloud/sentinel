"""External sharing: verify → grant or two-person approval → log → revoke.

The share register keeps every SHARE_REQUESTED / APPROVED / DENIED / REVOKED
decision, and an approved share still dies the moment the underlying access is
withdrawn or its own end date passes.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.config import Clearance, Role
from app.core.exceptions import AuthorizationDenied, TwoPersonControlViolation
from app.core.timeutil import utcnow
from app.database.session import ops_session
from app.models.documents import RecipientGrant
from app.security import revocation
from app.services import (
    approval_service,
    decryption_service,
    document_service,
    identity_service,
    seed_service,
    sharing_service,
)

GRANTER = "ADMIN-001"
#: A dedicated target: other suite files permanently revoke RECIPIENT-002, and
#: these tests must still exercise a live identity on a full run.
TARGET = "SHARE-RECIPIENT-001"
TARGET_DEVICE = "DEV-SHARE-001-A"


def ensure_target(session) -> None:
    if identity_service.get(session, TARGET) is not None:
        return
    identity_service.create(
        session,
        recipient_id=TARGET,
        display_name="Dedicated Share Target",
        role=Role.RECIPIENT,
        unit="BRAVO",
        clearance=Clearance.CONFIDENTIAL.value,
        password="Share1!2026",
        actor_id=GRANTER,
    )
    identity_service.register_device(
        session,
        recipient_id=TARGET,
        device_id=TARGET_DEVICE,
        device_name="share-target laptop",
        fingerprint="fp-share-target",
        actor_id=GRANTER,
    )


@pytest.fixture(autouse=True)
def _live_target(db):
    ensure_target(db)


def scratch(
    session,
    *,
    title: str,
    classification: str = "CONFIDENTIAL",
    unit: str = "BRAVO",
    recipients: list[str] | None = None,
    policy: dict | None = None,
) -> str:
    actor = identity_service.get(session, GRANTER)
    source = seed_service.synthetic_document(title, classification, unit, "SHARE-TEST")
    return document_service.create_document(
        session,
        actor=actor,
        source=source,
        title=title,
        classification=classification,
        unit=unit,
        recipient_ids=recipients,
        policy=policy or {},
    )["document_id"]


def share_it(session, document_id: str, **overrides) -> dict:
    payload = {
        "document_id": document_id,
        "target_recipient_id": TARGET,
        "requested_by": GRANTER,
        "justification": "Handover of the logistics annex to the on-shift recipient.",
    }
    payload.update(overrides)
    return sharing_service.request_share(session, **payload)


def decrypt_as(session, document_id: str) -> dict:
    actor = identity_service.get(session, TARGET)
    nonce = decryption_service.issue_nonce(
        session, recipient_id=TARGET, document_id=document_id
    )
    return decryption_service.decrypt(
        session,
        actor=actor,
        document_id=document_id,
        device_id=TARGET_DEVICE,
        nonce=nonce["nonce"],
    )


class TestDirectShare:
    def test_verified_target_gets_need_to_know_with_an_end_date(self, db):
        document_id = scratch(db, title="SHARE DIRECT")
        result = share_it(db, document_id, expires_in_days=7)
        assert result["status"] == sharing_service.APPROVED
        assert result["grant_id"]
        assert result["expires_at"] is not None
        assert result["rights_in_effect"]["DECRYPT"] == "ALLOW"
        assert "APPLICATION DEPENDENT" in result["limitation"]
        assert document_service.has_active_grant(db, document_id, TARGET)

    def test_already_granted_identity_is_a_no_op(self, db):
        document_id = scratch(db, title="SHARE ALREADY", recipients=[TARGET])
        result = share_it(db, document_id)
        assert result["status"] == "ALREADY_GRANTED"

    def test_unqualified_target_is_denied_with_the_actual_reasons(self, db):
        document_id = scratch(db, title="SHARE TOO SECRET", classification="SECRET")
        result = share_it(db, document_id)
        assert result["status"] == sharing_service.DENIED
        codes = [f["code"] for f in result["failures"]]
        assert "CLEARANCE_BELOW_CLASSIFICATION" in codes
        assert not document_service.has_active_grant(db, document_id, TARGET)

    def test_document_revoked_means_not_shareable(self, db):
        document_id = scratch(db, title="SHARE REVOKED DOC")
        document_service.transition(
            db,
            document_id=document_id,
            target="REVOKED",
            actor_id=GRANTER,
            reason="withdrawing the source document before sharing review",
        )
        result = share_it(db, document_id)
        assert result["status"] == sharing_service.DENIED
        assert any(f["code"] == "DOCUMENT_REVOKED" for f in result["failures"])


class TestTwoPersonShare:
    def test_configured_share_waits_for_a_different_approver(self, db):
        document_id = scratch(
            db, title="SHARE TWO PERSON", policy={"second_approval_required": True}
        )
        result = share_it(db, document_id)
        assert result["status"] == sharing_service.REQUESTED
        assert result["approval_id"]
        assert not document_service.has_active_grant(db, document_id, TARGET)

        approval_id = result["approval_id"]
        with pytest.raises(TwoPersonControlViolation):
            approval_service.approve(
                db, approval_id=approval_id, approver_id=GRANTER, approver_role="DOCUMENT_ADMIN"
            )
        decision = approval_service.approve(
            db, approval_id=approval_id, approver_id="COMMANDER-001", approver_role="COMMANDER"
        )
        assert decision["status"] == "APPROVED"
        final = sharing_service.finalize(db, approval_id=approval_id, approver_id="COMMANDER-001")
        assert final["status"] == sharing_service.APPROVED
        assert final["decided_by"] == "COMMANDER-001"
        assert document_service.has_active_grant(db, document_id, TARGET)
        row = db.get(RecipientGrant, final["grant_id"])
        assert row.expires_at is None or row.expires_at > utcnow()

    def test_rejection_records_a_denied_share(self, db):
        document_id = scratch(
            db, title="SHARE REJECTED", policy={"second_approval_required": True}
        )
        result = share_it(db, document_id)
        approval_id = result["approval_id"]
        approval_service.reject(
            db,
            approval_id=approval_id,
            approver_id="SECURITY-001",
            approver_role="SECURITY_OFFICER",
            reason="The recipient already has the paper original on shift.",
        )
        denied = sharing_service.record_denial(
            db,
            approval_id=approval_id,
            approver_id="SECURITY-001",
            reason="The recipient already has the paper original on shift.",
        )
        assert denied["status"] == sharing_service.DENIED
        assert denied["decided_by"] == "SECURITY-001"
        assert not document_service.has_active_grant(db, document_id, TARGET)


class TestShareLifecycle:
    def test_expiry_ends_need_to_know_and_shows_expired(self, db):
        document_id = scratch(db, title="SHARE EXPIRY")
        result = share_it(db, document_id, expires_in_days=1)
        grant_id = result["grant_id"]
        decrypt_as(db, document_id)

        past = utcnow() - timedelta(minutes=5)
        db.get(RecipientGrant, grant_id).expires_at = past
        share = db.get(sharing_service.ShareRequest, result["share_id"])
        share.expires_at = past
        db.flush()

        assert not document_service.has_active_grant(db, document_id, TARGET)
        with pytest.raises(AuthorizationDenied):
            decrypt_as(db, document_id)
        listed = sharing_service.list_shares(db, document_id=document_id)
        assert listed[0]["effective_status"] == "EXPIRED"

    def test_withdrawing_access_marks_the_share_revoked(self, db):
        document_id = scratch(db, title="SHARE THEN REVOKE")
        result = share_it(db, document_id)
        outcome = revocation.revoke_document_access(
            db,
            document_id=document_id,
            recipient_id=TARGET,
            actor_id="SECURITY-001",
            reason="The recipient moved to another programme.",
        )
        assert result["share_id"] in outcome["shares_revoked"]
        share = db.get(sharing_service.ShareRequest, result["share_id"])
        assert share.status == sharing_service.REVOKED
        assert not document_service.has_active_grant(db, document_id, TARGET)


class TestShareOverHttp:
    def test_direct_share_and_register_listing(self, client, tokens):
        with ops_session() as session:
            ensure_target(session)
            document_id = scratch(session, title="SHARE HTTP DIRECT")
        auth = {"Authorization": f"Bearer {tokens['admin']}"}
        created = client.post(
            f"/documents/{document_id}/shares",
            json={
                "recipient_id": TARGET,
                "justification": "Night-shift handover of the annex, acknowledged by both leads.",
                "expires_in_days": 3,
            },
            headers=auth,
        )
        assert created.status_code == 200, created.text
        assert created.json()["status"] == "APPROVED"

        listed = client.get(f"/documents/{document_id}/shares", headers=auth)
        assert listed.status_code == 200
        rows = listed.json()["shares"]
        assert len(rows) == 1
        assert rows[0]["status"] == "APPROVED"
        assert rows[0]["effective_status"] == "APPROVED"

    def test_classified_share_flows_through_two_person_approval(self, client, tokens):
        with ops_session() as session:
            ensure_target(session)
            document_id = scratch(
                session, title="SHARE HTTP APPROVAL", policy={"second_approval_required": True}
            )
        admin_auth = {"Authorization": f"Bearer {tokens['admin']}"}
        requested = client.post(
            f"/documents/{document_id}/shares",
            json={
                "recipient_id": TARGET,
                "justification": "Release to the on-shift recipient under dual control.",
            },
            headers=admin_auth,
        )
        assert requested.status_code == 200, requested.text
        body = requested.json()
        assert body["status"] == "SHARE_REQUESTED"
        approval_id = body["approval_id"]

        decided = client.post(
            f"/approvals/{approval_id}/approve",
            json={"reason": "Verified the handover roster personally."},
            headers={"Authorization": f"Bearer {tokens['commander']}"},
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["share"]["status"] == "APPROVED"

        listed = client.get(f"/documents/{document_id}/shares", headers=admin_auth)
        assert listed.json()["shares"][0]["status"] == "APPROVED"
