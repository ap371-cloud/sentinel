"""Offline grant windows and the withdrawal register.

A rights column nobody enforces is a claim, not a control, so every offline
denial reason and every revocation route gets a test that actually walks the
path a client would take.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import headers  # noqa: E402

from app.core.config import AccountStatus, Clearance, DocumentAccess, DocumentLifecycle, Role
from app.core.exceptions import AuthorizationDenied, ForgeError
from app.core.permissions import RequestContext, evaluate_decryption
from app.core.timeutil import as_utc, utcnow
from app.database.session import ops_session
from app.models.documents import Document, OfflineGrant
from app.models.identity import Recipient
from app.models.security import Revocation
from app.security import offline_grants, revocation
from app.services import decryption_service, document_service, identity_service, seed_service

DEVICE = "DEV-RECIPIENT-001-A"
RECIPIENT = "RECIPIENT-001"


def decrypt_offline(db, document_id: str) -> dict:
    actor = identity_service.get(db, RECIPIENT)
    nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=document_id)
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=DEVICE, nonce=nonce["nonce"],
        offline=True,
    )


def decrypt_online(db, document_id: str) -> dict:
    actor = identity_service.get(db, RECIPIENT)
    nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=document_id)
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=DEVICE, nonce=nonce["nonce"]
    )


def clear_leases(db, document_id: str) -> None:
    """Puts prior windows out of the way without exercising a revoke path —
    isolation, not behaviour under test."""
    for lease in db.execute(
        select(OfflineGrant).where(
            OfflineGrant.document_id == document_id, OfflineGrant.recipient_id == RECIPIENT
        )
    ).scalars():
        lease.status = offline_grants.GRANT_SUPERSEDED
        lease.closed_at = utcnow()
        lease.closed_reason = "test isolation"
    db.flush()


def latest_lease(db, document_id: str) -> OfflineGrant | None:
    return db.execute(
        select(OfflineGrant)
        .where(OfflineGrant.document_id == document_id, OfflineGrant.recipient_id == RECIPIENT)
        .order_by(OfflineGrant.granted_at.desc())
    ).scalars().first()


def scratch_document(db, *, title: str, offline_allowed: bool = True) -> str:
    actor = identity_service.get(db, "ADMIN-001")
    source = seed_service.synthetic_document(title, "CONFIDENTIAL", "BRAVO", "OFFLINE-TEST", sections=1)
    result = document_service.create_document(
        db,
        actor=actor,
        source=source,
        title=title,
        classification="CONFIDENTIAL",
        unit="BRAVO",
        recipient_ids=[RECIPIENT],
        policy={"offline_allowed": offline_allowed},
    )
    return result["document_id"]


def context(**overrides) -> RequestContext:
    base = dict(
        actor_id=RECIPIENT,
        role=Role.RECIPIENT,
        unit="BRAVO",
        clearance=Clearance.CONFIDENTIAL.value,
        account_status="ACTIVE",
        device_id=DEVICE,
        document_classification=Clearance.CONFIDENTIAL.value,
        document_status=DocumentAccess.SEALED,
        document_unit_scope=["BRAVO"],
        document_role_scope=[Role.RECIPIENT],
        granted=True,
        device_status="ACTIVE",
        device_trust="TRUSTED",
        device_owner_id=RECIPIENT,
        signing_key_status="ACTIVE",
        signing_key_expired=False,
        kem_key_status="ACTIVE",
        nonce_consumed=False,
        nonce_expired=False,
        nonce_owner_match=True,
        lockdown_active=False,
    )
    base.update(overrides)
    return RequestContext(**base)


class TestOfflineGrantDecision:
    def test_an_elapsed_window_refuses_offline_use(self):
        decision = evaluate_decryption(
            context(offline_requested=True, offline_allowed=True, offline_grant_expired=True)
        )
        assert decision.allowed is False
        assert decision.reason_code == "OFFLINE_GRANT_EXPIRED"

    def test_a_revoked_window_refuses_offline_use(self):
        decision = evaluate_decryption(
            context(offline_requested=True, offline_allowed=True, offline_grant_revoked=True)
        )
        assert decision.allowed is False
        assert decision.reason_code == "OFFLINE_GRANT_REVOKED"

    def test_the_denial_explains_the_remedy(self):
        decision = evaluate_decryption(
            context(offline_requested=True, offline_grant_expired=True)
        )
        assert "online" in decision.plain_explanation.lower()


class TestOfflineGrantLifecycle:
    def test_offline_decryption_records_an_active_lease(self, db, brief_id):
        clear_leases(db, brief_id)
        result = decrypt_offline(db, brief_id)
        lease = latest_lease(db, brief_id)
        assert lease is not None
        assert lease.status == offline_grants.GRANT_ACTIVE
        assert lease.session_id == result["session_id"]
        assert lease.policy_version
        listed = document_service.describe(db, brief_id)["offline_grants"]
        assert any(row["offline_grant_id"] == lease.offline_grant_id for row in listed)

    def test_repeated_offline_decryptions_reuse_the_same_window(self, db, brief_id):
        clear_leases(db, brief_id)
        decrypt_offline(db, brief_id)
        first = latest_lease(db, brief_id)
        decrypt_offline(db, brief_id)
        active = [
            row for row in document_service.describe(db, brief_id)["offline_grants"]
            if row["status"] == offline_grants.GRANT_ACTIVE
        ]
        assert len(active) == 1
        assert active[0]["offline_grant_id"] == first.offline_grant_id

    def test_offline_max_hours_bounds_the_window(self, db):
        document_id = scratch_document(db, title="OFFLINE TEST CAP")
        document = db.get(Document, document_id)
        document.offline_max_hours = 2
        db.flush()
        decrypt_offline(db, document_id)
        lease = latest_lease(db, document_id)
        assert lease.expires_at is not None
        remaining = as_utc(lease.expires_at) - utcnow()
        assert timedelta(hours=1, minutes=59) < remaining <= timedelta(hours=2, minutes=1)

    def test_offline_max_hours_is_validated(self, db):
        actor = identity_service.get(db, "ADMIN-001")
        source = seed_service.synthetic_document(
            "OFFLINE TEST BAD CAP", "CONFIDENTIAL", "BRAVO", "OFFLINE-TEST", sections=1
        )
        with pytest.raises(ForgeError):
            document_service.create_document(
                db,
                actor=actor,
                source=source,
                title="OFFLINE TEST BAD CAP",
                classification="CONFIDENTIAL",
                unit="BRAVO",
                recipient_ids=[RECIPIENT],
                policy={"offline_max_hours": 9000},
            )

    def test_an_elapsed_window_blocks_offline_until_one_online_session_renews_it(self, db, brief_id):
        clear_leases(db, brief_id)
        decrypt_offline(db, brief_id)
        lease = latest_lease(db, brief_id)
        lease.expires_at = utcnow() - timedelta(minutes=5)
        db.flush()

        actor = identity_service.get(db, RECIPIENT)
        nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=brief_id)
        with pytest.raises(AuthorizationDenied) as excinfo:
            decryption_service.decrypt(
                db, actor=actor, document_id=brief_id, device_id=DEVICE,
                nonce=nonce["nonce"], offline=True,
            )
        assert excinfo.value.detail == "OFFLINE_GRANT_EXPIRED"

        decrypt_online(db, brief_id)
        db.refresh(lease)
        assert lease.status == offline_grants.GRANT_SUPERSEDED

        decrypt_offline(db, brief_id)
        renewed = latest_lease(db, brief_id)
        assert renewed.offline_grant_id != lease.offline_grant_id
        assert renewed.status == offline_grants.GRANT_ACTIVE

    def test_rights_can_forbid_offline_even_when_the_column_allows_it(self, db, brief_id):
        document = db.get(Document, brief_id)
        original_rights = document.rights
        document.rights = json.dumps({"OFFLINE": "DENY"})
        document.offline_allowed = True
        db.flush()
        try:
            actor = identity_service.get(db, RECIPIENT)
            nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=brief_id)
            with pytest.raises(AuthorizationDenied) as excinfo:
                decryption_service.decrypt(
                    db, actor=actor, document_id=brief_id, device_id=DEVICE,
                    nonce=nonce["nonce"], offline=True,
                )
            assert excinfo.value.detail == "OFFLINE_NOT_PERMITTED"
        finally:
            document.rights = original_rights
            document.offline_allowed = True
            db.flush()

    def test_access_alone_does_not_resurrect_a_revoked_window(self, db, brief_id):
        clear_leases(db, brief_id)
        decrypt_offline(db, brief_id)
        revocation.revoke_document_access(
            db, document_id=brief_id, recipient_id=RECIPIENT,
            actor_id="SECURITY-001", reason="withdraw need-to-know for lease test",
        )
        lease = latest_lease(db, brief_id)
        assert lease.status == offline_grants.GRANT_REVOKED

        document_service.grant(
            db, document_id=brief_id, recipient_id=RECIPIENT,
            actor_id="ADMIN-001", note="re-grant for lease test",
        )
        actor = identity_service.get(db, RECIPIENT)
        nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=brief_id)
        with pytest.raises(AuthorizationDenied) as excinfo:
            decryption_service.decrypt(
                db, actor=actor, document_id=brief_id, device_id=DEVICE,
                nonce=nonce["nonce"], offline=True,
            )
        assert excinfo.value.detail == "OFFLINE_GRANT_REVOKED"


class TestWithdrawalRegister:
    def test_recipient_revocation_enters_the_register_with_its_cascade(self, db, brief_id):
        clear_leases(db, brief_id)
        decrypt_offline(db, brief_id)
        revocation.revoke_recipient(
            db, recipient_id=RECIPIENT, actor_id="SECURITY-001", reason="register test"
        )
        row = db.execute(
            select(Revocation).where(
                Revocation.subject_type == "USER", Revocation.subject_id == RECIPIENT
            )
        ).scalars().first()
        assert row is not None
        assert row.history_preserved is True
        lease = latest_lease(db, brief_id)
        assert lease.status == offline_grants.GRANT_REVOKED
        assert f"offline_grant:{lease.offline_grant_id}" in json.loads(row.cascaded_to)

        recipient = db.get(Recipient, RECIPIENT)
        recipient.status = AccountStatus.ACTIVE
        recipient.revoked_at = None
        recipient.revocation_reason = None
        revocation.register_device(
            db, device_id=DEVICE, recipient_id=RECIPIENT,
            device_name="restored for later tests", fingerprint="fp-restore-register",
            actor_id="SECURITY-001",
        )
        db.flush()

    def test_document_revocation_enters_the_register_and_kills_its_windows(self, db):
        document_id = scratch_document(db, title="OFFLINE TEST REVOKE DOC")
        decrypt_offline(db, document_id)
        lease = latest_lease(db, document_id)
        assert lease.status == offline_grants.GRANT_ACTIVE

        document_service.transition(
            db, document_id=document_id, target=DocumentLifecycle.REVOKED,
            actor_id="SECURITY-001", reason="withdraw the document entirely",
        )
        row = db.execute(
            select(Revocation).where(
                Revocation.subject_type == "DOCUMENT", Revocation.subject_id == document_id
            )
        ).scalars().first()
        assert row is not None
        db.refresh(lease)
        assert lease.status == offline_grants.GRANT_REVOKED

    def test_the_register_refuses_rewrites(self, db):
        revocation_id = revocation.record_revocation(
            db, subject_type="USER", subject_id="RECIPIENT-002", scope="ALL",
            reason="append-only check", actor_id="SECURITY-001",
        )
        db.flush()
        with pytest.raises(Exception):
            db.execute(
                text("UPDATE revocations SET reason='rewritten' WHERE revocation_id = :rid"),
                {"rid": revocation_id},
            )
        with pytest.raises(Exception):
            db.execute(
                text("DELETE FROM revocations WHERE revocation_id = :rid"),
                {"rid": revocation_id},
            )


class TestRevocationRoutes:
    def test_session_revocation_withdraws_the_artefact(self, client, tokens, brief_id):
        token = tokens["recipient_one"]
        nonce_response = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": brief_id}
        )
        assert nonce_response.status_code == 200, nonce_response.text
        decrypted = client.post(
            "/decrypt",
            headers=headers(token),
            json={
                "document_id": brief_id,
                "device_id": DEVICE,
                "nonce": nonce_response.json()["nonce"],
            },
        )
        assert decrypted.status_code == 200, decrypted.text
        session_id = decrypted.json()["session_id"]

        denied = client.post(
            f"/sessions/{session_id}/revoke",
            headers=headers(tokens["auditor"]),
            json={"reason": "auditor must not revoke"},
        )
        assert denied.status_code == 403

        revoked = client.post(
            f"/sessions/{session_id}/revoke",
            headers=headers(tokens["officer"]),
            json={"reason": "session withdrawal route test"},
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["status"] == "REVOKED"
        assert revoked.json()["history_preserved"] is True

        artefact = client.get(f"/sessions/{session_id}/document", headers=headers(token))
        assert artefact.status_code == 403
        assert artefact.json()["error"]["detail"] == "SESSION_REVOKED"

    def test_access_revocation_route_kills_offline_windows(self, client, tokens):
        with ops_session() as setup:
            document_id = scratch_document(setup, title="OFFLINE TEST ACCESS ROUTE")

        token = tokens["recipient_one"]
        nonce_response = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": document_id}
        )
        decrypted = client.post(
            "/decrypt",
            headers=headers(token),
            json={
                "document_id": document_id,
                "device_id": DEVICE,
                "nonce": nonce_response.json()["nonce"],
                "offline": True,
            },
        )
        assert decrypted.status_code == 200, decrypted.text

        response = client.post(
            f"/documents/{document_id}/access/revoke",
            headers=headers(tokens["officer"]),
            json={"recipient_id": RECIPIENT, "reason": "route cascade test"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["offline_grants_revoked"], "the offline window must die with the grant"

        with ops_session() as check:
            lease = check.execute(
                select(OfflineGrant).where(OfflineGrant.document_id == document_id)
            ).scalars().first()
            assert lease.status == offline_grants.GRANT_REVOKED
