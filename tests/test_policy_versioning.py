"""Policy versioning: POL-x.y history, per-decision digests, and the rule that a
recorded decision is never re-read under a later policy."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.conftest import headers

from app.core.config import Role, SETTINGS
from app.core.exceptions import ApprovalRequired, ForgeError
from app.database.session import ops_session
from app.models.security import ApprovalRequest, Policy, Revocation
from app.security import revocation
from app.services import (
    approval_service,
    decryption_service,
    document_service,
    identity_service,
)

RECIPIENT = "RECIPIENT-001"
DEVICE = "DEV-RECIPIENT-001-A"
GRANTER = "ADMIN-001"


def decrypt(db, document_id: str) -> dict:
    actor = identity_service.get(db, RECIPIENT)
    nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=document_id)
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=DEVICE, nonce=nonce["nonce"]
    )


def approve_update(db, changes: dict, *, reason: str, major: bool = False) -> dict:
    requested = approval_service.request(
        db,
        action="SECURITY_POLICY_MODIFICATION",
        requested_by=GRANTER,
        justification=reason,
        required_approvals=1,
    )
    approval_service.approve(
        db,
        approval_id=requested["approval_id"],
        approver_id="COMMANDER-001",
        approver_role=Role.COMMANDER,
    )
    return approval_service.update_policy(
        db,
        actor_id=GRANTER,
        actor_role=Role.DOCUMENT_ADMIN,
        changes=changes,
        reason=reason,
        approval_id=requested["approval_id"],
        bump_major=major,
    )


class TestPolicyDigest:
    def test_default_policy_ships_with_a_stable_digest(self, db):
        row = approval_service.active_policy(db)
        assert row.policy_version == SETTINGS.policy_version
        assert len(row.policy_hash) == 64
        assert row.policy_hash == approval_service.policy_hash(approval_service.policy_config(row))

    def test_route_exposes_current_policy_and_history(self, client, tokens):
        body = client.get("/documents/policies/current", headers=headers(tokens["recipient_one"])).json()
        assert len(body["policy"]["policy_hash"]) == 64
        assert body["policy"]["policy_version"] == SETTINGS.policy_version
        assert [v["policy_version"] for v in body["versions"]][0] == SETTINGS.policy_version

    def test_archived_version_keeps_its_hash_when_superseded(self, db):
        row = approval_service.active_policy(db)
        original_hash = row.policy_hash
        result = approve_update(db, {"replay_window_seconds": 90}, reason="Widen the replay window for field exercises")
        assert result["policy_version"] == "POL-1.1"
        assert result["previous_version"] == "POL-1.0"
        history = approval_service.policy_history(db)
        versions = [h["policy_version"] for h in history]
        assert versions[:2] == ["POL-1.1", "POL-1.0"]
        archived = next(h for h in history if h["policy_version"] == "POL-1.0")
        assert archived["active"] is False
        assert archived["policy_hash"] == original_hash
        assert archived["hash_verified"] is True

    def test_major_bump_is_explicit(self, db):
        result = approve_update(db, {"name": "Hardened baseline"}, reason="Promote the hardened baseline to a new major line", major=True)
        assert result["policy_version"] == "POL-2.0"


class TestTwoPersonGate:
    def test_policy_change_is_refused_without_an_approval(self, db):
        with pytest.raises(ApprovalRequired):
            approval_service.update_policy(
                db,
                actor_id=GRANTER,
                actor_role=Role.DOCUMENT_ADMIN,
                changes={"replay_window_seconds": 120},
                reason="Widen the replay window for field exercises",
            )

    def test_unknown_setting_is_refused(self, db):
        with pytest.raises(ForgeError):
            approval_service.update_policy(
                db,
                actor_id=GRANTER,
                actor_role=Role.DOCUMENT_ADMIN,
                changes={"sleep_mode": True},
                reason="No such setting should ever be accepted",
            )

    def test_invalid_values_are_refused(self, db):
        for changes in (
            {"replay_window_seconds": 3},
            {"replay_window_seconds": "100"},
            {"device_access_policy": "MAYBE"},
            {"break_glass_enabled": "yes"},
            {"high_risk_actions": "EVIDENCE_EXPORT"},
        ):
            with pytest.raises(ForgeError):
                approval_service.update_policy(
                    db,
                    actor_id=GRANTER,
                    actor_role=Role.DOCUMENT_ADMIN,
                    changes=changes,
                    reason="These changes must be rejected on validation",
                )

    def test_wrong_approval_action_is_refused(self, db):
        requested = approval_service.request(
            db,
            action="EVIDENCE_EXPORT",
            requested_by=GRANTER,
            justification="Export the forensics bundle for the review board",
            required_approvals=1,
        )
        approval_service.approve(
            db,
            approval_id=requested["approval_id"],
            approver_id="COMMANDER-001",
            approver_role=Role.COMMANDER,
        )
        with pytest.raises(ForgeError):
            approval_service.update_policy(
                db,
                actor_id=GRANTER,
                actor_role=Role.DOCUMENT_ADMIN,
                changes={"name": "Wrong approval"},
                reason="This approval does not cover a policy change",
                approval_id=requested["approval_id"],
            )


class TestDecisionVersioning:
    def test_a_recorded_decision_keeps_its_version_after_a_policy_change(self, db, brief_id):
        pre_change_version = approval_service.active_policy(db).policy_version
        first = decrypt(db, brief_id)
        first_description = decryption_service.describe_session(db, first["session_id"])
        assert first_description["policy_version"] == pre_change_version
        assert first_description["policy_hash"] == approval_service.policy_hash_for(
            db, pre_change_version
        )
        assert first_description["authorization_checks"]

        approve_update(db, {"replay_window_seconds": 150}, reason="Extend the replay window for the night shift")
        assert approval_service.active_policy(db).policy_version != pre_change_version

        second = decrypt(db, brief_id)
        second_description = decryption_service.describe_session(db, second["session_id"])
        assert second_description["policy_version"] == approval_service.active_policy(db).policy_version
        assert second_description["policy_version"] != pre_change_version
        assert first_description["policy_version"] == pre_change_version
        assert first_description["policy_hash"] == approval_service.policy_hash_for(db, pre_change_version)

    def test_policy_hash_reaches_document_describe(self, db, brief_id):
        described = document_service.describe(db, brief_id)
        assert described["policy_hash"] == approval_service.policy_hash_for(db, described["policy"]["policy_version"])


class TestEventsCarryTheVersion:
    def test_approval_requests_record_the_version(self, db):
        requested = approval_service.request(
            db,
            action="EMERGENCY_ACCESS",
            requested_by="RECIPIENT-001",
            justification="The forward post needs the annex before the shift ends.",
            subject_id="DOC-002",
        )
        assert requested["policy_version"] == approval_service.active_policy(db).policy_version

    def test_revocations_record_the_version(self, db):
        revocation.record_revocation(
            db,
            subject_type="DEVICE",
            subject_id="DEV-SCUTTLE-001",
            scope="DEVICE",
            reason="test-only scuttle entry",
            actor_id="SECURITY-001",
        )
        row = db.query(Revocation).filter_by(subject_id="DEV-SCUTTLE-001").order_by(Revocation.revoked_at.desc()).first()
        assert row.policy_version == approval_service.active_policy(db).policy_version


class TestTamperEvidence:
    def test_an_edited_hash_digest_is_visible_in_history(self, db):
        row = approval_service.active_policy(db)
        row.policy_hash = "0" * 64
        db.flush()
        described = next(h for h in approval_service.policy_history(db) if h["policy_version"] == row.policy_version)
        assert described["hash_verified"] is False

    def test_full_http_two_person_flow(self, client, tokens):
        created = client.post(
            "/approvals",
            json={
                "action": "SECURITY_POLICY_MODIFICATION",
                "subject_id": None,
                "justification": "Reduce the replay window to ninety seconds for operations.",
                "required_approvals": 2,
            },
            headers=headers(tokens["admin"]),
        )
        assert created.status_code == 200, created.text
        approval_id = created.json()["approval_id"]
        for approver in ("commander", "officer"):
            decided = client.post(
                f"/approvals/{approval_id}/approve",
                json={"reason": "Approved for the ops tempo."},
                headers=headers(tokens[approver]),
            )
            assert decided.status_code == 200, decided.text
        changed = client.post(
            "/policies",
            json={
                "changes": {"replay_window_seconds": 90},
                "reason": "Reduce the replay window to ninety seconds for operations.",
                "approval_id": approval_id,
            },
            headers=headers(tokens["admin"]),
        )
        assert changed.status_code == 200, changed.text
        body = changed.json()
        assert body["policy_version"] != SETTINGS.policy_version
        assert len(body["policy_hash"]) == 64
        assert body["approval_id"] == approval_id