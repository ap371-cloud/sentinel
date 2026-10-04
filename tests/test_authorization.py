"""Authorisation tests: RBAC, ABAC, need-to-know, device binding, revocation.

Every control has at least one negative test. A security mechanism that has only
a positive test has not been shown to work.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.core.config import Clearance, DeviceAccessPolicy, DocumentAccess, Role
from app.core.exceptions import (
    ApprovalRequired,
    AuthorizationDenied,
    DeviceNotAuthorized,
    LockdownActive,
    RecipientRevoked,
)
from app.core.permissions import (
    AUDITOR_FORBIDDEN,
    PERMISSIONS,
    RequestContext,
    evaluate_decryption,
    has_permission,
    raise_for_decision,
    require_permission,
    require_writable,
    separation_of_duties_report,
)
from app.security import lockdown, revocation
from app.services import approval_service, document_service, identity_service

# conftest lives beside this module and is not importable as a package because
# the suite runs from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import decrypt_once  # noqa: E402


def context(**overrides) -> RequestContext:
    base = dict(
        actor_id="RECIPIENT-001",
        role=Role.RECIPIENT,
        unit="BRAVO",
        clearance=Clearance.CONFIDENTIAL.value,
        account_status="ACTIVE",
        device_id="DEV-1",
        document_classification=Clearance.CONFIDENTIAL.value,
        document_status=DocumentAccess.SEALED,
        document_unit_scope=["BRAVO"],
        document_role_scope=[Role.RECIPIENT],
        granted=True,
        device_status="ACTIVE",
        device_trust="TRUSTED",
        device_owner_id="RECIPIENT-001",
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


class TestRolePermissions:
    def test_no_role_holds_every_permission(self):
        everything = set().union(*PERMISSIONS.values())
        for role, granted in PERMISSIONS.items():
            assert granted != everything, f"{role} holds every permission"

    def test_administrator_holds_no_evidence_or_ledger_authority(self):
        """The role that manages identities must not be able to forge attribution
        or rewrite the ledger, otherwise one compromised account could both act
        and erase the record of acting."""
        admin = PERMISSIONS[Role.DOCUMENT_ADMIN]
        assert "forensics.analyze" not in admin
        assert "investigation.manage" not in admin
        assert "evidence.export" not in admin
        assert "ledger.admin" not in admin
        assert "approval.decide" not in admin
        assert "incident.manage" not in admin

    def test_investigator_cannot_approve_their_own_export(self):
        investigator = PERMISSIONS[Role.INVESTIGATOR]
        assert "evidence.export" in investigator
        assert "approval.decide" not in investigator

    def test_auditor_is_read_only(self):
        for permission in AUDITOR_FORBIDDEN:
            assert permission not in PERMISSIONS[Role.AUDITOR], permission

    def test_require_writable_refuses_auditor(self):
        with pytest.raises(AuthorizationDenied):
            require_writable(Role.AUDITOR)

    def test_separation_report_is_populated(self):
        report = separation_of_duties_report()
        assert len(report) == len(PERMISSIONS)
        admin = next(row for row in report if row["role"] == Role.DOCUMENT_ADMIN)
        assert admin["holds_evidence_authority"] is False
        assert admin["holds_ledger_write_authority"] is False
        assert admin["holds_approval_authority"] is False

    def test_unknown_permission_is_refused(self):
        assert not has_permission(Role.COMMANDER, "document.decrypt")
        with pytest.raises(AuthorizationDenied):
            require_permission(Role.COMMANDER, "document.decrypt")


class TestAttributeEvaluation:
    def test_fully_authorised_request_is_allowed(self):
        decision = evaluate_decryption(context())
        assert decision.allowed is True
        assert decision.reason_code == "ACCESS_GRANTED"
        assert all(check.passed for check in decision.checks)

    def test_revoked_account_is_refused(self):
        decision = evaluate_decryption(context(account_status="REVOKED"))
        assert decision.allowed is False
        assert decision.reason_code == "ACCOUNT_REVOKED"

    def test_missing_need_to_know_is_refused_despite_clearance(self):
        """The headline case: sufficient clearance is not sufficient on its own."""
        decision = evaluate_decryption(
            context(clearance=Clearance.TOP_SECRET.value, granted=False)
        )
        assert decision.allowed is False
        assert decision.reason_code == "NEED_TO_KNOW_MISSING"

    def test_insufficient_clearance_is_refused(self):
        decision = evaluate_decryption(
            context(clearance=Clearance.RESTRICTED.value, document_classification=Clearance.SECRET.value)
        )
        assert decision.allowed is False
        assert decision.reason_code == "CLEARANCE_BELOW_SECRET"

    def test_out_of_scope_unit_is_refused(self):
        decision = evaluate_decryption(context(unit="CHARLIE", document_unit_scope=["ALPHA"]))
        assert decision.allowed is False
        assert decision.reason_code == "UNIT_OUT_OF_SCOPE"

    def test_role_not_in_policy_is_refused(self):
        decision = evaluate_decryption(context(role=Role.SENDER, document_role_scope=[Role.RECIPIENT]))
        assert decision.allowed is False
        assert decision.reason_code == "ROLE_NOT_PERMITTED"

    def test_unregistered_device_is_refused(self):
        decision = evaluate_decryption(context(device_status=None, device_trust=None))
        assert decision.allowed is False
        assert decision.reason_code == "DEVICE_NOT_REGISTERED"

    def test_device_belonging_to_another_identity_is_refused(self):
        decision = evaluate_decryption(context(device_owner_id="RECIPIENT-002"))
        assert decision.allowed is False
        assert decision.reason_code == "DEVICE_NOT_AUTHORIZED"

    def test_compromised_device_is_refused(self):
        decision = evaluate_decryption(context(device_trust="COMPROMISED"))
        assert decision.allowed is False
        assert decision.reason_code == "DEVICE_COMPROMISED"

    def test_device_policy_deny_overrides_everything(self):
        decision = evaluate_decryption(context(), device_policy=DeviceAccessPolicy.DENY)
        assert decision.allowed is False
        assert decision.reason_code == "DEVICE_POLICY_DENY"

    def test_second_approval_policy_is_signalled(self):
        decision = evaluate_decryption(context(), device_policy=DeviceAccessPolicy.REQUIRE_SECOND_APPROVAL)
        assert decision.allowed is True
        assert decision.requires_second_approval is True
        with pytest.raises(ApprovalRequired):
            raise_for_decision(decision)

    def test_suspended_document_is_refused(self):
        decision = evaluate_decryption(context(document_status=DocumentAccess.SUSPENDED))
        assert decision.allowed is False
        assert decision.reason_code == "DOCUMENT_SUSPENDED"

    def test_revoked_document_is_refused(self):
        decision = evaluate_decryption(context(document_status=DocumentAccess.REVOKED))
        assert decision.allowed is False
        assert decision.reason_code == "DOCUMENT_REVOKED"

    def test_expired_document_is_refused(self):
        decision = evaluate_decryption(context(document_expired=True))
        assert decision.allowed is False
        assert decision.reason_code == "DOCUMENT_EXPIRED"

    def test_revoked_signing_key_is_refused(self):
        decision = evaluate_decryption(context(signing_key_status="REVOKED"))
        assert decision.allowed is False
        assert decision.reason_code == "KEY_REVOKED"

    def test_expired_signing_key_is_refused(self):
        decision = evaluate_decryption(context(signing_key_expired=True))
        assert decision.allowed is False
        assert decision.reason_code == "KEY_EXPIRED"

    def test_consumed_nonce_is_refused(self):
        decision = evaluate_decryption(context(nonce_consumed=True))
        assert decision.allowed is False
        assert decision.reason_code == "NONCE_REPLAYED_OR_INVALID"

    def test_session_budget_is_enforced(self):
        decision = evaluate_decryption(context(session_budget_exhausted=True))
        assert decision.allowed is False
        assert decision.reason_code == "MAXIMUM_SESSIONS_REACHED"

    def test_offline_operation_follows_document_policy(self):
        allowed = evaluate_decryption(context(offline_requested=True, offline_allowed=True))
        assert allowed.allowed is True
        refused = evaluate_decryption(context(offline_requested=True, offline_allowed=False))
        assert refused.allowed is False
        assert refused.reason_code == "OFFLINE_NOT_PERMITTED"

    def test_lockdown_blocks_unless_break_glass_approved(self):
        blocked = evaluate_decryption(context(lockdown_active=True))
        assert blocked.allowed is False
        assert blocked.reason_code == "EMERGENCY_LOCKDOWN_ACTIVE"
        permitted = evaluate_decryption(context(lockdown_active=True, break_glass_approved=True))
        assert permitted.allowed is True

    def test_trace_explains_every_check(self):
        trace = evaluate_decryption(context(granted=False)).trace()
        assert len(trace) >= 12
        failed = [row for row in trace if not row["passed"]]
        assert failed and failed[0]["plain_explanation"]

    def test_first_failure_is_reported(self):
        decision = evaluate_decryption(context(granted=False, clearance=0))
        assert decision.reason_code == "NEED_TO_KNOW_MISSING"


class TestErrorMapping:
    def test_revoked_recipient_raises_specific_error(self):
        with pytest.raises(RecipientRevoked):
            raise_for_decision(evaluate_decryption(context(account_status="REVOKED")))

    def test_device_failure_raises_specific_error(self):
        with pytest.raises(DeviceNotAuthorized):
            raise_for_decision(evaluate_decryption(context(device_trust="SUSPICIOUS")))

    def test_lockdown_raises_specific_error(self):
        with pytest.raises(LockdownActive):
            raise_for_decision(evaluate_decryption(context(lockdown_active=True)))


class TestRevocationAtRuntime:
    def test_revoked_recipient_cannot_decrypt(self, db, brief_id):
        revocation.revoke_recipient(
            db, recipient_id="RECIPIENT-002", actor_id="SECURITY-001", reason="unit test revocation"
        )
        with pytest.raises((RecipientRevoked, AuthorizationDenied)):
            decrypt_once(
                db, recipient_id="RECIPIENT-002", document_id=brief_id, device_id="DEV-RECIPIENT-002-A"
            )

    def test_revocation_preserves_history(self, db):
        from app.models.sessions import DecryptionEvent
        from sqlalchemy import select

        before = db.execute(select(DecryptionEvent)).scalars().all()
        revocation.revoke_recipient(
            db, recipient_id="RECIPIENT-002", actor_id="SECURITY-001", reason="history preservation check"
        )
        after = db.execute(select(DecryptionEvent)).scalars().all()
        assert len(after) >= len(before)

    def test_revoked_device_is_refused(self, db, brief_id):
        device_id = "DEV-RECIPIENT-001-A"
        revocation.revoke_device(db, device_id=device_id, actor_id="SECURITY-001", reason="unit test")
        with pytest.raises((DeviceNotAuthorized, AuthorizationDenied)):
            decrypt_once(
                db, recipient_id="RECIPIENT-001", document_id=brief_id, device_id=device_id
            )
        revocation.register_device(
            db,
            device_id=device_id,
            recipient_id="RECIPIENT-001",
            device_name="restored",
            fingerprint="fp-restored",
            actor_id="SECURITY-001",
        )


class TestTwoPersonControl:
    def test_single_approval_is_insufficient(self, db):
        approval = approval_service.request(
            db,
            action="EVIDENCE_EXPORT",
            requested_by="INVESTIGATOR-001",
            justification="unit test justification for two-person control",
        )
        assert approval["sufficient"] is False
        result = approval_service.approve(
            db, approval_id=approval["approval_id"], approver_id="COMMANDER-001", approver_role=Role.COMMANDER
        )
        assert result["sufficient"] is False
        assert result["status"] == "PENDING"
        with pytest.raises(ApprovalRequired):
            approval_service.consume(db, approval_id=approval["approval_id"], acting_role="INVESTIGATOR")

    def test_requester_cannot_approve(self, db):
        approval = approval_service.request(
            db,
            action="EMERGENCY_ACCESS",
            requested_by="COMMANDER-001",
            justification="unit test justification for self approval check",
        )
        from app.core.exceptions import TwoPersonControlViolation

        with pytest.raises(TwoPersonControlViolation):
            approval_service.approve(
                db,
                approval_id=approval["approval_id"],
                approver_id="COMMANDER-001",
                approver_role=Role.COMMANDER,
            )

    def test_two_distinct_approvers_satisfy_the_control(self, db):
        approval = approval_service.request(
            db,
            action="EVIDENCE_EXPORT",
            requested_by="INVESTIGATOR-001",
            justification="unit test justification for two distinct approvers",
        )
        approval_service.approve(
            db, approval_id=approval["approval_id"], approver_id="COMMANDER-001", approver_role=Role.COMMANDER
        )
        final = approval_service.approve(
            db, approval_id=approval["approval_id"], approver_id="SECURITY-001", approver_role=Role.SECURITY_OFFICER
        )
        assert final["sufficient"] is True
        assert final["status"] == "APPROVED"

    def test_approval_is_single_use(self, db):
        approval = approval_service.request(
            db,
            action="EVIDENCE_EXPORT",
            requested_by="INVESTIGATOR-001",
            justification="unit test justification for single use approval",
        )
        for approver, role in (("COMMANDER-001", Role.COMMANDER), ("SECURITY-001", Role.SECURITY_OFFICER)):
            approval_service.approve(
                db, approval_id=approval["approval_id"], approver_id=approver, approver_role=role
            )
        approval_service.consume(db, approval_id=approval["approval_id"], acting_role="INVESTIGATOR")
        with pytest.raises(Exception):
            approval_service.consume(db, approval_id=approval["approval_id"], acting_role="INVESTIGATOR")

    def test_non_approver_role_cannot_approve(self, db):
        from app.core.exceptions import ForgeError

        approval = approval_service.request(
            db,
            action="EVIDENCE_EXPORT",
            requested_by="INVESTIGATOR-001",
            justification="unit test justification for role enforcement",
        )
        with pytest.raises(ForgeError):
            approval_service.approve(
                db,
                approval_id=approval["approval_id"],
                approver_id="LEDGER-001",
                approver_role=Role.LEDGER_OPERATOR,
            )
