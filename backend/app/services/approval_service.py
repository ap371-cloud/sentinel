from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import SETTINGS, Role
from ..core.exceptions import ApprovalRequired, ForgeError, TwoPersonControlViolation
from ..core.identifiers import next_id
from ..core.timeutil import as_utc
from ..models.identity import Recipient
from ..models.security import ApprovalRequest, Policy
from ..security import incident_engine
from . import audit_service

EXPIRED = "EXPIRED"


def active_policy(session: Session) -> Policy:
    policy = session.execute(select(Policy).where(Policy.active.is_(True)).order_by(Policy.updated_at.desc())).scalar_one_or_none()
    if policy is None:
        policy = Policy(
            policy_id="POL-DEFAULT",
            policy_version=SETTINGS.policy_version,
            name="Baseline command security policy",
            body=json.dumps(
                {
                    "device_access_policy": "ALLOW",
                    "replay_window_seconds": SETTINGS.replay_window_seconds,
                    "break_glass_enabled": True,
                }
            ),
            device_access_policy="ALLOW",
            replay_window_seconds=SETTINGS.replay_window_seconds,
            high_risk_actions=json.dumps(
                [
                    "DOCUMENT_ACCESS_HIGH_CLASSIFICATION",
                    "KEY_RECOVERY",
                    "EMERGENCY_ACCESS",
                    "SECURITY_POLICY_MODIFICATION",
                    "LEDGER_NODE_ADMINISTRATION",
                    "EVIDENCE_EXPORT",
                ]
            ),
            updated_by="SYSTEM",
        )
        session.add(policy)
        session.flush()
    return policy


def high_risk_actions(session: Session) -> list[str]:
    return json.loads(active_policy(session).high_risk_actions or "[]")


def requires_two_person(session: Session, action: str) -> bool:
    return action in high_risk_actions(session)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def request(
    session: Session,
    *,
    action: str,
    requested_by: str,
    justification: str,
    subject_id: str | None = None,
    required_approvals: int = 2,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    """One person's word is never enough. The request stays inert until a
    different, separately authenticated identity approves it."""
    requester = session.get(Recipient, requested_by)
    if requester is None:
        raise TwoPersonControlViolation(f"{requested_by} is not a known identity.")
    if len(justification.strip()) < 10:
        raise ForgeError("A written justification is required for this action.")

    approval_id = next_id("APR")
    row = ApprovalRequest(
        approval_id=approval_id,
        action=action,
        subject_id=subject_id,
        justification=justification,
        requested_by=requested_by,
        required_approvals=required_approvals,
        status="PENDING",
        expires_at=_utcnow() + timedelta(seconds=ttl_seconds or SETTINGS.approval_ttl_seconds),
        approvals=json.dumps([]),
        rejections=json.dumps([]),
    )
    session.add(row)
    audit_service.record(
        session,
        actor_id=requested_by,
        actor_role=requester.role,
        action="APPROVAL_REQUESTED",
        target_type="APPROVAL",
        target_id=approval_id,
        detail={"action": action, "subject_id": subject_id, "justification": justification},
    )
    return describe(row)


def approve(
    session: Session, *, approval_id: str, approver_id: str, approver_role: str
) -> dict[str, Any]:
    row = session.get(ApprovalRequest, approval_id)
    if row is None:
        raise ForgeError(f"No approval request {approval_id}.")
    now = _utcnow()
    if row.status != "PENDING":
        raise ForgeError(f"This request is already {row.status.lower()}.")
    if now > as_utc(row.expires_at):
        row.status = EXPIRED
        raise ForgeError("This approval request has expired. Raise a new request.")
    if approver_id == row.requested_by:
        raise TwoPersonControlViolation(
            "The identity that raised this request cannot also approve it.",
            detail="Two-person control requires two different authenticated identities.",
        )
    if approver_role not in Role.APPROVERS:
        raise ForgeError(f"Role {approver_role} is not authorised to approve high-risk actions.")

    approvals = json.loads(row.approvals or "[]")
    if approver_id in approvals:
        raise ForgeError(f"{approver_id} has already approved this request.")
    approvals.append(approver_id)
    row.approvals = json.dumps(approvals)

    if row.is_satisfied():
        row.status = "APPROVED"
        row.decided_at = now
    audit_service.record(
        session,
        actor_id=approver_id,
        actor_role=approver_role,
        action="APPROVAL_DECIDED",
        target_type="APPROVAL",
        target_id=approval_id,
        detail={
            "decision": "APPROVE",
            "action": row.action,
            "approvals_so_far": len(set(approvals) - {row.requested_by}),
            "required": row.required_approvals,
        },
    )
    return describe(row)


def reject(
    session: Session, *, approval_id: str, approver_id: str, approver_role: str, reason: str
) -> dict[str, Any]:
    row = session.get(ApprovalRequest, approval_id)
    if row is None:
        raise ForgeError(f"No approval request {approval_id}.")
    rejections = json.loads(row.rejections or "[]")
    rejections.append({"approver_id": approver_id, "reason": reason, "at": _utcnow().isoformat(timespec="seconds")})
    row.rejections = json.dumps(rejections)
    row.status = "REJECTED"
    row.decided_at = _utcnow()
    audit_service.record(
        session,
        actor_id=approver_id,
        actor_role=approver_role,
        action="APPROVAL_DECIDED",
        target_type="APPROVAL",
        target_id=approval_id,
        detail={"decision": "REJECT", "reason": reason},
    )
    return describe(row)


def consume(session: Session, *, approval_id: str, acting_role: str, expected_action: str | None = None) -> ApprovalRequest:
    """An approval is single-use so an approved emergency cannot be replayed for
    repeated access."""
    row = session.get(ApprovalRequest, approval_id)
    if row is None:
        raise ForgeError(f"No approval request {approval_id}.")
    if row.status != "APPROVED":
        raise ApprovalRequired(
            f"This action is still awaiting approval (current state: {row.status}).",
            detail=f"{row.required_approvals} separate approvals are required.",
        )
    if row.consumed_at is not None:
        raise ForgeError("This approval has already been used.")
    if _utcnow() > as_utc(row.expires_at):
        row.status = EXPIRED
        raise ForgeError("This approval has expired.")
    if expected_action and row.action != expected_action:
        raise ForgeError(f"Approval covers {row.action}, not {expected_action}.")
    row.consumed_at = _utcnow()
    audit_service.record(
        session,
        actor_id=row.requested_by,
        actor_role=acting_role,
        action="APPROVAL_DECIDED",
        target_type="APPROVAL",
        target_id=approval_id,
        detail={"decision": "CONSUMED", "action": row.action},
    )
    return row


def request_break_glass(
    session: Session, *, recipient_id: str, document_id: str, reason: str
) -> dict[str, Any]:
    result = request(
        session,
        action="EMERGENCY_ACCESS",
        requested_by=recipient_id,
        justification=reason,
        subject_id=document_id,
    )
    incident_engine.raise_event(
        session,
        "EMERGENCY_ACCESS",
        what_happened=(
            f"{recipient_id} requested emergency access to {document_id}. Justification: {reason}"
        ),
        why_it_matters="Emergency access bypasses a normal authorisation rule and must be reviewed afterwards.",
        what_was_affected=document_id,
        recommended_action="A second authorised officer must approve or reject this request.",
        subject_id=recipient_id,
        document_id=document_id,
    )
    result["next_step"] = (
        "A second authorised identity must approve this request before any decryption is possible."
    )
    return result


def describe(row: ApprovalRequest) -> dict[str, Any]:
    approvals = json.loads(row.approvals or "[]")
    rejections = json.loads(row.rejections or "[]")
    counted = len(set(approvals) - {row.requested_by})
    return {
        "approval_id": row.approval_id,
        "action": row.action,
        "subject_id": row.subject_id,
        "justification": row.justification,
        "requested_by": row.requested_by,
        "required_approvals": row.required_approvals,
        "approvals_recorded": approvals,
        "approvals_counted": counted,
        "approvals_remaining": max(0, row.required_approvals - counted),
        "rejections": rejections,
        "status": row.status,
        "created_at": row.created_at.isoformat(timespec="seconds"),
        "expires_at": row.expires_at.isoformat(timespec="seconds"),
        "consumed": row.consumed_at is not None,
        "sufficient": row.is_satisfied(),
        "plain_explanation": (
            f"{counted} of {row.required_approvals} required approvals recorded. "
            "The requester can never be one of the approvers."
        ),
    }


def list_requests(session: Session, *, status: str | None = None) -> list[dict[str, Any]]:
    statement = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    if status:
        statement = statement.where(ApprovalRequest.status == status)
    return [describe(row) for row in session.execute(statement).scalars()]
