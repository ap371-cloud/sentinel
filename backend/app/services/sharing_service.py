from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import SETTINGS, AccountStatus, Clearance
from ..core.exceptions import ForgeError, NotFound
from ..core.identifiers import next_id
from ..core.rights import effective_rights
from ..core.timeutil import has_expired
from ..models.documents import Document, ShareRequest
from ..models.identity import Recipient
from ..models.security import ApprovalRequest
from . import approval_service, audit_service, document_service

REQUESTED = "SHARE_REQUESTED"
APPROVED = "APPROVED"
DENIED = "DENIED"
REVOKED = "REVOKED"
OPEN_STATES = (REQUESTED, APPROVED)

#: A share always records the rights in force at request time. Narrowing
#: rights per share instead of per document is not enforced here — that would
#: need grant-level rights, and claiming it without it would be dishonest.
LIMITATION = (
    "A share controls who receives need-to-know and until when. The rights "
    "matrix stays the document's own policy (recorded as a snapshot on this "
    "row); per-share rights narrowing is APPLICATION DEPENDENT."
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def preflight(document: Document, target: Recipient) -> list[dict[str, str]]:
    """Identity → clearance → unit → role → policy, re-checked every time.

    The same facts are enforced again, from live state, on every decrypt; this
    pass exists so a share request can be refused with the actual reason
    instead of granting access that would fail later.
    """
    failures: list[dict[str, str]] = []
    if target.status != AccountStatus.ACTIVE:
        failures.append(
            {"code": "TARGET_INACTIVE", "detail": f"The target identity is {target.status}."}
        )
    required = Clearance[document.classification].value
    if target.clearance < required:
        failures.append(
            {
                "code": "CLEARANCE_BELOW_CLASSIFICATION",
                "detail": (
                    f"{target.recipient_id} holds clearance {target.clearance}; "
                    f"{document.classification} needs {required}."
                ),
            }
        )
    units = json.loads(document.need_to_know_units or "[]")
    if units and target.unit not in units:
        failures.append(
            {
                "code": "UNIT_OUT_OF_SCOPE",
                "detail": f"{target.unit} is outside this document's scope {units}.",
            }
        )
    roles = json.loads(document.permitted_roles or "[]")
    if roles and target.role not in roles:
        failures.append(
            {
                "code": "ROLE_NOT_PERMITTED",
                "detail": f"Role {target.role} is outside permitted roles {roles}.",
            }
        )
    if document.status in ("REVOKED", "SUSPENDED"):
        failures.append(
            {"code": f"DOCUMENT_{document.status}", "detail": "The document itself is not shareable."}
        )
    if document_service.is_expired(document):
        failures.append({"code": "DOCUMENT_EXPIRED", "detail": "The document has expired."})
    if not document_service._has_usable_keys(target.recipient_id):
        failures.append(
            {
                "code": "TARGET_HAS_NO_KEYS",
                "detail": "The target has no key-establishment keys, so no content key can reach it.",
            }
        )
    return failures


def _needs_second_approval(session: Session, document: Document) -> bool:
    return bool(
        document.second_approval_required
        or document.classification in ("SECRET", "TOP_SECRET")
        or approval_service.requires_two_person(session, "DOCUMENT_SHARING")
    )


def request_share(
    session: Session,
    *,
    document_id: str,
    target_recipient_id: str,
    requested_by: str,
    justification: str,
    expires_in_days: int = 0,
) -> dict[str, Any]:
    document = session.get(Document, document_id)
    if document is None:
        raise NotFound(f"No document {document_id}.")
    target = session.get(Recipient, target_recipient_id)
    if target is None:
        raise NotFound(f"No identity {target_recipient_id}.")
    if len(justification.strip()) < 10:
        raise ForgeError("A written justification of at least 10 characters is required.")
    if document_service.has_active_grant(session, document_id, target_recipient_id):
        return {
            "document_id": document_id,
            "recipient_id": target_recipient_id,
            "status": "ALREADY_GRANTED",
            "plain_explanation": "This identity already holds need-to-know on this document.",
        }

    expires_at = _utcnow() + timedelta(days=expires_in_days) if expires_in_days else None
    snapshot = json.dumps(effective_rights(document), sort_keys=True)

    failures = preflight(document, target)
    if failures:
        share = _record(
            session,
            document=document,
            target_recipient_id=target_recipient_id,
            requested_by=requested_by,
            justification=justification,
            status=DENIED,
            reason="; ".join(f["code"] for f in failures),
            rights_snapshot=snapshot,
            expires_at=expires_at,
        )
        audit_service.record(
            session,
            actor_id=requested_by,
            action="SHARE_DENIED",
            target_type="SHARE",
            target_id=share.share_id,
            detail={
                "document_id": document_id,
                "recipient_id": target_recipient_id,
                "failures": failures,
                "justification": justification,
            },
        )
        return {
            **describe(session, share),
            "failures": failures,
            "plain_explanation": "The share was refused after verification of the target identity.",
        }

    if _needs_second_approval(session, document):
        approval = approval_service.request(
            session,
            action="DOCUMENT_SHARING",
            requested_by=requested_by,
            justification=justification,
            subject_id=document_id,
            required_approvals=1,
        )
        share = _record(
            session,
            document=document,
            target_recipient_id=target_recipient_id,
            requested_by=requested_by,
            justification=justification,
            status=REQUESTED,
            rights_snapshot=snapshot,
            expires_at=expires_at,
            approval_id=approval["approval_id"],
        )
        audit_service.record(
            session,
            actor_id=requested_by,
            action="SHARE_REQUESTED",
            target_type="SHARE",
            target_id=share.share_id,
            detail={
                "document_id": document_id,
                "recipient_id": target_recipient_id,
                "approval_id": approval["approval_id"],
                "expires_at": expires_at.isoformat(timespec="seconds") if expires_at else None,
                "justification": justification,
            },
        )
        result = describe(session, share)
        result["approval"] = approval
        result["plain_explanation"] = (
            "The share is recorded but grants nothing yet: a second, different "
            "authorised identity must approve it first."
        )
        return result

    return _approve_now(
        session,
        document=document,
        target_recipient_id=target_recipient_id,
        requested_by=requested_by,
        justification=justification,
        rights_snapshot=snapshot,
        expires_at=expires_at,
        decided_by=requested_by,
    )


def _approve_now(
    session: Session,
    *,
    document: Document,
    target_recipient_id: str,
    requested_by: str,
    justification: str | None,
    rights_snapshot: str | None,
    expires_at: datetime | None,
    decided_by: str,
    approval_id: str | None = None,
) -> dict[str, Any]:
    share = _record(
        session,
        document=document,
        target_recipient_id=target_recipient_id,
        requested_by=requested_by,
        justification=justification,
        status=APPROVED,
        rights_snapshot=rights_snapshot,
        expires_at=expires_at,
        approval_id=approval_id,
        decided_by=decided_by,
        decided_at=_utcnow(),
    )
    grant = document_service.grant(
        session,
        document_id=document.document_id,
        recipient_id=target_recipient_id,
        actor_id=decided_by,
        note=f"share {share.share_id}",
        expires_at=expires_at,
    )
    share.grant_id = grant.get("grant_id")
    audit_service.record(
        session,
        actor_id=decided_by,
        action="SHARE_APPROVED",
        target_type="SHARE",
        target_id=share.share_id,
        detail={
            "document_id": document.document_id,
            "recipient_id": target_recipient_id,
            "grant_id": share.grant_id,
            "approval_id": approval_id,
            "expires_at": expires_at.isoformat(timespec="seconds") if expires_at else None,
        },
    )
    result = describe(session, share)
    result["grant"] = grant
    result["plain_explanation"] = (
        "The target identity was verified and now holds need-to-know on this document."
    )
    return result


def finalize(
    session: Session, *, approval_id: str, approver_id: str
) -> dict[str, Any]:
    """Runs the moment a DOCUMENT_SHARING approval is satisfied.

    The target is verified again from live state — approval waits are exactly
    when an identity gets revoked or a document gets withdrawn underneath a
    pending request.
    """
    share = session.execute(
        select(ShareRequest).where(ShareRequest.approval_id == approval_id)
    ).scalar_one_or_none()
    if share is None:
        raise NotFound(f"No share request behind approval {approval_id}.")
    if share.status != REQUESTED:
        return describe(session, share)
    approval = session.get(ApprovalRequest, approval_id)
    if approval is not None and approval.consumed_at is None:
        approval.consumed_at = _utcnow()

    document = session.get(Document, share.document_id)
    target = session.get(Recipient, share.recipient_id)
    failures = (
        preflight(document, target)
        if document is not None and target is not None
        else [{"code": "SUBJECT_MISSING", "detail": "Document or identity vanished while pending."}]
    )
    if failures:
        share.status = DENIED
        share.decided_by = approver_id
        share.decided_at = _utcnow()
        share.reason = "; ".join(f["code"] for f in failures)
        audit_service.record(
            session,
            actor_id=approver_id,
            action="SHARE_DENIED",
            target_type="SHARE",
            target_id=share.share_id,
            detail={
                "document_id": share.document_id,
                "recipient_id": share.recipient_id,
                "approval_id": approval_id,
                "failures": failures,
                "note": "Re-verified at approval time and refused.",
            },
        )
        result = describe(session, share)
        result["failures"] = failures
        result["plain_explanation"] = (
            "Approval was given, but the share was refused anyway because the "
            "target no longer qualifies as of this moment."
        )
        return result

    return _approve_now(
        session,
        document=document,
        target_recipient_id=share.recipient_id,
        requested_by=share.requested_by,
        justification=share.justification,
        rights_snapshot=share.rights_snapshot,
        expires_at=share.expires_at,
        decided_by=approver_id,
        approval_id=approval_id,
    )


def record_denial(
    session: Session, *, approval_id: str, approver_id: str, reason: str
) -> dict[str, Any]:
    share = session.execute(
        select(ShareRequest).where(ShareRequest.approval_id == approval_id)
    ).scalar_one_or_none()
    if share is None:
        return {"approval_id": approval_id, "share": None}
    if share.status == REQUESTED:
        share.status = DENIED
        share.decided_by = approver_id
        share.decided_at = _utcnow()
        share.reason = reason
        audit_service.record(
            session,
            actor_id=approver_id,
            action="SHARE_DENIED",
            target_type="SHARE",
            target_id=share.share_id,
            detail={
                "document_id": share.document_id,
                "recipient_id": share.recipient_id,
                "approval_id": approval_id,
                "reason": reason,
            },
        )
    return describe(session, share)


def mark_revoked(
    session: Session, *, actor_id: str, reason: str, document_id: str | None = None,
    recipient_id: str | None = None,
) -> list[str]:
    """Withdraws open shares along with a grant or identity revocation.

    Called from the revocation paths so a share can never outlive the access
    it was created to hand out.
    """
    if document_id is None and recipient_id is None:
        raise ForgeError("Share revocation needs a document or an identity to act on.")
    statement = select(ShareRequest).where(ShareRequest.status.in_(OPEN_STATES))
    if document_id is not None:
        statement = statement.where(ShareRequest.document_id == document_id)
    if recipient_id is not None:
        statement = statement.where(ShareRequest.recipient_id == recipient_id)
    revoked: list[str] = []
    for share in session.execute(statement).scalars():
        share.status = REVOKED
        share.revoked_at = _utcnow()
        share.reason = reason
        revoked.append(share.share_id)
        audit_service.record(
            session,
            actor_id=actor_id,
            action="SHARE_REVOKED",
            target_type="SHARE",
            target_id=share.share_id,
            detail={
                "document_id": share.document_id,
                "recipient_id": share.recipient_id,
                "reason": reason,
            },
        )
    return revoked


def list_shares(session: Session, *, document_id: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(ShareRequest)
        .where(ShareRequest.document_id == document_id)
        .order_by(ShareRequest.created_at.desc())
    ).scalars()
    return [describe(session, row) for row in rows]


def describe(session: Session, row: ShareRequest) -> dict[str, Any]:
    effective = row.status
    if row.status == APPROVED and row.expires_at is not None and has_expired(row.expires_at):
        effective = "EXPIRED"
    return {
        "share_id": row.share_id,
        "document_id": row.document_id,
        "recipient_id": row.recipient_id,
        "requested_by": row.requested_by,
        "status": row.status,
        "effective_status": effective,
        "justification": row.justification,
        "reason": row.reason,
        "rights_in_effect": json.loads(row.rights_snapshot) if row.rights_snapshot else None,
        "expires_at": row.expires_at.isoformat(timespec="seconds") if row.expires_at else None,
        "approval_id": row.approval_id,
        "decided_by": row.decided_by,
        "decided_at": row.decided_at.isoformat(timespec="seconds") if row.decided_at else None,
        "grant_id": row.grant_id,
        "policy_version": row.policy_version,
        "created_at": row.created_at.isoformat(timespec="seconds"),
        "revoked_at": row.revoked_at.isoformat(timespec="seconds") if row.revoked_at else None,
        "limitation": LIMITATION,
    }


def _record(
    session: Session,
    *,
    document: Document,
    target_recipient_id: str,
    requested_by: str,
    justification: str | None,
    status: str,
    rights_snapshot: str | None,
    expires_at: datetime | None,
    reason: str | None = None,
    approval_id: str | None = None,
    decided_by: str | None = None,
    decided_at: datetime | None = None,
) -> ShareRequest:
    share = ShareRequest(
        share_id=next_id("SHR", width=8),
        document_id=document.document_id,
        recipient_id=target_recipient_id,
        requested_by=requested_by,
        status=status,
        justification=justification,
        reason=reason,
        rights_snapshot=rights_snapshot,
        expires_at=expires_at,
        approval_id=approval_id,
        decided_by=decided_by,
        decided_at=decided_at,
        policy_version=SETTINGS.policy_version,
    )
    session.add(share)
    session.flush()
    return share
