from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import AccountStatus, DeviceTrust, DocumentAccess, KeyStatus
from ..core.exceptions import NotFound
from ..core.identifiers import next_id
from ..crypto.key_management import VAULT
from ..models.documents import Document, RecipientGrant
from ..models.identity import Device, Recipient
from ..models.security import Revocation
from ..models.sessions import DecryptionSession
from ..services import audit_service
from . import incident_engine, offline_grants

REVOCATION_EFFECT = (
    "New decryptions and new sessions fail immediately. Every record of what happened before "
    "this moment is left untouched."
)


def record_revocation(
    session: Session,
    *,
    subject_type: str,
    subject_id: str,
    scope: str,
    reason: str,
    actor_id: str,
    cascaded_to: list[str] | None = None,
) -> str:
    """Appends one entry to the withdrawal register.

    Every revoke path writes here, so "who withdrew what, when and why" has a
    single queryable history that outlives the rows it revokes.
    """
    revocation_id = next_id("REV", width=8)
    row = Revocation(
        revocation_id=revocation_id,
        subject_type=subject_type,
        subject_id=subject_id,
        scope=scope,
        reason=reason,
        revoked_by=actor_id,
        revoked_at=datetime.now(timezone.utc),
        cascaded_to=json.dumps(cascaded_to or []),
    )
    session.add(row)
    session.flush()
    return revocation_id


def revoke_recipient(
    session: Session, *, recipient_id: str, actor_id: str, reason: str
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None:
        raise KeyError(recipient_id)
    moment = datetime.now(timezone.utc)
    recipient.status = AccountStatus.REVOKED
    recipient.revoked_at = moment
    recipient.revocation_reason = reason
    for device in session.execute(select(Device).where(Device.recipient_id == recipient_id)).scalars():
        device.status = "REVOKED"
        device.revoked_at = moment
    dead_leases = offline_grants.revoke(
        session, recipient_id=recipient_id, actor_id=actor_id, reason=reason
    )
    from ..services import sharing_service

    dead_shares = sharing_service.mark_revoked(
        session, actor_id=actor_id, reason=reason, recipient_id=recipient_id
    )

    audit_service.record(
        session,
        actor_id=actor_id,
        action="USER_REVOKED",
        target_type="RECIPIENT",
        target_id=recipient_id,
        detail={"reason": reason, "shares_revoked": dead_shares},
    )
    record_revocation(
        session,
        subject_type="USER",
        subject_id=recipient_id,
        scope="ALL",
        reason=reason,
        actor_id=actor_id,
        cascaded_to=[f"offline_grant:{gid}" for gid in dead_leases]
        + [f"share:{sid}" for sid in dead_shares],
    )
    incident_engine.raise_event(
        session,
        "KEY_COMPROMISE",
        title=f"Recipient {recipient_id} revoked",
        what_happened=f"{recipient_id} was revoked by {actor_id}. Reason: {reason}",
        why_it_matters="The identity can no longer decrypt, and its devices and keys are withdrawn.",
        what_was_affected=f"{recipient_id} and all registered devices",
        recommended_action="Confirm the revocation was intended and review any access before this time.",
        severity="HIGH",
        subject_id=recipient_id,
        actor_id=actor_id,
    )
    return {
        "recipient_id": recipient_id,
        "status": AccountStatus.REVOKED,
        "revoked_at": moment.isoformat(timespec="seconds"),
        "revoked_by": actor_id,
        "reason": reason,
        "history_preserved": True,
        "plain_explanation": REVOCATION_EFFECT,
    }


def suspend_recipient(
    session: Session, *, recipient_id: str, actor_id: str, reason: str
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None:
        raise KeyError(recipient_id)
    recipient.status = AccountStatus.SUSPENDED
    audit_service.record(
        session,
        actor_id=actor_id,
        action="USER_MODIFIED",
        target_type="RECIPIENT",
        target_id=recipient_id,
        detail={"status": AccountStatus.SUSPENDED, "reason": reason},
    )
    return {
        "recipient_id": recipient_id,
        "status": AccountStatus.SUSPENDED,
        "plain_explanation": "Access is paused. A senior officer can restore or revoke it.",
    }


def revoke_device(session: Session, *, device_id: str, actor_id: str, reason: str) -> dict[str, Any]:
    device = session.get(Device, device_id)
    if device is None:
        raise KeyError(device_id)
    device.status = "REVOKED"
    device.revoked_at = datetime.now(timezone.utc)
    dead_leases = offline_grants.revoke(
        session, device_id=device_id, actor_id=actor_id, reason=reason
    )
    audit_service.record(
        session,
        actor_id=actor_id,
        action="DEVICE_REVOKED",
        target_type="DEVICE",
        target_id=device_id,
        detail={"reason": reason, "owner": device.recipient_id},
    )
    record_revocation(
        session,
        subject_type="DEVICE",
        subject_id=device_id,
        scope="DECRYPTION",
        reason=reason,
        actor_id=actor_id,
        cascaded_to=[f"offline_grant:{gid}" for gid in dead_leases],
    )
    incident_engine.raise_event(
        session,
        "DEVICE_NOT_AUTHORIZED",
        title=f"Device {device_id} revoked",
        what_happened=f"Device {device_id} belonging to {device.recipient_id} was revoked by {actor_id}.",
        why_it_matters="Requests from this device are refused even if the recipient's account is still valid.",
        what_was_affected=device_id,
        recommended_action="Register a replacement device through the normal approval process.",
        severity="MEDIUM",
        subject_id=device_id,
        actor_id=actor_id,
    )
    return {
        "device_id": device_id,
        "status": "REVOKED",
        "plain_explanation": "This device can no longer be used for decryption.",
    }


def revoke_key(
    session: Session, *, owner_id: str, purpose: str, actor_id: str, reason: str
) -> dict[str, Any]:
    VAULT.set_status(owner_id, purpose, KeyStatus.REVOKED)
    audit_service.record(
        session,
        actor_id=actor_id,
        action="KEY_REVOKED",
        target_type="KEY",
        target_id=f"{owner_id}:{purpose}",
        detail={"reason": reason},
    )
    record_revocation(
        session,
        subject_type="KEY",
        subject_id=f"{owner_id}:{purpose}",
        scope=purpose,
        reason=reason,
        actor_id=actor_id,
    )
    incident_engine.raise_event(
        session,
        "KEY_COMPROMISE",
        what_happened=f"The {purpose} key of {owner_id} was revoked by {actor_id}. Reason: {reason}",
        why_it_matters="Events signed by this key after the revocation can no longer be attributed with confidence.",
        what_was_affected=f"{owner_id} {purpose} key",
        recommended_action="Issue a fresh key pair and re-verify any evidence signed by the withdrawn key.",
        subject_id=owner_id,
        actor_id=actor_id,
    )
    return {
        "owner_id": owner_id,
        "purpose": purpose,
        "status": KeyStatus.REVOKED,
        "plain_explanation": (
            "The key no longer signs or establishes keys. Records it already signed remain valid evidence."
        ),
    }


def revoke_document_access(
    session: Session, *, document_id: str, recipient_id: str, actor_id: str, reason: str
) -> dict[str, Any]:
    grant = session.execute(
        select(RecipientGrant).where(
            RecipientGrant.document_id == document_id, RecipientGrant.recipient_id == recipient_id
        )
    ).scalar_one_or_none()
    if grant is None:
        raise KeyError(f"{recipient_id} has no grant on {document_id}")
    grant.revoked_at = datetime.now(timezone.utc)
    grant.note = reason
    dead_leases = offline_grants.revoke(
        session,
        document_id=document_id,
        recipient_id=recipient_id,
        actor_id=actor_id,
        reason=reason,
    )
    from ..services import sharing_service

    dead_shares = sharing_service.mark_revoked(
        session,
        actor_id=actor_id,
        reason=reason,
        document_id=document_id,
        recipient_id=recipient_id,
    )
    audit_service.record(
        session,
        actor_id=actor_id,
        action="DOCUMENT_PERMISSION_CHANGED",
        target_type="DOCUMENT_GRANT",
        target_id=grant.grant_id,
        detail={
            "document_id": document_id,
            "recipient_id": recipient_id,
            "reason": reason,
            "shares_revoked": dead_shares,
        },
    )
    record_revocation(
        session,
        subject_type="DOCUMENT_GRANT",
        subject_id=f"{document_id}:{recipient_id}",
        scope="DOCUMENT",
        reason=reason,
        actor_id=actor_id,
        cascaded_to=[f"offline_grant:{gid}" for gid in dead_leases]
        + [f"share:{sid}" for sid in dead_shares],
    )
    return {
        "document_id": document_id,
        "recipient_id": recipient_id,
        "status": "REVOKED",
        "offline_grants_revoked": dead_leases,
        "shares_revoked": dead_shares,
        "plain_explanation": "This recipient can no longer open the document, even though their clearance is unchanged.",
    }


def revoke_session(
    session: Session, *, session_id: str, actor_id: str, reason: str
) -> dict[str, Any]:
    """Withdraws a decryption session: its artefact download is refused from
    now on and any offline lease issued under it dies with it. The signed
    event chain for the session is deliberately left intact — revoking
    authority never rewrites history."""
    row = session.get(DecryptionSession, session_id)
    if row is None:
        raise NotFound(f"No session {session_id}.")
    if row.status == "REVOKED":
        return {
            "session_id": session_id,
            "status": "REVOKED",
            "already_revoked": True,
            "plain_explanation": "This session was already withdrawn.",
        }
    moment = datetime.now(timezone.utc)
    row.status = "REVOKED"
    dead_leases = offline_grants.revoke(
        session, session_id=session_id, actor_id=actor_id, reason=reason
    )
    audit_service.record(
        session,
        actor_id=actor_id,
        action="SESSION_REVOKED",
        target_type="DECRYPTION_SESSION",
        target_id=session_id,
        detail={"document_id": row.document_id, "recipient_id": row.recipient_id, "reason": reason},
    )
    record_revocation(
        session,
        subject_type="SESSION",
        subject_id=session_id,
        scope=row.document_id,
        reason=reason,
        actor_id=actor_id,
        cascaded_to=[f"offline_grant:{gid}" for gid in dead_leases],
    )
    return {
        "session_id": session_id,
        "status": "REVOKED",
        "revoked_at": moment.isoformat(timespec="seconds"),
        "offline_grants_revoked": dead_leases,
        "history_preserved": True,
        "plain_explanation": (
            "This session can no longer deliver its artefact or support offline access. "
            "The signed evidence of what it already did is preserved."
        ),
    }


def suspend_document(session: Session, *, document_id: str, actor_id: str, reason: str) -> dict[str, Any]:
    document = session.get(Document, document_id)
    if document is None:
        raise KeyError(document_id)
    document.status = DocumentAccess.SUSPENDED
    document.suspended_at = datetime.now(timezone.utc)
    audit_service.record(
        session,
        actor_id=actor_id,
        action="DOCUMENT_SUSPENDED",
        target_type="DOCUMENT",
        target_id=document_id,
        detail={"reason": reason},
    )
    return {
        "document_id": document_id,
        "status": DocumentAccess.SUSPENDED,
        "plain_explanation": "Decryption of this document is blocked for everyone until it is restored.",
    }


def register_device(
    session: Session,
    *,
    device_id: str,
    recipient_id: str,
    device_name: str,
    fingerprint: str,
    actor_id: str,
) -> dict[str, Any]:
    """Registers or re-enrols a device.

    Re-enrolment reactivates an existing row rather than refusing, because a
    revoked device that is later returned and re-authorised must be able to come
    back into service without a separate repair path. The original revocation
    stays in the revocation register either way.
    """
    device = session.get(Device, device_id)
    if device is None:
        device = Device(
            device_id=device_id,
            recipient_id=recipient_id,
            device_name=device_name,
            device_fingerprint=fingerprint,
            status="ACTIVE",
            trust_state=DeviceTrust.PENDING,
            registered_at=datetime.now(timezone.utc),
        )
        session.add(device)
        action = "DEVICE_REGISTERED"
    else:
        device.recipient_id = recipient_id
        device.device_name = device_name
        device.device_fingerprint = fingerprint
        device.status = "ACTIVE"
        device.trust_state = DeviceTrust.PENDING
        device.revoked_at = None
        action = "DEVICE_RE_ENROLLED"

    session.flush()
    audit_service.record(
        session,
        actor_id=actor_id,
        action=action,
        target_type="DEVICE",
        target_id=device_id,
        detail={"recipient_id": recipient_id, "device_name": device_name},
    )
    incident_engine.raise_event(
        session,
        "DEVICE_REGISTERED" if action == "DEVICE_REGISTERED" else "DEVICE_RE_ENROLLED",
        title=f"Device {device_id} {'registered' if action == 'DEVICE_REGISTERED' else 're-enrolled'}",
        what_happened=(
            f"{actor_id} {'registered' if action == 'DEVICE_REGISTERED' else 're-enrolled'} device "
            f"{device_id} for {recipient_id}."
        ),
        why_it_matters=(
            "A newly enrolled device is a new endpoint that can request authorised decryption."
        ),
        what_was_affected=device_id,
        recommended_action="Confirm the device physically belongs to the named recipient.",
        severity="LOW",
        subject_id=device_id,
    )
    return {
        "device_id": device_id,
        "recipient_id": recipient_id,
        "status": "ACTIVE",
        "trust_state": device.trust_state,
        "attestation_note": device.attestation_note,
        "plain_explanation": (
            "This device can now request decryption, subject to a trust assessment. It starts at "
            "PENDING until an operator or a hardware attestation process confirms it."
        ),
    }


def next_grant_id() -> str:
    return next_id("GRT", width=6)
