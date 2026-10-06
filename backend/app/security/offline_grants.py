from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.identifiers import next_id
from ..core.timeutil import has_expired
from ..models.documents import Document, OfflineGrant
from ..services import audit_service

GRANT_ACTIVE = "ACTIVE"
GRANT_EXPIRED = "EXPIRED"
GRANT_SUPERSEDED = "SUPERSEDED"
GRANT_REVOKED = "REVOKED"

#: Reasons returned by evaluate(); the first two mean "no usable lease exists
#: yet", the others are hard denials that only a fresh online session (or a
#: new document policy) can clear.
ALLOW_NEW = "OFFLINE_GRANT_NEW"
ALLOW_RENEWED = "OFFLINE_GRANT_RENEWED"
DENY_EXPIRED = "OFFLINE_GRANT_EXPIRED"
DENY_REVOKED = "OFFLINE_GRANT_REVOKED"


def _latest_lease(
    session: Session, *, document_id: str, recipient_id: str, device_id: str
) -> OfflineGrant | None:
    return session.execute(
        select(OfflineGrant)
        .where(
            OfflineGrant.document_id == document_id,
            OfflineGrant.recipient_id == recipient_id,
            OfflineGrant.device_id == device_id,
        )
        .order_by(OfflineGrant.granted_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def evaluate(
    session: Session, *, document: Document, recipient_id: str, device_id: str
) -> tuple[bool, str, OfflineGrant | None]:
    """Decides whether an offline-mode decryption may proceed on this device.

    A revoked lease refuses the offline path until one authenticated online
    session supersedes it — the withdrawal itself is never undone (it stays in
    the append-only register), but an operator who restores access must not
    have to re-enrol the device to give offline use back. An expired lease
    follows the same reconnect-to-renew rule.
    """
    lease = _latest_lease(
        session,
        document_id=document.document_id,
        recipient_id=recipient_id,
        device_id=device_id,
    )
    if lease is None:
        return True, ALLOW_NEW, None
    if lease.status == GRANT_REVOKED:
        return False, DENY_REVOKED, lease
    if lease.status == GRANT_SUPERSEDED:
        return True, ALLOW_RENEWED, lease

    moment = datetime.now(timezone.utc)
    if lease.expires_at is not None and has_expired(lease.expires_at, reference=moment):
        if lease.status != GRANT_EXPIRED:
            # Self-heal the status so the row matches what evaluate() decided.
            lease.status = GRANT_EXPIRED
            lease.closed_at = moment
            lease.closed_reason = "Lease window elapsed."
        return False, DENY_EXPIRED, lease
    return True, ALLOW_NEW, lease


def issue(
    session: Session,
    *,
    document: Document,
    recipient_id: str,
    device_id: str,
    session_id: str | None,
    actor_id: str,
) -> dict[str, Any]:
    """Creates (or reuses) the offline lease for this device after a successful
    offline decryption. The lease is the record the disconnected client and the
    server both point at when someone asks "on what basis was this opened
    without contact?"."""
    moment = datetime.now(timezone.utc)
    lease = _latest_lease(
        session,
        document_id=document.document_id,
        recipient_id=recipient_id,
        device_id=device_id,
    )
    if lease is not None and lease.status == GRANT_ACTIVE:
        if lease.expires_at is None or not has_expired(lease.expires_at, reference=moment):
            return _describe(lease, reused=True)
        lease.status = GRANT_EXPIRED
        lease.closed_at = moment
        lease.closed_reason = "Lease window elapsed."

    expires_at = None
    if document.offline_max_hours > 0:
        expires_at = moment + timedelta(hours=document.offline_max_hours)
    lease = OfflineGrant(
        offline_grant_id=next_id("OFG", width=8),
        document_id=document.document_id,
        recipient_id=recipient_id,
        device_id=device_id,
        session_id=session_id,
        policy_version=document.policy_version,
        status=GRANT_ACTIVE,
        granted_at=moment,
        expires_at=expires_at,
    )
    session.add(lease)
    session.flush()
    audit_service.record(
        session,
        actor_id=actor_id,
        action="OFFLINE_GRANT_ISSUED",
        target_type="OFFLINE_GRANT",
        target_id=lease.offline_grant_id,
        detail={
            "document_id": document.document_id,
            "recipient_id": recipient_id,
            "device_id": device_id,
            "policy_version": document.policy_version,
            "expires_at": expires_at.isoformat(timespec="seconds") if expires_at else None,
            "hours": document.offline_max_hours,
        },
    )
    return _describe(lease, reused=False)


def supersede_expired(
    session: Session, *, document: Document, recipient_id: str, device_id: str
) -> int:
    """Called after a successful online decryption: elapsed — or withdrawn —
    leases no longer block the next offline request, but the rows stay (marked
    SUPERSEDED) and the withdrawal register keeps the original fact, so the
    audit trail shows when each window actually ended and why."""
    moment = datetime.now(timezone.utc)
    closed = 0
    for lease in session.execute(
        select(OfflineGrant).where(
            OfflineGrant.document_id == document.document_id,
            OfflineGrant.recipient_id == recipient_id,
            OfflineGrant.device_id == device_id,
            OfflineGrant.status.in_([GRANT_ACTIVE, GRANT_EXPIRED, GRANT_REVOKED]),
        )
    ).scalars():
        prior_status = lease.status
        if prior_status == GRANT_ACTIVE and (
            lease.expires_at is None or not has_expired(lease.expires_at, reference=moment)
        ):
            continue
        lease.status = GRANT_SUPERSEDED
        lease.closed_at = moment
        if prior_status == GRANT_REVOKED:
            lease.closed_reason = (
                "Superseded by a later online session; the original revocation stands in the register."
            )
        else:
            lease.closed_reason = "Superseded by a later online session."
        closed += 1
    return closed


def revoke(
    session: Session,
    *,
    document_id: str | None = None,
    recipient_id: str | None = None,
    device_id: str | None = None,
    session_id: str | None = None,
    actor_id: str,
    reason: str,
) -> list[str]:
    """Marks matching ACTIVE/EXPIRED leases as revoked. Used by every
    revocation path so offline windows die together with the access they were
    issued under."""
    moment = datetime.now(timezone.utc)
    stmt = select(OfflineGrant).where(
        OfflineGrant.status.in_([GRANT_ACTIVE, GRANT_EXPIRED])
    )
    if document_id is not None:
        stmt = stmt.where(OfflineGrant.document_id == document_id)
    if recipient_id is not None:
        stmt = stmt.where(OfflineGrant.recipient_id == recipient_id)
    if device_id is not None:
        stmt = stmt.where(OfflineGrant.device_id == device_id)
    if session_id is not None:
        stmt = stmt.where(OfflineGrant.session_id == session_id)
    revoked: list[str] = []
    for lease in session.execute(stmt).scalars():
        lease.status = GRANT_REVOKED
        lease.closed_at = moment
        lease.closed_reason = reason
        revoked.append(lease.offline_grant_id)
    return revoked


def active_grants(session: Session, document_id: str) -> list[OfflineGrant]:
    moment = datetime.now(timezone.utc)
    return list(
        session.execute(
            select(OfflineGrant)
            .where(
                OfflineGrant.document_id == document_id,
                OfflineGrant.status == GRANT_ACTIVE,
            )
            .order_by(OfflineGrant.granted_at.desc())
        ).scalars()
    )


def describe(lease: OfflineGrant, *, reused: bool = False) -> dict[str, Any]:
    return _describe(lease, reused=reused)


def _describe(lease: OfflineGrant, *, reused: bool) -> dict[str, Any]:
    return {
        "offline_grant_id": lease.offline_grant_id,
        "document_id": lease.document_id,
        "recipient_id": lease.recipient_id,
        "device_id": lease.device_id,
        "status": lease.status,
        "granted_at": lease.granted_at.isoformat(timespec="seconds"),
        "expires_at": lease.expires_at.isoformat(timespec="seconds") if lease.expires_at else None,
        "policy_version": lease.policy_version,
        "reused_existing": reused,
        "plain_explanation": (
            "This device holds an offline access window for the document. "
            "Every use inside it is still recorded and can be revoked."
        ),
    }
