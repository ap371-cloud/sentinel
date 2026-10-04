from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import AccountStatus, Clearance, Role
from ..core.exceptions import AuthenticationError, AuthorizationDenied
from ..core.security import TOKENS, hash_password, verify_password
from ..core.timeutil import has_expired, iso, utcnow
from ..crypto.key_management import VAULT
from ..models.identity import Device, KeyMetadata, Recipient
from ..models.security import SystemState
from ..security import incident_engine
from . import audit_service

LOCKOUT_AFTER_FAILURES = 5
LOCKOUT_MINUTES = 15


def to_public(recipient: Recipient) -> dict[str, Any]:
    """Shape handed to the API and the frontend. The password hash and salt are
    not part of it, so there is no code path that can leak them by accident."""
    return {
        "recipient_id": recipient.recipient_id,
        "display_name": recipient.display_name,
        "role": recipient.role,
        "unit": recipient.unit,
        "clearance": recipient.clearance,
        "clearance_label": Clearance(recipient.clearance).label,
        "status": recipient.status,
        "email": recipient.email,
        "created_at": recipient.created_at.isoformat(timespec="seconds"),
        "last_login_at": recipient.last_login_at.isoformat(timespec="seconds")
        if recipient.last_login_at
        else None,
        "revoked_at": recipient.revoked_at.isoformat(timespec="seconds") if recipient.revoked_at else None,
        "revocation_reason": recipient.revocation_reason,
    }


def get(session: Session, recipient_id: str) -> Recipient | None:
    return session.get(Recipient, recipient_id)


def list_all(session: Session, *, role: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    statement = select(Recipient).order_by(Recipient.recipient_id)
    if role:
        statement = statement.where(Recipient.role == role)
    if status:
        statement = statement.where(Recipient.status == status)
    return [to_public(row) for row in session.execute(statement).scalars()]


def create(
    session: Session,
    *,
    recipient_id: str,
    display_name: str,
    role: str,
    unit: str,
    clearance: int,
    password: str,
    actor_id: str,
    email: str | None = None,
) -> dict[str, Any]:
    if role not in Role.ALL:
        raise ValueError(f"Unknown role {role}")
    if session.get(Recipient, recipient_id) is not None:
        raise ValueError(f"{recipient_id} already exists")

    password_hash, salt = hash_password(password)
    recipient = Recipient(
        recipient_id=recipient_id,
        display_name=display_name,
        role=role,
        unit=unit,
        clearance=clearance,
        status=AccountStatus.ACTIVE,
        password_hash=password_hash,
        password_salt=salt,
        email=email,
    )
    session.add(recipient)
    session.flush()

    issued = VAULT.issue_identity(recipient_id)
    _mirror_key_metadata(session, recipient_id, issued)

    audit_service.record(
        session,
        actor_id=actor_id,
        actor_role="SUPER_ADMIN",
        action="USER_CREATED",
        target_type="RECIPIENT",
        target_id=recipient_id,
        detail={"role": role, "unit": unit, "clearance": clearance},
    )
    return to_public(recipient)


def _mirror_key_metadata(session: Session, owner_id: str, issued: dict[str, Any]) -> None:
    for record in issued.values():
        session.merge(
            KeyMetadata(
                key_id=record.key_id,
                owner_id=owner_id,
                purpose=record.purpose,
                algorithm=record.algorithm,
                version=record.version,
                status=record.status,
                public_key=record.public_key,
                created_at=datetime.now(timezone.utc),
            )
        )


def register_device(
    session: Session,
    *,
    recipient_id: str,
    device_id: str,
    device_name: str,
    fingerprint: str,
    actor_id: str,
) -> dict[str, Any]:
    from ..security import revocation

    return revocation.register_device(
        session,
        device_id=device_id,
        recipient_id=recipient_id,
        device_name=device_name,
        fingerprint=fingerprint,
        actor_id=actor_id,
    )


def devices_for(session: Session, recipient_id: str) -> list[dict[str, Any]]:
    rows = session.execute(select(Device).where(Device.recipient_id == recipient_id)).scalars()
    return [
        {
            "device_id": d.device_id,
            "device_name": d.device_name,
            "fingerprint": d.device_fingerprint,
            "status": d.status,
            "registered_at": d.registered_at.isoformat(timespec="seconds"),
            "last_seen_at": d.last_seen_at.isoformat(timespec="seconds") if d.last_seen_at else None,
            "revoked_at": d.revoked_at.isoformat(timespec="seconds") if d.revoked_at else None,
            "attestation_note": d.attestation_note,
        }
        for d in rows
    ]


def authenticate(
    session: Session, *, recipient_id: str, password: str, device_id: str | None = None
) -> tuple[Recipient, str]:
    recipient = session.get(Recipient, recipient_id)
    now = datetime.now(timezone.utc)

    if recipient is None or not verify_password(password, recipient.password_hash):
        if recipient is not None:
            recipient.failed_login_count += 1
            if recipient.failed_login_count >= LOCKOUT_AFTER_FAILURES:
                recipient.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                recipient.failed_login_count = 0
                incident_engine.raise_event(
                    session,
                    "AUTHENTICATION_ANOMALY",
                    what_happened=(
                        f"{recipient_id} failed {LOCKOUT_AFTER_FAILURES} authentications and is locked "
                        f"for {LOCKOUT_MINUTES} minutes."
                    ),
                    what_was_affected=recipient_id,
                    subject_id=recipient_id,
                    severity="HIGH",
                )
        audit_service.record(
            session,
            actor_id=recipient_id,
            actor_role="UNKNOWN",
            action="LOGIN_FAILED",
            target_type="RECIPIENT",
            target_id=recipient_id,
            outcome="DENIED",
        )
        raise AuthenticationError("Identity or passphrase not recognised.")

    if has_expired(recipient.locked_until, reference=now) and recipient.locked_until is not None:
        raise AuthenticationError(
            "This account is temporarily locked after repeated failed authentication attempts."
        )

    if recipient.status != AccountStatus.ACTIVE:
        audit_service.record(
            session,
            actor_id=recipient_id,
            actor_role=recipient.role,
            action="LOGIN_FAILED",
            target_type="RECIPIENT",
            target_id=recipient_id,
            outcome="DENIED",
            detail={"status": recipient.status},
        )
        raise AuthorizationDenied(
            f"This account is {recipient.status}; it cannot be used to sign in.",
            detail="A senior officer must restore the account before it can be used.",
        )

    if device_id:
        device = session.get(Device, device_id)
        if device is None or device.recipient_id != recipient_id or device.status != "ACTIVE":
            incident_engine.raise_event(
                session,
                "DEVICE_NOT_AUTHORIZED",
                what_happened=f"{recipient_id} attempted to sign in from unrecognised device {device_id}.",
                what_was_affected=device_id or "UNKNOWN",
                subject_id=device_id,
                severity="MEDIUM",
            )
            raise AuthorizationDenied(
                f"Device {device_id} is not registered to {recipient_id}.",
                detail="Register the device before using it.",
            )
        device.last_seen_at = now

    recipient.failed_login_count = 0
    recipient.locked_until = None
    recipient.last_login_at = now
    token = TOKENS.issue(
        subject=recipient.recipient_id,
        role=recipient.role,
        unit=recipient.unit,
        clearance=recipient.clearance,
    )
    audit_service.record(
        session,
        actor_id=recipient.recipient_id,
        actor_role=recipient.role,
        action="LOGIN",
        target_type="RECIPIENT",
        target_id=recipient.recipient_id,
        detail={"device_id": device_id},
    )
    return recipient, token


def identify(session: Session, token: str) -> Recipient:
    """Every request re-reads the account, so a revocation takes effect on the
    next call rather than when the token happens to expire."""
    claims = TOKENS.read(token)
    recipient = session.get(Recipient, claims.subject)
    if recipient is None:
        raise AuthenticationError("The identity behind this token no longer exists.")
    if recipient.status != AccountStatus.ACTIVE:
        raise AuthorizationDenied(
            f"This account is {recipient.status}; access is refused.",
            detail="Revocation and suspension take effect immediately.",
        )
    if recipient.role != claims.role:
        raise AuthorizationDenied("The token no longer matches the account's current role.")
    return recipient


def key_inventory(session: Session, owner_id: str | None = None) -> list[dict[str, Any]]:
    statement = select(KeyMetadata).order_by(KeyMetadata.key_id)
    if owner_id:
        statement = statement.where(KeyMetadata.owner_id == owner_id)
    return [
        {
            "key_id": row.key_id,
            "owner_id": row.owner_id,
            "purpose": row.purpose,
            "algorithm": row.algorithm,
            "version": row.version,
            "status": row.status,
            "created_at": row.created_at.isoformat(timespec="seconds"),
            "expires_at": row.expires_at.isoformat(timespec="seconds") if row.expires_at else None,
            "secret_material_stored": False,
            "note": "Private key material is held only in the encrypted key vault.",
        }
        for row in session.execute(statement).scalars()
    ]


def active_counts(session: Session) -> dict[str, int]:
    total = int(session.execute(select(func.count()).select_from(Recipient)).scalar_one())
    active = int(
        session.execute(
            select(func.count()).select_from(Recipient).where(Recipient.status == AccountStatus.ACTIVE)
        ).scalar_one()
    )
    return {"total": total, "active": active, "inactive": total - active}


def system_status(session: Session) -> str:
    row = session.get(SystemState, "GLOBAL")
    if row is None:
        return "SECURE"
    if row.lockdown_active:
        return "EMERGENCY LOCKDOWN"
    if row.air_gap_violation:
        return "WARNING"
    return "SECURE"
