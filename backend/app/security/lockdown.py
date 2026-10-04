from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models.security import SystemState

LOCKDOWN_EXPLANATION = (
    "New sensitive operations are temporarily blocked while existing evidence remains preserved."
)


def state(session: Session) -> SystemState:
    row = session.get(SystemState, "GLOBAL")
    if row is None:
        row = SystemState(state_id="GLOBAL")
        session.add(row)
        session.flush()
    return row


def is_active(session: Session) -> bool:
    return bool(state(session).lockdown_active)


def activate(session: Session, *, actor_id: str, reason: str) -> dict[str, Any]:
    row = state(session)
    already = bool(row.lockdown_active)
    row.lockdown_active = True
    row.lockdown_reason = reason
    row.lockdown_activated_by = actor_id
    row.lockdown_activated_at = row.lockdown_activated_at or datetime.now(timezone.utc)
    row.updated_at = datetime.now(timezone.utc)
    return {
        "system_status": "EMERGENCY LOCKDOWN",
        "already_active": already,
        "activated_by": actor_id,
        "activated_at": row.lockdown_activated_at.isoformat(timespec="seconds"),
        "reason": reason,
        "blocked_now": [
            "New document decryptions",
            "New decryption sessions",
            "Breach-glass requests without an approved emergency authorization",
        ],
        "still_permitted": [
            "Reading the audit trail",
            "Ledger verification",
            "Forensic analysis of an existing leak",
            "Revoking recipients, devices and keys",
        ],
        "evidence_preserved": True,
        "plain_explanation": LOCKDOWN_EXPLANATION,
    }


def release(session: Session, *, actor_id: str, reason: str) -> dict[str, Any]:
    row = state(session)
    was_active = bool(row.lockdown_active)
    row.lockdown_active = False
    row.updated_at = datetime.now(timezone.utc)
    return {
        "system_status": "SECURE" if not row.air_gap_violation else "WARNING",
        "was_active": was_active,
        "released_by": actor_id,
        "released_at": row.updated_at.isoformat(timespec="seconds"),
        "reason": reason,
        "plain_explanation": (
            "Normal decryption is permitted again. Everything recorded during the lockdown remains "
            "in the ledger and was never deleted."
        ),
    }


def describe(session: Session) -> dict[str, Any]:
    row = state(session)
    if row.lockdown_active:
        status = "EMERGENCY LOCKDOWN"
    elif row.air_gap_violation:
        status = "WARNING"
    else:
        status = "SECURE"
    return {
        "system_status": status,
        "lockdown_active": bool(row.lockdown_active),
        "lockdown_reason": row.lockdown_reason,
        "lockdown_activated_by": row.lockdown_activated_by,
        "lockdown_activated_at": row.lockdown_activated_at.isoformat(timespec="seconds")
        if row.lockdown_activated_at
        else None,
        "air_gap_violation": bool(row.air_gap_violation),
        "plain_explanation": LOCKDOWN_EXPLANATION if row.lockdown_active else "No emergency restrictions are in force.",
    }
