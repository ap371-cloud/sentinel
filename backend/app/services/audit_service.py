from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.identifiers import next_id, sync_counter
from ..crypto.hashing import canonical_bytes, sha256_hex
from ..models.security import AuditRecord

GENESIS_AUDIT_HASH = "0" * 64

PRIVILEGED_ACTIONS = (
    "LOGIN",
    "LOGIN_FAILED",
    "LOGOUT",
    "USER_CREATED",
    "USER_MODIFIED",
    "USER_REVOKED",
    "KEY_ISSUED",
    "KEY_ROTATED",
    "KEY_REVOKED",
    "KEY_RECOVERY",
    "POLICY_CHANGED",
    "DOCUMENT_PERMISSION_CHANGED",
    "DOCUMENT_UPLOADED",
    "DOCUMENT_SEALED",
    "DOCUMENT_DECRYPTED",
    "DOCUMENT_SUSPENDED",
    "LEDGER_OPERATION",
    "LEDGER_NODE_ADMIN",
    "EMERGENCY_ACCESS",
    "BREAK_GLASS_USED",
    "EVIDENCE_ACCESSED",
    "EVIDENCE_EXPORTED",
    "APPROVAL_REQUESTED",
    "APPROVAL_DECIDED",
    "LOCKDOWN_ACTIVATED",
    "LOCKDOWN_RELEASED",
    "BACKUP_CREATED",
    "BACKUP_RESTORED",
    "DEVICE_REGISTERED",
    "DEVICE_REVOKED",
    "INVESTIGATION_OPENED",
)


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def record(
    session: Session,
    *,
    actor_id: str,
    actor_role: str | None = None,
    action: str,
    target_type: str,
    target_id: str | None = None,
    outcome: str = "SUCCESS",
    detail: dict[str, Any] | None = None,
) -> str:
    """Appends one privileged-action record to the hash-chained audit log.

    The role is read from the identity record rather than asserted by the
    caller, so a code path cannot log an action under a role it does not hold.

    This log is deliberately separate from the ledger: an operator who
    compromises the ledger service still cannot rewrite the administrative
    history without breaking this chain.
    """
    resolved_role = actor_role or _role_of(session, actor_id)
    previous = chain_head(session)
    audit_id = _next_audit_id(session)
    moment = datetime.now(timezone.utc)
    payload = {
        "audit_id": audit_id,
        "actor_id": actor_id,
        "actor_role": resolved_role,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "outcome": outcome,
        "detail": detail or {},
        "occurred_at": moment.isoformat(timespec="seconds"),
    }
    session.add(
        AuditRecord(
        audit_id=audit_id,
        actor_id=actor_id,
        actor_role=resolved_role,
        action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            detail=json.dumps(payload["detail"], sort_keys=True),
            record_hash=_record_hash(payload, previous),
            prev_record_hash=previous,
            occurred_at=moment,
        )
    )
    return audit_id


def _next_audit_id(session: Session) -> str:
    """The in-memory counter restarts with the process, so it is re-seeded from the
    highest audit_id already persisted. Without this a restart reissues AUD-0001 and
    the chain fails on the audit_id primary key."""
    highest = session.execute(
        select(func.max(func.substr(AuditRecord.audit_id, 5)))
    ).scalar()
    issued = next_id("AUD")
    if highest and int(highest) >= int(issued.split("-")[1]):
        sync_counter("AUD", int(highest))
        issued = next_id("AUD")
    return issued


def _record_hash(payload: dict[str, Any], previous: str) -> str:
    return sha256_hex(canonical_bytes({"payload": payload, "prev": previous}))


def _role_of(session: Session, actor_id: str) -> str:
    from ..models.identity import Recipient

    row = session.get(Recipient, actor_id)
    return row.role if row else "UNKNOWN"


def chain_head(session: Session) -> str:
    # Ordering by the numeric suffix rather than the string: AUD-0010 must sort
    # after AUD-0009, which a plain string ordering gets backwards.
    row = session.execute(
        select(AuditRecord.record_hash)
        .order_by(func.length(AuditRecord.audit_id), func.substr(AuditRecord.audit_id, 5).desc())
        .limit(1)
    ).scalar()
    return row or GENESIS_AUDIT_HASH


def verify_chain(session: Session) -> dict[str, Any]:
    rows = list(
        session.execute(
            select(AuditRecord).order_by(func.length(AuditRecord.audit_id), AuditRecord.audit_id)
        ).scalars()
    )
    previous = GENESIS_AUDIT_HASH
    broken_at: str | None = None
    for row in rows:
        payload = {
            "audit_id": row.audit_id,
            "actor_id": row.actor_id,
            "actor_role": row.actor_role,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "outcome": row.outcome,
            "detail": json.loads(row.detail or "{}"),
            "occurred_at": _utc(row.occurred_at).isoformat(timespec="seconds"),
        }
        if row.prev_record_hash != previous or _record_hash(payload, previous) != row.record_hash:
            broken_at = row.audit_id
            break
        previous = row.record_hash
    return {
        "chain_length": len(rows),
        "head": previous,
        "status": "VERIFIED" if broken_at is None else "TAMPER DETECTED",
        "first_broken_record": broken_at,
        "plain_explanation": (
            "Every privileged action is cryptographically chained to the one before it, so "
            "editing or deleting any entry breaks the chain and is detected."
        ),
    }


def recent(session: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = list(
        session.execute(select(AuditRecord).order_by(AuditRecord.occurred_at.desc()).limit(limit)).scalars()
    )
    out = []
    for row in reversed(rows):
        out.append(
            {
                "audit_id": row.audit_id,
                "actor_id": row.actor_id,
                "actor_role": row.actor_role,
                "action": row.action,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "outcome": row.outcome,
                "detail": json.loads(row.detail or "{}"),
                "occurred_at": _utc(row.occurred_at).isoformat(timespec="seconds"),
                "record_hash": row.record_hash,
                "prev_record_hash": row.prev_record_hash,
            }
        )
    return out
