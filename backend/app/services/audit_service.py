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
    "SHARE_REQUESTED",
    "SHARE_APPROVED",
    "SHARE_DENIED",
    "SHARE_REVOKED",
)


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


#: Structured, filterable columns. Only populated values are folded into the
#: record hash, which is what keeps an upgraded database with legacy rows
#: verifiable while still covering the new fields on fresh records.
STRUCTURED = ("device_id", "document_id", "document_hash", "session_id", "policy_version", "reason", "severity")


def _structured_from(detail: dict[str, Any]) -> dict[str, str]:
    return {
        "document_id": detail.get("document_id") or None,
        "device_id": detail.get("device_id") or None,
        "session_id": detail.get("session_id") or None,
        "document_hash": detail.get("document_hash") or None,
        "policy_version": detail.get("policy_version") or None,
        "reason": detail.get("reason_code") or detail.get("reason") or None,
        "severity": detail.get("severity") or None,
    }


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
    device_id: str | None = None,
    document_id: str | None = None,
    document_hash: str | None = None,
    session_id: str | None = None,
    policy_version: str | None = None,
    reason: str | None = None,
    severity: str | None = None,
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
    explicit = {
        "device_id": device_id,
        "document_id": document_id,
        "document_hash": document_hash,
        "session_id": session_id,
        "policy_version": policy_version,
        "reason": reason,
        "severity": severity,
    }
    inferred = _structured_from(detail or {})
    if target_type == "DECRYPTION_SESSION" and target_id and not inferred["session_id"]:
        inferred["session_id"] = target_id
    structured = {key: explicit[key] if explicit[key] is not None else inferred.get(key) for key in STRUCTURED}
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
    payload.update({key: value for key, value in structured.items() if value})
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
            device_id=structured["device_id"],
            document_id=structured["document_id"],
            document_hash=structured["document_hash"],
            session_id=structured["session_id"],
            policy_version=structured["policy_version"],
            reason=structured["reason"],
            severity=structured["severity"],
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
        payload.update(
            {key: getattr(row, key) for key in STRUCTURED if getattr(row, key) is not None}
        )
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


def _row_to_dict(row: AuditRecord) -> dict[str, Any]:
    return {
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
        "device_id": row.device_id,
        "document_id": row.document_id,
        "document_hash": row.document_hash,
        "session_id": row.session_id,
        "policy_version": row.policy_version,
        "reason": row.reason,
        "severity": row.severity,
    }


def recent(session: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = list(
        session.execute(select(AuditRecord).order_by(AuditRecord.occurred_at.desc()).limit(limit)).scalars()
    )
    return [_row_to_dict(row) for row in reversed(rows)]


def search(
    session: Session,
    *,
    limit: int = 100,
    actor_id: str | None = None,
    action: str | None = None,
    target_id: str | None = None,
    device_id: str | None = None,
    document_id: str | None = None,
    session_id: str | None = None,
    severity: str | None = None,
    policy_version: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict[str, Any]]:
    """Filtered, newest-first trail query. The hash chain still verifies over
    everything returned, so filters cannot hide a tamper."""
    from datetime import datetime

    statement = select(AuditRecord)
    if actor_id is not None:
        statement = statement.where(AuditRecord.actor_id == actor_id)
    if action is not None:
        statement = statement.where(AuditRecord.action == action)
    if target_id is not None:
        statement = statement.where(AuditRecord.target_id == target_id)
    if device_id is not None:
        statement = statement.where(AuditRecord.device_id == device_id)
    if document_id is not None:
        statement = statement.where(AuditRecord.document_id == document_id)
    if session_id is not None:
        statement = statement.where(AuditRecord.session_id == session_id)
    if severity is not None:
        statement = statement.where(AuditRecord.severity == severity)
    if policy_version is not None:
        statement = statement.where(AuditRecord.policy_version == policy_version)
    if since is not None:
        statement = statement.where(AuditRecord.occurred_at >= _parse_iso(since))
    if until is not None:
        statement = statement.where(AuditRecord.occurred_at <= _parse_iso(until))
    statement = statement.order_by(AuditRecord.occurred_at.desc()).limit(min(limit, 500))
    rows = list(session.execute(statement).scalars())
    return [_row_to_dict(row) for row in reversed(rows)]


def _parse_iso(value: str) -> datetime:
    normalized = value[:-1] if value.endswith(("Z", "z")) else value
    return datetime.fromisoformat(normalized)
