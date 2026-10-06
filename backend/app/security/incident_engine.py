from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Severity
from ..core.identifiers import next_id
from ..models.security import SecurityEvent

TEMPLATES: dict[str, dict[str, str]] = {
    "UNAUTHORIZED_DOCUMENT_ACCESS": {
        "severity": Severity.HIGH,
        "title": "Unauthorised document access attempt",
        "plain_explanation": "Someone tried to open a document they were not authorised for.",
        "why_it_matters": "It may be a misconfigured account, or it may be the first step of an intrusion.",
        "recommended_action": "Confirm whether the identity should hold this grant; review the account's recent activity.",
    },
    "REVOKED_RECIPIENT_ACCESS": {
        "severity": Severity.HIGH,
        "title": "Revoked recipient attempted decryption",
        "plain_explanation": "An account that was revoked tried to decrypt a document again.",
        "why_it_matters": "The credential may still be circulating and is being used after it was cancelled.",
        "recommended_action": "Keep the recipient revoked, invalidate outstanding sessions and begin a security review.",
    },
    "DEVICE_NOT_AUTHORIZED": {
        "severity": Severity.HIGH,
        "title": "Unknown device attempted decryption",
        "plain_explanation": "The request came from a device that is not registered to this recipient.",
        "why_it_matters": "A stolen credential used from a new machine is a common pattern after compromise.",
        "recommended_action": "Confirm with the recipient whether the device is legitimate before registering it.",
    },
    "REPLAY_ATTACK": {
        "severity": Severity.CRITICAL,
        "title": "Replay attack detected",
        "plain_explanation": "A decryption request that had already been used was submitted again.",
        "why_it_matters": "Someone captured a valid request and is trying to reuse it to obtain another authorised decryption.",
        "recommended_action": "Treat the captured request as compromised evidence and investigate its origin.",
    },
    "LEDGER_TAMPER": {
        "severity": Severity.CRITICAL,
        "title": "Ledger integrity verification failed",
        "plain_explanation": "A ledger node's stored history no longer matches its own recorded hashes.",
        "why_it_matters": "The immutable record of who decrypted what can no longer be trusted on that node.",
        "recommended_action": "Isolate the node, preserve its database as evidence and rebuild it from quorum-certified blocks.",
    },
    "LEDGER_DIVERGENCE": {
        "severity": Severity.CRITICAL,
        "title": "Ledger nodes disagree",
        "plain_explanation": "Two ledger nodes hold different history for the same block height.",
        "why_it_matters": "At least one node has been altered outside the protocol, or one was restored from a stale backup.",
        "recommended_action": "Compare signed block certificates and quarantine the diverging node.",
    },
    "SIGNATURE_INVALID": {
        "severity": Severity.CRITICAL,
        "title": "Cryptographic signature did not verify",
        "plain_explanation": "A record claimed to be signed by a recipient could not be verified with that recipient's public key.",
        "why_it_matters": "The record may have been forged by someone who does not hold the recipient's private key.",
        "recommended_action": "Preserve the record and investigate how it entered the system.",
    },
    "DOCUMENT_HASH_MISMATCH": {
        "severity": Severity.HIGH,
        "title": "Document content does not match its recorded version",
        "plain_explanation": "A file's content hash differs from the version the system recorded.",
        "why_it_matters": "The file was altered after it was distributed, so it is not the document that was authorised.",
        "recommended_action": "Treat the copy as a modified leak and record it as separate evidence.",
    },
    "WATERMARK_MISSING": {
        "severity": Severity.MEDIUM,
        "title": "No forensic watermark recovered",
        "plain_explanation": "A suspected leaked copy did not yield a usable watermark.",
        "why_it_matters": "Either the copy was heavily processed or the watermark was deliberately removed.",
        "recommended_action": "Attempt recovery from the highest-quality available copy of the leak.",
    },
    "AUTHENTICATION_ANOMALY": {
        "severity": Severity.MEDIUM,
        "title": "Repeated authentication failures",
        "plain_explanation": "One identity failed to authenticate several times in a short period.",
        "why_it_matters": "This can indicate password guessing or a stolen credential being tested.",
        "recommended_action": "Confirm the account is locked and ask the identity owner to verify their activity.",
    },
    "UNUSUAL_DECRYPTION_ACTIVITY": {
        "severity": Severity.MEDIUM,
        "title": "Unusual decryption frequency",
        "plain_explanation": "One recipient decrypted far more documents than normal in a short window.",
        "why_it_matters": "Bulk decryption shortly before a leak is a pattern worth understanding.",
        "recommended_action": "Ask the recipient's chain of command to confirm the operational reason.",
    },
    "DEVICE_IDENTITY_CHANGE": {
        "severity": Severity.MEDIUM,
        "title": "Device identity changed unexpectedly",
        "plain_explanation": "A recipient began using a device that was not previously associated with them.",
        "why_it_matters": "Device changes can indicate credential sharing or endpoint compromise.",
        "recommended_action": "Validate the new device registration with the recipient's unit.",
    },
    "EMERGENCY_ACCESS": {
        "severity": Severity.HIGH,
        "title": "Break-glass emergency access used",
        "plain_explanation": "A normal authorisation rule was bypassed under an emergency justification.",
        "why_it_matters": "Emergency access is a legitimate tool but a common abuse path, so it always needs review.",
        "recommended_action": "Conduct the mandatory post-event review of the justification and the material accessed.",
    },
    "TWO_PERSON_CONTROL_BYPASS_ATTEMPT": {
        "severity": Severity.HIGH,
        "title": "Single-identity attempt on a two-person controlled action",
        "plain_explanation": "One identity tried to complete an action that requires a second approver.",
        "why_it_matters": "The control exists so one person can never enable a high-impact change alone.",
        "recommended_action": "Confirm no partial change took effect, then route the request for proper approval.",
    },
    "AIR_GAP_VIOLATION": {
        "severity": Severity.CRITICAL,
        "title": "Offline security policy violation",
        "plain_explanation": "The system attempted or detected network activity while air-gapped mode was active.",
        "why_it_matters": "An air-gapped deployment must not reach external services at all.",
        "recommended_action": "Investigate the process responsible and keep the deployment isolated.",
    },
    "KEY_COMPROMISE": {
        "severity": Severity.CRITICAL,
        "title": "Cryptographic key revoked",
        "plain_explanation": "A recipient's signing or key-establishment key was withdrawn.",
        "why_it_matters": "Anything signed by that key after the revocation date can no longer be attributed with confidence.",
        "recommended_action": "Issue a replacement key and review the events signed by the withdrawn key.",
    },
    "POLICY_MODIFICATION": {
        "severity": Severity.MEDIUM,
        "title": "Security policy changed",
        "plain_explanation": "An authorized administrator changed a setting that controls access decisions.",
        "why_it_matters": "Policy changes can weaken protection if they are not deliberate.",
        "recommended_action": "Review the recorded justification and the two-person approval for the change.",
    },
    "REPEATED_DENIALS": {
        "severity": Severity.MEDIUM,
        "title": "Repeated authorisation denials for one identity",
        "plain_explanation": "One identity was refused a sensitive operation several times in a short period.",
        "why_it_matters": "A user may be probing what they can reach, or an automated process may be retrying access it was never granted.",
        "recommended_action": "Review the recorded denial reasons and confirm whether the identity should hold broader access.",
    },
}


def raise_event(
    session: Session,
    category: str,
    *,
    title: str | None = None,
    plain_explanation: str | None = None,
    what_happened: str,
    why_it_matters: str | None = None,
    what_was_affected: str = "",
    recommended_action: str | None = None,
    severity: str | None = None,
    actor_id: str | None = None,
    subject_id: str | None = None,
    document_id: str | None = None,
    session_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> str:
    """Records one security event in the command-readable four-question form:
    what happened, why it matters, what was affected, what to do next."""
    template = TEMPLATES.get(category, {})
    event_id = next_id("SEC")
    session.add(
        SecurityEvent(
            security_event_id=event_id,
            category=category,
            severity=severity or template.get("severity", Severity.MEDIUM),
            title=title or template.get("title", category.replace("_", " ").title()),
            plain_explanation=plain_explanation
            or template.get("plain_explanation", "A security-relevant condition was detected."),
            what_happened=what_happened,
            why_it_matters=why_it_matters or template.get("why_it_matters", ""),
            what_was_affected=what_was_affected,
            recommended_action=recommended_action or template.get("recommended_action", ""),
            actor_id=actor_id,
            subject_id=subject_id,
            document_id=document_id,
            session_id=session_id,
            detail=json.dumps(detail or {}, sort_keys=True),
            detected_at=datetime.now(timezone.utc),
        )
    )
    return event_id


def recent(session: Session, limit: int = 30, *, minimum_severity: str | None = None) -> list[dict[str, Any]]:
    statement = select(SecurityEvent).order_by(SecurityEvent.detected_at.desc())
    if minimum_severity:
        floor = Severity.ORDER[minimum_severity]
        allowed = [name for name, rank in Severity.ORDER.items() if rank >= floor]
        statement = statement.where(SecurityEvent.severity.in_(allowed))
    rows = list(session.execute(statement.limit(limit)).scalars())
    return [describe(row) for row in rows]


def describe(row: SecurityEvent) -> dict[str, Any]:
    return {
        "security_event_id": row.security_event_id,
        "category": row.category,
        "severity": row.severity,
        "title": row.title,
        "plain_explanation": row.plain_explanation,
        "command_brief": {
            "what_happened": row.what_happened,
            "why_it_is_important": row.why_it_matters,
            "what_was_affected": row.what_was_affected,
            "recommended_action": row.recommended_action,
        },
        "actor_id": row.actor_id,
        "subject_id": row.subject_id,
        "document_id": row.document_id,
        "session_id": row.session_id,
        "status": row.status,
        "detail": json.loads(row.detail or "{}"),
        "detected_at": row.detected_at.isoformat(timespec="seconds"),
        "acknowledged_by": row.acknowledged_by,
    }


def has_open_event(session: Session, category: str, subject_id: str) -> bool:
    """True when an open alert for this subject already exists, so repeated
    conditions escalate once instead of spamming the command feed."""
    return (
        int(
            session.execute(
                select(func.count()).select_from(SecurityEvent).where(
                    SecurityEvent.category == category,
                    SecurityEvent.status == "OPEN",
                    SecurityEvent.subject_id == subject_id,
                )
            ).scalar_one()
        )
        > 0
    )


def acknowledge(session: Session, event_id: str, actor_id: str) -> bool:
    row = session.get(SecurityEvent, event_id)
    if row is None:
        return False
    row.status = "ACKNOWLEDGED"
    row.acknowledged_by = actor_id
    row.acknowledged_at = datetime.now(timezone.utc)
    return True


def counts_by_severity(session: Session) -> dict[str, int]:
    rows = session.execute(select(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity)).all()
    return {severity: 0 for severity in Severity.ORDER} | {row[0]: row[1] for row in rows}


def open_count(session: Session) -> int:
    return int(
        session.execute(
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.status == "OPEN")
        ).scalar_one()
    )
