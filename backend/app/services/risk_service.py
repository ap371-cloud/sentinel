"""Transparent rule-based risk scoring (Phase 15).

The score is never produced by an unexplained model: every point is attributed
to a named contributing factor backed by recorded audit rows or security
events, so an operator can see exactly why an identity is treated as risky.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.timeutil import as_utc
from ..models.identity import Device, Recipient
from ..models.security import AuditRecord, SecurityEvent
from ..models.sessions import DecryptionEvent

MAX_SCORE = 100
LOGIN_WINDOW_MINUTES = 15
DENIAL_WINDOW_MINUTES = 15
EXPORT_WINDOW_MINUTES = 30
LOCATION_WINDOW_MINUTES = 15

#: Points per occurrence for signals that repeat within a window.
LOGIN_FAILURE_POINTS = 20
DENIAL_POINTS = 25
LOCATION_DENIAL_POINTS = 20
EXPORT_POINTS = 25

#: Fixed points for standing conditions.
LOCKED_ACCOUNT_POINTS = 30
SUSPENDED_DEVICE_POINTS = 30
REVOKED_DEVICE_POINTS = 40

#: Points carried by an OPEN security event that names this identity.
INCIDENT_POINTS = {
    "KEY_COMPROMISE": 60,
    "REPLAY_ATTACK": 50,
    "REVOKED_RECIPIENT_ACCESS": 40,
    "UNUSUAL_DECRYPTION_ACTIVITY": 30,
    "DEVICE_NOT_AUTHORIZED": 30,
    "AUTHENTICATION_ANOMALY": 25,
    "REPEATED_DENIALS": 25,
}

LEVELS = (
    ("CRITICAL", 80),
    ("HIGH", 60),
    ("MEDIUM", 40),
    ("LOW", 20),
)


def risk_level(score: int) -> str:
    for label, floor in LEVELS:
        if score >= floor:
            return label
    return "MINIMAL"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _count_audits(session: Session, recipient_id: str, action: str, window_minutes: int) -> int:
    since = _utcnow() - timedelta(minutes=window_minutes)
    return int(
        session.execute(
            select(func.count())
            .select_from(AuditRecord)
            .where(
                AuditRecord.actor_id == recipient_id,
                AuditRecord.action == action,
                AuditRecord.occurred_at >= since,
            )
        ).scalar_one()
    )


def _recent_denial_reasons(session: Session, recipient_id: str, window_minutes: int) -> list[str]:
    since = _utcnow() - timedelta(minutes=window_minutes)
    rows = session.execute(
        select(AuditRecord.detail)
        .select_from(AuditRecord)
        .where(
            AuditRecord.actor_id == recipient_id,
            AuditRecord.action == "DECRYPT_DENIED",
            AuditRecord.occurred_at >= since,
        )
    ).scalars()
    reasons = []
    for detail in rows:
        code = json.loads(detail or "{}").get("reason_code", "")
        if code:
            reasons.append(code)
    return reasons


def _recent_exported_decryptions(session: Session, recipient_id: str, window_minutes: int) -> list[str]:
    since = _utcnow() - timedelta(minutes=window_minutes)
    rows = session.execute(
        select(DecryptionEvent)
        .where(DecryptionEvent.recipient_id == recipient_id, DecryptionEvent.occurred_at >= since)
        .order_by(DecryptionEvent.occurred_at.desc())
    ).scalars()
    exported = []
    for row in rows:
        payload = json.loads(row.payload or "{}")
        if payload.get("exported"):
            exported.append(row.event_id)
    return exported


def _open_incidents(session: Session, recipient_id: str) -> list[SecurityEvent]:
    return list(
        session.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.status == "OPEN",
                SecurityEvent.subject_id == recipient_id,
                SecurityEvent.category.in_(set(INCIDENT_POINTS)),
            )
            .order_by(SecurityEvent.detected_at.desc())
        ).scalars()
    )


def _factor(name: str, points: int, evidence: list[Any] | None = None, detail: str = "") -> dict[str, Any]:
    return {
        "factor": name,
        "points": points,
        "evidence": evidence or [],
        "detail": detail,
    }


def assess(session: Session, recipient_id: str) -> dict[str, Any]:
    """Returns score, level and the full breakdown of contributing factors.
    A factor is only included when it actually contributed points."""
    factors: list[dict[str, Any]] = []
    recipient = session.get(Recipient, recipient_id)
    if recipient is None:
        return {
            "recipient_id": recipient_id,
            "risk_score": 0,
            "maximum": MAX_SCORE,
            "risk_level": "MINIMAL",
            "assessment_at": _utcnow().isoformat(timespec="seconds"),
            "contributing_factors": [],
            "plain_explanation": "Identity is not registered, so no risk applies.",
        }

    failures = _count_audits(session, recipient_id, "LOGIN_FAILED", LOGIN_WINDOW_MINUTES)
    if failures:
        factors.append(
            _factor(
                "REPEATED_LOGIN_FAILURE",
                failures * LOGIN_FAILURE_POINTS,
                evidence=[f"{failures} failed sign-in(s) in the last {LOGIN_WINDOW_MINUTES} minutes"],
            )
        )

    locked_until = recipient.locked_until
    if locked_until is not None and as_utc(locked_until) > _utcnow():
        factors.append(_factor("ACCOUNT_LOCKED", LOCKED_ACCOUNT_POINTS, detail=as_utc(locked_until).isoformat(timespec="seconds")))

    device_states = {
        row.trust_state: row.device_id
        for row in session.execute(select(Device).where(Device.recipient_id == recipient_id)).scalars()
    }
    for state, points, label in (
        ("REVOKED", REVOKED_DEVICE_POINTS, "REVOKED_DEVICE"),
        ("SUSPENDED", SUSPENDED_DEVICE_POINTS, "SUSPENDED_DEVICE"),
    ):
        if state in device_states:
            factors.append(
                _factor(label, points, evidence=[device_states[state]], detail=state)
            )
            break

    denials = _count_audits(session, recipient_id, "DECRYPT_DENIED", DENIAL_WINDOW_MINUTES)
    if denials:
        factors.append(
            _factor(
                "REPEATED_DECRYPT_DENIAL",
                denials * DENIAL_POINTS,
                evidence=[f"{denials} refused decryption(s) in the last {DENIAL_WINDOW_MINUTES} minutes"],
            )
        )

    location_denials = [
        r for r in _recent_denial_reasons(session, recipient_id, LOCATION_WINDOW_MINUTES) if r.startswith("LOCATION_")
    ]
    if location_denials:
        factors.append(
            _factor(
                "LOCATION_DENIAL",
                len(location_denials) * LOCATION_DENIAL_POINTS,
                evidence=[f"{r}" for r in location_denials],
            )
        )

    exported = _recent_exported_decryptions(session, recipient_id, EXPORT_WINDOW_MINUTES)
    if exported:
        factors.append(
            _factor(
                "REPEATED_EXPORT",
                len(exported) * EXPORT_POINTS,
                evidence=[f"{len(exported)} renamed export copies in the last {EXPORT_WINDOW_MINUTES} minutes"],
            )
        )

    incidents = _open_incidents(session, recipient_id)
    if incidents:
        points = sum(INCIDENT_POINTS.get(e.category, 0) for e in incidents)
        factors.append(
            _factor(
                "OPEN_INCIDENTS",
                points,
                evidence=[f"{e.category} ({e.security_event_id})" for e in incidents],
            )
        )

    factors.sort(key=lambda f: f["points"], reverse=True)
    score = min(sum(f["points"] for f in factors), MAX_SCORE)
    return {
        "recipient_id": recipient_id,
        "risk_score": score,
        "maximum": MAX_SCORE,
        "risk_level": risk_level(score),
        "assessment_at": _utcnow().isoformat(timespec="seconds"),
        "contributing_factors": factors,
        "plain_explanation": (
            "Rule-based score: each contributing factor names how many points it added and the "
            "recorded evidence behind it. The score is informational; authorisation decisions "
            "are never made by this number alone."
        ),
    }