from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Severity
from ..core.identifiers import next_id
from ..models.identity import Device, Recipient
from ..models.security import AnomalyObservation
from ..models.sessions import DecryptionEvent, DecryptionSession

#: Explainable thresholds. Every rule names the numbers it used so an operator
#: can disagree with the threshold without reverse-engineering a model.
FAILED_LOGIN_THRESHOLD = 3
DECRYPTIONS_PER_MINUTE_THRESHOLD = 5
DEVICE_CHANGE_WINDOW_MINUTES = 60


@dataclass
class AnomalyVerdict:
    rule: str
    triggered: bool
    severity: str
    subject_id: str | None
    observed_value: int
    threshold: int
    explanation: str


def observe(
    session: Session,
    *,
    rule: str,
    subject_id: str | None,
    observed_value: int,
    threshold: int,
    triggered: bool,
    severity: str,
    explanation: str,
    window_seconds: int,
) -> AnomalyVerdict:
    session.add(
        AnomalyObservation(
            observation_id=next_id("ANO"),
            rule=rule,
            subject_id=subject_id,
            window_start=datetime.now(timezone.utc) - timedelta(seconds=window_seconds),
            window_seconds=window_seconds,
            observed_value=observed_value,
            threshold=threshold,
            triggered=triggered,
            explanation=explanation,
        )
    )
    return AnomalyVerdict(rule, triggered, severity, subject_id, observed_value, threshold, explanation)


def authentication_anomaly(session: Session, recipient_id: str) -> AnomalyVerdict:
    recent_failures = int(
        session.execute(
            select(func.count())
            .select_from(DecryptionEvent)
            .where(DecryptionEvent.event_type == "LOGIN_FAILED", DecryptionEvent.recipient_id == recipient_id)
        ).scalar_one()
    )
    triggered = recent_failures >= FAILED_LOGIN_THRESHOLD
    explanation = (
        f"{recent_failures} failed authentication attempts recorded for {recipient_id}; "
        f"the alert threshold is {FAILED_LOGIN_THRESHOLD}."
    )
    return observe(
        session,
        rule="AUTHENTICATION_ANOMALY",
        subject_id=recipient_id,
        observed_value=recent_failures,
        threshold=FAILED_LOGIN_THRESHOLD,
        triggered=triggered,
        severity=Severity.MEDIUM,
        explanation=explanation,
        window_seconds=900,
    )


def unusual_decryption_frequency(session: Session, recipient_id: str, *, window_minutes: int = 1) -> AnomalyVerdict:
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    count = int(
        session.execute(
            select(func.count())
            .select_from(DecryptionSession)
            .where(DecryptionSession.recipient_id == recipient_id, DecryptionSession.issued_at >= since)
        ).scalar_one()
    )
    threshold = DECRYPTIONS_PER_MINUTE_THRESHOLD * window_minutes
    triggered = count > threshold
    return observe(
        session,
        rule="UNUSUAL_DECRYPTION_ACTIVITY",
        subject_id=recipient_id,
        observed_value=count,
        threshold=threshold,
        triggered=triggered,
        severity=Severity.MEDIUM,
        explanation=(
            f"{recipient_id} opened {count} documents in the last {window_minutes} minute(s); "
            f"the normal rate is about {DECRYPTIONS_PER_MINUTE_THRESHOLD} per minute."
        ),
        window_seconds=window_minutes * 60,
    )


def device_identity_change(session: Session, recipient_id: str, device_id: str) -> AnomalyVerdict:
    known = session.get(Device, device_id)
    foreign = known is not None and known.recipient_id != recipient_id
    triggered = known is None or foreign
    return observe(
        session,
        rule="DEVICE_IDENTITY_CHANGE",
        subject_id=recipient_id,
        observed_value=0 if known else 1,
        threshold=0,
        triggered=triggered,
        severity=Severity.MEDIUM,
        explanation=(
            f"Device {device_id} presented by {recipient_id} is "
            + ("not registered to them" if known is None else "registered to a different identity")
            if triggered
            else f"Device {device_id} is registered to {recipient_id}."
        ),
        window_seconds=DEVICE_CHANGE_WINDOW_MINUTES * 60,
    )


def run_for_decryption(session: Session, recipient: Recipient, device_id: str) -> list[AnomalyVerdict]:
    """Called on the decryption path so the rules fire without a separate
    monitoring process."""
    verdicts = [
        unusual_decryption_frequency(session, recipient.recipient_id),
        device_identity_change(session, recipient.recipient_id, device_id),
    ]
    return verdicts


def rule_catalogue() -> list[dict[str, Any]]:
    return [
        {
            "rule": "AUTHENTICATION_ANOMALY",
            "severity": Severity.MEDIUM,
            "threshold": f"{FAILED_LOGIN_THRESHOLD} failed authentications",
            "explanation": "Suggests password guessing or a stolen credential being tested.",
        },
        {
            "rule": "UNUSUAL_DECRYPTION_ACTIVITY",
            "severity": Severity.MEDIUM,
            "threshold": f"more than {DECRYPTIONS_PER_MINUTE_THRESHOLD} documents per minute",
            "explanation": "Bulk access shortly before a leak is a pattern worth explaining.",
        },
        {
            "rule": "DEVICE_IDENTITY_CHANGE",
            "severity": Severity.MEDIUM,
            "threshold": "any unregistered or foreign device",
            "explanation": "Device changes can indicate credential sharing or endpoint compromise.",
        },
        {
            "rule": "REVOKED_ACCOUNT_ACCESS_ATTEMPT",
            "severity": Severity.HIGH,
            "threshold": "any attempt by a revoked identity",
            "explanation": "A cancelled credential is still in use.",
        },
        {
            "rule": "EMERGENCY_ACCESS_USED",
            "severity": Severity.HIGH,
            "threshold": "any break-glass decryption",
            "explanation": "Emergency access always triggers a mandatory post-event review.",
        },
    ]


def recent_observations(session: Session, limit: int = 40) -> list[dict[str, Any]]:
    rows = list(
        session.execute(
            select(AnomalyObservation).order_by(AnomalyObservation.recorded_at.desc()).limit(limit)
        ).scalars()
    )
    return [
        {
            "observation_id": r.observation_id,
            "rule": r.rule,
            "subject_id": r.subject_id,
            "observed_value": r.observed_value,
            "threshold": r.threshold,
            "triggered": r.triggered,
            "explanation": r.explanation,
            "window_seconds": r.window_seconds,
            "recorded_at": r.recorded_at.isoformat(timespec="seconds"),
        }
        for r in rows
    ]
