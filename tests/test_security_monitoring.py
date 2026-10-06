"""Rule-based security monitoring (Phase 14).

Rules never grant or deny anything: they only observe, every threshold is
published next to the rule that uses it, and a triggered rule escalates to a
command-readable security event exactly once per open alert.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.conftest import headers

from app.core.config import Clearance, Role
from app.core.exceptions import AuthorizationDenied, AuthenticationError
from app.models.security import AuditRecord
from app.security import anomaly_detection, incident_engine, revocation
from app.services import (
    approval_service,
    decryption_service,
    document_service,
    identity_service,
    seed_service,
)

ACTIVE = "RECIPIENT-001"
ACTIVE_DEVICE = "DEV-RECIPIENT-001-A"
MONITOR_USER = "MON-RECIPIENT-001"


def ensure_monitor(db) -> None:
    if identity_service.get(db, MONITOR_USER) is not None:
        return
    identity_service.create(
        db,
        recipient_id=MONITOR_USER,
        display_name="Monitoring Test Target",
        role=Role.RECIPIENT,
        unit="BRAVO",
        clearance=Clearance.CONFIDENTIAL.value,
        password="Monitor1!2026",
        actor_id="ADMIN-001",
    )


def deny_once(db, document_id: str) -> None:
    actor = identity_service.get(db, ACTIVE)
    nonce = decryption_service.issue_nonce(db, recipient_id=ACTIVE, document_id=document_id)
    with pytest.raises(AuthorizationDenied):
        decryption_service.decrypt(
            db, actor=actor, document_id=document_id, device_id=ACTIVE_DEVICE, nonce=nonce["nonce"]
        )


def events_for(db, category: str, subject_id: str) -> list[dict]:
    return [
        e for e in incident_engine.recent(db, limit=500)
        if e["category"] == category and e["subject_id"] == subject_id
    ]


class TestAuthenticationMonitoring:
    def test_failed_logins_escalate_to_the_lockout_alert(self, db):
        ensure_monitor(db)
        for _ in range(5):
            with pytest.raises(AuthenticationError):
                identity_service.authenticate(
                    db, recipient_id=MONITOR_USER, password="definitely-wrong"
                )
        alerts = events_for(db, "AUTHENTICATION_ANOMALY", MONITOR_USER)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "HIGH"

    def test_the_authentication_rule_counts_audited_failures(self, db):
        verdict = anomaly_detection.authentication_anomaly(db, MONITOR_USER)
        assert verdict.triggered
        assert verdict.observed_value >= 3

    def test_revoked_identity_login_raises_a_high_alert(self, db):
        ensure_monitor(db)
        revocation.revoke_recipient(
            db, recipient_id=MONITOR_USER, actor_id="SECURITY-001", reason="monitoring test revoke"
        )
        with pytest.raises(AuthorizationDenied):
            identity_service.authenticate(db, recipient_id=MONITOR_USER, password="Monitor1!2026")
        alerts = events_for(db, "REVOKED_RECIPIENT_ACCESS", MONITOR_USER)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "HIGH"


class TestDecryptionDenialMonitoring:
    def test_denials_are_audited_with_their_reason(self, db):
        actor = identity_service.get(db, "ADMIN-001")
        source = seed_service.synthetic_document("MONITOR DENY", "CONFIDENTIAL", "BRAVO", "MONITOR-TEST", sections=1)
        document_id = document_service.create_document(
            db,
            actor=actor,
            source=source,
            title="MONITOR DENY",
            classification="CONFIDENTIAL",
            unit="BRAVO",
            recipient_ids=["RECIPIENT-002"],
        )["document_id"]
        deny_once(db, document_id)
        denied = (
            db.query(AuditRecord)
            .filter_by(action="DECRYPT_DENIED", actor_id=ACTIVE)
            .order_by(AuditRecord.audit_id.desc())
            .first()
        )
        assert denied is not None
        assert denied.outcome == "DENIED"
        reason = __import__("json").loads(denied.detail or "{}").get("reason_code", "")
        assert reason

    def test_repeated_denials_escalate_then_stay_single(self, db):
        actor = identity_service.get(db, "ADMIN-001")
        source = seed_service.synthetic_document("MONITOR STORM", "CONFIDENTIAL", "BRAVO", "MONITOR-TEST", sections=1)
        document_id = document_service.create_document(
            db,
            actor=actor,
            source=source,
            title="MONITOR STORM",
            classification="CONFIDENTIAL",
            unit="BRAVO",
            recipient_ids=["RECIPIENT-002"],
        )["document_id"]
        for _ in range(6):
            deny_once(db, document_id)
        verdict = anomaly_detection.repeated_denials(db, ACTIVE)
        assert verdict.triggered
        assert verdict.observed_value >= 6
        alerts = events_for(db, "REPEATED_DENIALS", ACTIVE)
        assert len(alerts) == 1
        assert alerts[0]["detail"]["reason_code"]

        deny_once(db, document_id)
        assert len(events_for(db, "REPEATED_DENIALS", ACTIVE)) == 1


class TestPolicyMonitoring:
    def test_policy_change_raises_an_alert(self, db):
        requested = approval_service.request(
            db,
            action="SECURITY_POLICY_MODIFICATION",
            requested_by="ADMIN-001",
            justification="Widen the replay window for the night shift",
            required_approvals=1,
        )
        approval_service.approve(
            db,
            approval_id=requested["approval_id"],
            approver_id="COMMANDER-001",
            approver_role=Role.COMMANDER,
        )
        changed = approval_service.update_policy(
            db,
            actor_id="ADMIN-001",
            actor_role=Role.DOCUMENT_ADMIN,
            changes={"replay_window_seconds": 130},
            reason="Widen the replay window for the night shift",
            approval_id=requested["approval_id"],
        )
        alerts = events_for(db, "POLICY_MODIFICATION", "ADMIN-001")
        assert alerts
        newest = alerts[0]
        assert newest["detail"]["policy_version"] == changed["policy_version"]
        assert newest["detail"]["previous_version"]
        assert len(newest["detail"]["policy_hash"]) == 64


class TestMonitoringSurface:
    def test_anomalies_route_exposes_rules_and_observations(self, client, tokens):
        body = client.get("/anomalies", headers=headers(tokens["officer"])).json()
        rules = {r["rule"]: r for r in body["rules"]}
        assert "REPEATED_DENIALS" in rules
        assert "AUTHENTICATION_ANOMALY" in rules
        assert rules["REPEATED_DENIALS"]["threshold"]
        assert isinstance(body["recent_observations"], list)
        assert body["open_alerts"] is not None

    def test_auditor_cannot_read_monitoring_detail(self, client, tokens):
        response = client.get("/anomalies", headers=headers(tokens["auditor"]))
        assert response.status_code == 403