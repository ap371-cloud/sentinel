"""Rule-based risk scoring (Phase 15).

The score is transparent: every point maps to a named contributing factor with
recorded evidence, and the number itself never makes an authorisation decision.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.conftest import headers

from app.core.config import Clearance, Role
from app.core.exceptions import AuthorizationDenied, AuthenticationError
from app.models.identity import Device
from app.security import revocation
from app.services import (
    decryption_service,
    document_service,
    identity_service,
    risk_service,
    seed_service,
)

RISK_USER = "RISK-RECIPIENT-001"
RISK_DEVICE = "DEV-RISK-001-A"


def ensure_risk_user(db) -> None:
    if identity_service.get(db, RISK_USER) is not None:
        return
    identity_service.create(
        db,
        recipient_id=RISK_USER,
        display_name="Risk Scoring Target",
        role=Role.RECIPIENT,
        unit="BRAVO",
        clearance=Clearance.CONFIDENTIAL.value,
        password="RiskUser1!2026",
        actor_id="ADMIN-001",
    )
    identity_service.register_device(
        db,
        recipient_id=RISK_USER,
        device_id=RISK_DEVICE,
        device_name="Risk test device",
        fingerprint="r1sk-f1ng3rpr1nt",
        actor_id="ADMIN-001",
    )


def denied_document(db) -> str:
    actor = identity_service.get(db, "ADMIN-001")
    source = seed_service.synthetic_document("RISK DENY", "CONFIDENTIAL", "BRAVO", "RISK-TEST", sections=1)
    return document_service.create_document(
        db,
        actor=actor,
        source=source,
        title="RISK DENY",
        classification="CONFIDENTIAL",
        unit="BRAVO",
        recipient_ids=["RECIPIENT-002"],
    )["document_id"]


class TestBaseline:
    def test_unregistered_identity_has_no_score(self, db):
        assessment = risk_service.assess(db, "GHOST-USER")
        assert assessment["risk_score"] == 0
        assert assessment["risk_level"] == "MINIMAL"
        assert assessment["contributing_factors"] == []
        assert "not registered" in assessment["plain_explanation"]

    def test_clean_identity_starts_minimal(self, db):
        ensure_risk_user(db)
        assessment = risk_service.assess(db, RISK_USER)
        assert assessment["risk_score"] == 0
        assert assessment["risk_level"] == "MINIMAL"
        assert assessment["contributing_factors"] == []


class TestContributingFactors:
    def test_failed_logins_add_points_then_lockout_counts(self, db):
        ensure_risk_user(db)
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                identity_service.authenticate(db, recipient_id=RISK_USER, password="wrong-pass")
        assessment = risk_service.assess(db, RISK_USER)
        factors = {f["factor"]: f for f in assessment["contributing_factors"]}
        assert "REPEATED_LOGIN_FAILURE" in factors
        assert factors["REPEATED_LOGIN_FAILURE"]["points"] >= 60

        for _ in range(2):
            with pytest.raises(AuthenticationError):
                identity_service.authenticate(db, recipient_id=RISK_USER, password="wrong-pass")
        assessment = risk_service.assess(db, RISK_USER)
        factors = {f["factor"]: f for f in assessment["contributing_factors"]}
        assert "ACCOUNT_LOCKED" in factors
        assert assessment["risk_score"] > 60

    def test_revoked_device_adds_fixed_points(self, db):
        ensure_risk_user(db)
        row = db.query(Device).filter_by(recipient_id=RISK_USER, device_id=RISK_DEVICE).one()
        row.trust_state = "REVOKED"
        db.flush()
        assessment = risk_service.assess(db, RISK_USER)
        factors = {f["factor"]: f for f in assessment["contributing_factors"]}
        assert "REVOKED_DEVICE" in factors
        assert factors["REVOKED_DEVICE"]["points"] == 40
        assert factors["REVOKED_DEVICE"]["evidence"][0] == RISK_DEVICE

    def test_decryption_denials_add_points(self, db):
        ensure_risk_user(db)
        db.query(Device).filter_by(recipient_id=RISK_USER, device_id=RISK_DEVICE).update({"trust_state": "TRUSTED"})
        db.flush()
        document_id = denied_document(db)
        actor = identity_service.get(db, RISK_USER)
        for _ in range(2):
            nonce = decryption_service.issue_nonce(db, recipient_id=RISK_USER, document_id=document_id)
            with pytest.raises(AuthorizationDenied):
                decryption_service.decrypt(
                    db, actor=actor, document_id=document_id, device_id=RISK_DEVICE, nonce=nonce["nonce"]
                )
        assessment = risk_service.assess(db, RISK_USER)
        factors = {f["factor"]: f for f in assessment["contributing_factors"]}
        assert "REPEATED_DECRYPT_DENIAL" in factors
        assert factors["REPEATED_DECRYPT_DENIAL"]["points"] >= 50

    def test_exported_copies_are_flagged(self, db):
        ensure_risk_user(db)
        db.query(Device).filter_by(recipient_id=RISK_USER, device_id=RISK_DEVICE).update({"trust_state": "TRUSTED"})
        db.flush()
        actor = identity_service.get(db, "ADMIN-001")
        source = seed_service.synthetic_document("RISK EXPORT", "CONFIDENTIAL", "BRAVO", "RISK-TEST", sections=1)
        document_id = document_service.create_document(
            db,
            actor=actor,
            source=source,
            title="RISK EXPORT",
            classification="CONFIDENTIAL",
            unit="BRAVO",
            recipient_ids=[RISK_USER],
            policy={"rights": {"EXPORT": "ALLOW"}},
        )["document_id"]
        recipient = identity_service.get(db, RISK_USER)
        nonce = decryption_service.issue_nonce(db, recipient_id=RISK_USER, document_id=document_id)
        decryption_service.decrypt(
            db,
            actor=recipient,
            document_id=document_id,
            device_id=RISK_DEVICE,
            nonce=nonce["nonce"],
            export_as="RISK EXPORT - renamed copy.pdf",
        )
        assessment = risk_service.assess(db, RISK_USER)
        factors = {f["factor"]: f for f in assessment["contributing_factors"]}
        assert "REPEATED_EXPORT" in factors
        assert factors["REPEATED_EXPORT"]["points"] >= 25

    def test_revoked_login_open_incident_adds_points(self, db):
        holder = "RISK-REVOKED-001"
        if identity_service.get(db, holder) is None:
            identity_service.create(
                db,
                recipient_id=holder,
                display_name="Revoked risk target",
                role=Role.RECIPIENT,
                unit="BRAVO",
                clearance=Clearance.CONFIDENTIAL.value,
                password="RiskRevoked1!2026",
                actor_id="ADMIN-001",
            )
        revocation.revoke_recipient(db, recipient_id=holder, actor_id="SECURITY-001", reason="risk test revoke")
        with pytest.raises(AuthorizationDenied):
            identity_service.authenticate(db, recipient_id=holder, password="RiskRevoked1!2026")
        assessment = risk_service.assess(db, holder)
        factors = {f["factor"]: f for f in assessment["contributing_factors"]}
        assert "OPEN_INCIDENTS" in factors
        assert any("REVOKED_RECIPIENT_ACCESS" in e for e in factors["OPEN_INCIDENTS"]["evidence"])


class TestRiskSurface:
    def test_risk_routes_are_visible_to_security_officers(self, db, client, tokens):
        ensure_risk_user(db)
        body = client.get(f"/risk/{RISK_USER}", headers=headers(tokens["officer"])).json()
        assert body["recipient_id"] == RISK_USER
        assert set(("risk_score", "risk_level", "contributing_factors", "maximum")) <= set(body)
        assert body["maximum"] == 100

        leaderboard = client.get("/risk", headers=headers(tokens["officer"])).json()
        assert "recipients" in leaderboard
        assert any(r["recipient_id"] == RISK_USER for r in leaderboard["recipients"])

    def test_auditor_cannot_read_risk(self, client, tokens):
        response = client.get("/risk/RECIPIENT-001", headers=headers(tokens["auditor"]))
        assert response.status_code == 403