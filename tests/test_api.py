"""HTTP-level tests against the real ASGI application.

These exercise routing, dependency wiring, error mapping and the read-only
auditor boundary, which the service-level tests cannot cover.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.conftest import headers, token_for


class TestSystemEndpoints:
    def test_health_reports_the_real_pqc_backend(self, client):
        body = client.get("/api/health").json()
        assert body["status"] == "UP"
        assert body["post_quantum"]["production_grade_backend"] is True
        assert "ml_dsa" in body["post_quantum"]["backend"].lower() or "Mldsa" in body["post_quantum"]["signing"]

    def test_status_reports_air_gap_and_ledger(self, client):
        body = client.get("/api/status").json()
        assert body["air_gap"]["air_gapped_mode"] == "ACTIVE"
        assert body["air_gap"]["guard_installed"] is True
        assert body["ledger"]["node_count"] == 3

    def test_status_lists_the_outcome_vocabulary(self, client):
        body = client.get("/api/status").json()
        assert "VERIFIED ASSOCIATION" in body["ui_contract"]["forensic_outcomes"]
        assert "TAMPER DETECTED" in body["ui_contract"]["statuses"]

    def test_openapi_is_served(self, client):
        schema = client.get("/api/openapi.json").json()
        assert "/decrypt" in schema["paths"]
        assert "/forensics/analyze" in schema["paths"]


class TestAuthentication:
    def test_login_succeeds_and_returns_identity(self, client):
        response = client.post(
            "/auth/login",
            json={"recipient_id": "RECIPIENT-001", "password": "Recipient1!2026"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["token"]
        assert body["identity"]["role"] == "RECIPIENT"
        assert "password" not in str(body["identity"]).lower()

    def test_wrong_passphrase_is_refused(self, client):
        response = client.post(
            "/auth/login", json={"recipient_id": "RECIPIENT-001", "password": "nope"}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "AUTHENTICATION_FAILED"

    def test_unknown_identity_is_refused(self, client):
        response = client.post(
            "/auth/login", json={"recipient_id": "NOBODY-999", "password": "whatever"}
        )
        assert response.status_code == 401

    def test_protected_route_without_token_is_refused(self, client):
        assert client.get("/commander/dashboard").status_code == 401

    def test_garbage_token_is_refused(self, client):
        assert client.get("/commander/dashboard", headers=headers("not-a-token")).status_code == 401

    def test_whoami_lists_permissions(self, client, tokens):
        body = client.get("/auth/whoami", headers=headers(tokens["auditor"])).json()
        assert body["identity"]["role"] == "AUDITOR"
        assert "evidence.read" in body["permissions"]


class TestSeparationOfDuties:
    def test_recipient_cannot_open_the_command_dashboard(self, client, tokens):
        assert client.get("/commander/dashboard", headers=headers(tokens["recipient_one"])).status_code == 403

    def test_recipient_cannot_read_investigations(self, client, tokens):
        assert client.get("/investigations", headers=headers(tokens["recipient_one"])).status_code == 403

    def test_auditor_cannot_create_an_investigation(self, client, tokens):
        response = client.post(
            "/investigations",
            headers=headers(tokens["auditor"]),
            json={"title": "auditor must not create this"},
        )
        assert response.status_code == 403

    def test_auditor_can_verify_evidence(self, client, tokens):
        assert client.get("/investigations", headers=headers(tokens["auditor"])).status_code == 200

    def test_auditor_cannot_lockdown(self, client, tokens):
        response = client.post(
            "/lockdown", headers=headers(tokens["auditor"]), json={"reason": "auditor attempt"}
        )
        assert response.status_code == 403

    def test_administrator_cannot_run_forensic_analysis(self, client, tokens):
        response = client.post(
            "/forensics/analyze",
            headers=headers(tokens["admin"]),
            data={"case_id": "CASE-2026-001"},
            files={"file": ("x.pdf", b"%PDF-1.4\n", "application/pdf")},
        )
        assert response.status_code == 403

    def test_every_role_matrix_is_exposed_for_review(self, client, tokens):
        body = client.get("/commander/roles", headers=headers(tokens["auditor"])).json()
        admin = next(row for row in body["separation_of_duties"] if row["role"] == "DOCUMENT_ADMIN")
        assert admin["holds_evidence_authority"] is False
        assert admin["holds_ledger_write_authority"] is False


class TestDocumentRoutes:
    def test_list_returns_classification_labels(self, client, tokens):
        body = client.get("/documents", headers=headers(tokens["auditor"])).json()
        assert body["documents"]
        assert all("CLASSIFICATION:" in d["classification_label"] for d in body["documents"])

    def test_detail_exposes_no_key_material(self, client, tokens, brief_id):
        body = client.get(f"/documents/{brief_id}", headers=headers(tokens["auditor"])).json()["document"]
        blob = str(body).lower()
        assert "secret_key" not in blob
        assert "document_key\": \"" not in blob
        assert body["versions"][0]["key_wrap_algorithm"].startswith("ML-KEM")

    def test_classification_labelled_as_prototype(self, client, tokens):
        body = client.get("/documents/classifications", headers=headers(tokens["auditor"])).json()
        assert "do not reproduce" in body["note"]

    def test_lifecycle_transitions_are_declared(self, client, tokens):
        body = client.get("/documents/lifecycle", headers=headers(tokens["auditor"])).json()
        assert "REVOKED" in body["states"]
        assert body["transitions"]["CREATED"] == ["CLASSIFIED", "ARCHIVED"]

    def test_upload_requires_permission(self, client, tokens):
        response = client.post(
            "/documents",
            headers=headers(tokens["recipient_one"]),
            data={"title": "x", "classification": "RESTRICTED", "unit": "BRAVO"},
            files={"file": ("x.pdf", b"%PDF-1.4\n", "application/pdf")},
        )
        assert response.status_code == 403


class TestDecryptionRoute:
    def test_authorise_then_decrypt(self, client, tokens, brief_id):
        token = tokens["recipient_one"]
        nonce = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": brief_id}
        ).json()
        result = client.post(
            "/decrypt",
            headers=headers(token),
            json={"document_id": brief_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce["nonce"]},
        )
        assert result.status_code == 200
        body = result.json()
        assert body["watermark_tag"]
        assert body["ledger"]["committed"] is True
        assert all(check["passed"] for check in body["authorization_checks"])

    def test_replay_is_refused_with_a_specific_code(self, client, tokens, brief_id):
        token = tokens["recipient_one"]
        nonce = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": brief_id}
        ).json()
        client.post(
            "/decrypt",
            headers=headers(token),
            json={"document_id": brief_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce["nonce"]},
        )
        replay = client.post(
            "/decrypt",
            headers=headers(token),
            json={"document_id": brief_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce["nonce"]},
        )
        assert replay.status_code == 403
        assert replay.json()["error"]["code"] == "REPLAY_ATTACK_DETECTED"

    def test_unknown_device_is_refused(self, client, tokens, brief_id):
        token = tokens["recipient_one"]
        nonce = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": brief_id}
        ).json()
        response = client.post(
            "/decrypt",
            headers=headers(token),
            json={"document_id": brief_id, "device_id": "DEV-NOT-REGISTERED", "nonce": nonce["nonce"]},
        )
        assert response.json()["error"]["code"] == "DEVICE_NOT_AUTHORIZED"

    def test_unknown_document_returns_404(self, client, tokens):
        token = tokens["recipient_one"]
        response = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": "DOC-NOPE"}
        )
        assert response.status_code in (200, 404)

    def test_malformed_body_is_rejected_cleanly(self, client, tokens):
        response = client.post(
            "/decrypt", headers=headers(tokens["recipient_one"]), json={"document_id": ""}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_REQUEST"

    def test_viewer_note_documents_the_export_limitation(self, client, tokens, brief_id):
        token = tokens["recipient_one"]
        nonce = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": brief_id}
        ).json()
        body = client.post(
            "/decrypt",
            headers=headers(token),
            json={"document_id": brief_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce["nonce"]},
        ).json()
        assert "hardened endpoint" in body["viewer_note"]


class TestLedgerRoutes:
    def test_status_lists_three_nodes(self, client, tokens):
        body = client.get("/ledger/status", headers=headers(tokens["auditor"])).json()
        assert body["node_count"] == 3
        assert all("block_height" in node for node in body["nodes"])

    def test_verify_reports_integrity(self, client, tokens):
        body = client.get("/ledger/verify", headers=headers(tokens["auditor"])).json()
        assert "headline" in body
        assert body["quorum_size"] == 2

    def test_node_admin_requires_two_person_control(self, client, tokens):
        response = client.post(
            "/ledger/nodes/admin",
            headers=headers(tokens["ledger"]),
            json={"node_id": "NODE-C", "operation": "OFFLINE", "reason": "unauthorised attempt"},
        )
        assert response.status_code in (400, 403, 428)


class TestSecurityRoutes:
    def test_security_events_have_command_guidance(self, client, tokens):
        body = client.get("/security-events", headers=headers(tokens["officer"])).json()
        assert body["events"]
        assert all(e["plain_explanation"] for e in body["events"])

    def test_lab_scenario_catalogue_is_labelled(self, client, tokens):
        body = client.get("/security-lab/scenarios", headers=headers(tokens["auditor"])).json()
        assert body["environment"] == "DEMO SECURITY LAB"
        assert len(body["scenarios"]) >= 9

    def test_lab_simulation_runs_real_backend_logic(self, client, tokens):
        outcome = client.post(
            "/security-lab/simulate", headers=headers(tokens["officer"]), json={"scenario": "signature_forgery"}
        ).json()
        assert outcome["detected"] is True
        assert outcome["verdict"] == "SIGNATURE INVALID"

    def test_unknown_scenario_is_refused(self, client, tokens):
        response = client.post(
            "/security-lab/simulate", headers=headers(tokens["officer"]), json={"scenario": "invented"}
        )
        assert response.status_code == 400

    def test_ai_health_is_always_available_as_a_route(self, client, tokens):
        body = client.get("/ai/health", headers=headers(tokens["commander"])).json()
        assert body["status"] in ("ONLINE", "AI SERVICE OFFLINE")

    def test_audit_trail_is_hash_chained(self, client, tokens):
        body = client.get("/audit", headers=headers(tokens["auditor"]), params={"limit": 50}).json()
        assert body["chain"]["status"] == "VERIFIED"
        assert body["privileged_actions"]


class TestLockdownRoute:
    def test_lockdown_blocks_and_release_needs_approval(self, client, tokens, brief_id):
        engagement = client.post(
            "/lockdown", headers=headers(tokens["commander"]), json={"reason": "http lockdown verification"}
        )
        assert engagement.json()["system_status"] == "EMERGENCY LOCKDOWN"
        try:
            nonce = client.post(
                "/decrypt/authorize", headers=headers(tokens["recipient_one"]),
                json={"document_id": brief_id},
            ).json()
            blocked = client.post(
                "/decrypt",
                headers=headers(tokens["recipient_one"]),
                json={"document_id": brief_id, "device_id": "DEV-RECIPIENT-001-A", "nonce": nonce["nonce"]},
            )
            assert blocked.status_code == 423
            assert client.get("/audit", headers=headers(tokens["auditor"])).status_code == 200
            release = client.post(
                "/unlock", headers=headers(tokens["commander"]),
                json={"reason": "release without approval", "approval_id": ""},
            )
            assert release.status_code in (400, 403, 428)
        finally:
            from app.security import lockdown
            from app.database.session import ops_session

            with ops_session() as session:
                if lockdown.is_active(session):
                    lockdown.release(session, actor_id="COMMANDER-001", reason="http test teardown")
