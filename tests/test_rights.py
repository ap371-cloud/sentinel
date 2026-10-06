"""Granular usage rights: classification defaults, per-document layering and
the enforcement points that actually refuse a request.

A right that is stored but never enforced is a claim, not a control, so every
enforced right gets a negative test at the route that owns it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from app.core import rights
from app.core.exceptions import AuthorizationDenied, ForgeError
from app.core.permissions import RequestContext, evaluate_decryption, raise_for_decision
from app.core.config import Clearance, DocumentAccess, Role
from app.database.session import ensure_column
from app.models.documents import Document

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import headers  # noqa: E402


class StubDocument:
    """The layering rules are pure functions of five attributes; a stub keeps
    these tests independent of the database."""

    def __init__(self, classification: str = "CONFIDENTIAL", **overrides):
        self.classification = classification
        self.download_allowed = True
        self.print_allowed = False
        self.export_allowed = True
        self.offline_allowed = False
        self.rights = "{}"
        for name, value in overrides.items():
            setattr(self, name, value)


def context(**overrides) -> RequestContext:
    base = dict(
        actor_id="RECIPIENT-001",
        role=Role.RECIPIENT,
        unit="BRAVO",
        clearance=Clearance.CONFIDENTIAL.value,
        account_status="ACTIVE",
        device_id="DEV-1",
        document_classification=Clearance.CONFIDENTIAL.value,
        document_status=DocumentAccess.SEALED,
        document_unit_scope=["BRAVO"],
        document_role_scope=[Role.RECIPIENT],
        granted=True,
        device_status="ACTIVE",
        device_trust="TRUSTED",
        device_owner_id="RECIPIENT-001",
        signing_key_status="ACTIVE",
        signing_key_expired=False,
        kem_key_status="ACTIVE",
        nonce_consumed=False,
        nonce_expired=False,
        nonce_owner_match=True,
        lockdown_active=False,
    )
    base.update(overrides)
    return RequestContext(**base)


class TestClassificationDefaults:
    def test_stricter_labels_tighten_usage_rights(self):
        assert rights.classification_defaults("UNCLASSIFIED")["PRINT"] == rights.ALLOW
        assert rights.classification_defaults("CONFIDENTIAL")["PRINT"] == rights.DENY
        assert rights.classification_defaults("SECRET")["DOWNLOAD"] == rights.ALLOW
        assert rights.classification_defaults("TOP_SECRET")["DOWNLOAD"] == rights.DENY

    def test_key_recovery_is_never_a_default(self):
        for label in ("UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"):
            assert rights.classification_defaults(label)["RECOVER_KEY"] == rights.DENY

    def test_decryption_stays_possible_on_every_label(self):
        for label in ("UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"):
            matrix = rights.classification_defaults(label)
            assert matrix["DECRYPT"] == rights.ALLOW
            assert matrix["VIEW"] == rights.ALLOW

    def test_unknown_classification_fails_closed(self):
        assert rights.classification_defaults("MADE-UP-LABEL")["DOWNLOAD"] == rights.DENY


class TestRightLayering:
    def test_document_columns_beat_the_classification_baseline(self):
        doc = StubDocument("CONFIDENTIAL", print_allowed=True)
        assert rights.effective_rights(doc)["PRINT"] == rights.ALLOW

    def test_explicit_override_beats_the_columns(self):
        assert rights.effective_rights(StubDocument(rights='{"PRINT": "ALLOW"}'))["PRINT"] == rights.ALLOW
        doc = StubDocument(rights='{"DOWNLOAD": "DENY"}')
        assert rights.effective_rights(doc)["DOWNLOAD"] == rights.DENY

    def test_sources_name_the_layer_that_decided(self):
        doc = StubDocument(rights='{"PRINT": "ALLOW"}')
        sources = rights.right_sources(doc)
        assert sources["PRINT"] == rights.SOURCE_EXPLICIT
        assert sources["DOWNLOAD"] == rights.SOURCE_DOCUMENT
        assert sources["VIEW"] == rights.SOURCE_CLASSIFICATION

    def test_garbage_override_json_is_ignored_not_fatal(self):
        doc = StubDocument(rights="{not json")
        assert rights.effective_rights(doc)["PRINT"] == rights.DENY

    def test_unknown_right_in_override_is_dropped(self):
        doc = StubDocument(rights='{"MIND_READING": "ALLOW"}')
        assert "MIND_READING" not in rights.effective_rights(doc)

    def test_validate_overrides_rejects_unknown_names_and_values(self):
        with pytest.raises(ForgeError):
            rights.validate_overrides({"MIND_READING": "ALLOW"})
        with pytest.raises(ForgeError):
            rights.validate_overrides({"PRINT": "MAYBE"})
        assert rights.validate_overrides({"PRINT": "ALLOW"}) == {"PRINT": "ALLOW"}


class TestRightEnforcementHelpers:
    def test_require_right_raises_with_the_right_named_in_the_detail(self):
        with pytest.raises(AuthorizationDenied) as excinfo:
            rights.require_right(StubDocument(), "PRINT", operation="Printing this document")
        assert "RIGHT_PRINT_DENIED" in excinfo.value.detail

    def test_require_right_passes_when_allowed(self):
        rights.require_right(StubDocument("UNCLASSIFIED", print_allowed=None), "PRINT", operation="Printing")

    def test_evaluate_right_explains_itself(self):
        allowed, reason, plain = rights.evaluate_right(StubDocument(), "PRINT")
        assert allowed is False
        assert reason == "RIGHT_PRINT_DENIED"
        assert "document policy" in plain

    def test_evaluate_right_flags_unknown_rights(self):
        allowed, reason, _ = rights.evaluate_right(StubDocument(), "MIND_READING")
        assert allowed is False
        assert reason.endswith("_UNKNOWN")


class TestDecryptionGate:
    def test_denied_decrypt_right_refuses_a_otherwise_valid_request(self):
        decision = evaluate_decryption(context(decrypt_right=rights.DENY))
        assert decision.allowed is False
        assert decision.reason_code == "DECRYPT_RIGHT_DENIED"
        with pytest.raises(AuthorizationDenied) as excinfo:
            raise_for_decision(decision)
        assert excinfo.value.detail == "DECRYPT_RIGHT_DENIED"

    def test_allowed_decrypt_right_keeps_the_trace_visible(self):
        decision = evaluate_decryption(context())
        assert decision.allowed is True
        trace = {check["check"]: check["passed"] for check in decision.trace()}
        assert trace["decrypt_right"] is True


class TestModelSurface:
    def test_policy_reports_the_effective_matrix_and_sources(self):
        doc = Document(
            document_id="DOC-TEST",
            title="rights",
            classification="SECRET",
            owner_id="ADMIN-001",
            owning_unit="BRAVO",
            policy_version="POL-1.0",
            rights='{"DOWNLOAD": "DENY"}',
        )
        policy = doc.policy()
        assert policy["rights"]["DOWNLOAD"] == rights.DENY
        assert policy["rights"]["PRINT"] == rights.DENY
        assert policy["right_sources"]["DOWNLOAD"] == rights.SOURCE_EXPLICIT
        assert policy["rights_overrides"] == {"DOWNLOAD": "DENY"}
        assert policy["classification_defaults"]["VIEW"] == rights.ALLOW


class TestSchemaMigration:
    def test_ensure_column_lifts_a_new_column_onto_an_old_table(self, tmp_path):
        engine = create_engine(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE documents (document_id VARCHAR(32) PRIMARY KEY)"))
        ensure_column(engine, "documents", "rights", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(engine, "documents", "rights", "TEXT NOT NULL DEFAULT '{}'")
        with engine.connect() as connection:
            columns = [row[1] for row in connection.execute(text('PRAGMA table_info("documents")'))]
        assert "rights" in columns


class TestRouteEnforcement:
    """End-to-end: the refusal must come from the route, with the right named."""

    @pytest.fixture(scope="class")
    def docs(self):
        from app.database.session import ops_session
        from app.services import document_service, identity_service, seed_service

        created = {}
        with ops_session() as session:
            actor = identity_service.get(session, "ADMIN-001")
            plan = {
                "no_decrypt": {"DECRYPT": "DENY"},
                "no_download": {"DOWNLOAD": "DENY"},
                "no_view": {"VIEW": "DENY"},
            }
            for name, overrides in plan.items():
                source = seed_service.synthetic_document(
                    f"RIGHTS TEST {name}", "CONFIDENTIAL", "BRAVO", "RIGHTS-TEST", sections=1
                )
                result = document_service.create_document(
                    session,
                    actor=actor,
                    source=source,
                    title=f"RIGHTS TEST {name}",
                    classification="CONFIDENTIAL",
                    unit="BRAVO",
                    recipient_ids=["RECIPIENT-001"],
                    policy={"rights": overrides},
                )
                created[name] = result["document_id"]
        return created

    def _nonce(self, client, token, document_id):
        response = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": document_id}
        )
        assert response.status_code == 200, response.text
        return response.json()["nonce"]

    def test_decryption_is_refused_when_the_right_is_denied(self, client, tokens, docs):
        token = tokens["recipient_one"]
        nonce = self._nonce(client, token, docs["no_decrypt"])
        response = client.post(
            "/decrypt",
            headers=headers(token),
            json={
                "document_id": docs["no_decrypt"],
                "device_id": "DEV-RECIPIENT-001-A",
                "nonce": nonce,
            },
        )
        assert response.status_code == 403
        error = response.json()["error"]
        assert error["code"] == "ACCESS_DENIED"
        assert error["detail"] == "DECRYPT_RIGHT_DENIED"

    def test_document_detail_is_refused_when_view_is_denied(self, client, tokens, docs):
        response = client.get(f"/documents/{docs['no_view']}", headers=headers(tokens["recipient_one"]))
        assert response.status_code == 403
        assert "RIGHT_VIEW_DENIED" in response.json()["error"]["detail"]

    def test_session_copy_download_is_refused_when_denied(self, client, tokens, docs):
        token = tokens["recipient_one"]
        nonce = self._nonce(client, token, docs["no_download"])
        decrypted = client.post(
            "/decrypt",
            headers=headers(token),
            json={
                "document_id": docs["no_download"],
                "device_id": "DEV-RECIPIENT-001-A",
                "nonce": nonce,
            },
        )
        assert decrypted.status_code == 200, decrypted.text
        response = client.get(
            f"/sessions/{decrypted.json()['session_id']}/document", headers=headers(token)
        )
        assert response.status_code == 403
        assert "RIGHT_DOWNLOAD_DENIED" in response.json()["error"]["detail"]

    def test_renamed_export_is_refused_when_export_is_denied(self, client, tokens, docs):
        token = tokens["recipient_one"]
        nonce = self._nonce(client, token, docs["no_download"])
        response = client.post(
            "/decrypt",
            headers=headers(token),
            json={
                "document_id": docs["no_download"],
                "device_id": "DEV-RECIPIENT-001-A",
                "nonce": nonce,
                "export_as": "renamed-copy",
            },
        )
        assert response.status_code == 403
        assert "RIGHT_EXPORT_DENIED" in response.json()["error"]["detail"]

    def test_plain_decryption_still_works_on_the_same_document(self, client, tokens, docs):
        token = tokens["recipient_one"]
        nonce = self._nonce(client, token, docs["no_download"])
        response = client.post(
            "/decrypt",
            headers=headers(token),
            json={
                "document_id": docs["no_download"],
                "device_id": "DEV-RECIPIENT-001-A",
                "nonce": nonce,
            },
        )
        assert response.status_code == 200, response.text
        assert all(check["passed"] for check in response.json()["authorization_checks"])

    def test_policy_endpoint_shows_the_effective_rights(self, client, tokens, docs):
        body = client.get(
            f"/documents/{docs['no_download']}", headers=headers(tokens["recipient_one"])
        ).json()["document"]["policy"]
        assert body["rights"]["DOWNLOAD"] == rights.DENY
        assert body["right_sources"]["DOWNLOAD"] == rights.SOURCE_EXPLICIT

    def test_read_only_roles_cannot_use_write_guarded_routes(self, client, tokens, docs):
        grant = client.post(
            f"/documents/{docs['no_view']}/grants",
            headers=headers(tokens["auditor"]),
            json={"recipient_id": "RECIPIENT-002"},
        )
        assert grant.status_code == 403
        trust = client.post(
            "/devices/DEV-RECIPIENT-001-A/trust",
            headers=headers(tokens["auditor"]),
            json={"trust_state": "TRUSTED", "note": "auditor attempt"},
        )
        assert trust.status_code == 403
