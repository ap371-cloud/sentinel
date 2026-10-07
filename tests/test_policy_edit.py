"""Post-creation policy edits and the read surfaces around them.

A rights system that can only be set at upload time is a one-shot system: a
document cannot be re-tightened after a leak. These tests cover the edit
endpoint, its two-person gate on high-classification documents, the grants
register, the withdrawal register and the dashboard feeds built on them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import headers  # noqa: E402


def _create_document(*, title: str, classification: str) -> str:
    from app.database.session import ops_session
    from app.services import document_service, identity_service, seed_service

    with ops_session() as session:
        actor = identity_service.get(session, "ADMIN-001")
        source = seed_service.synthetic_document(title, classification, "BRAVO", "POLICY-EDIT", sections=1)
        created = document_service.create_document(
            session,
            actor=actor,
            source=source,
            title=title,
            classification=classification,
            unit="BRAVO",
            recipient_ids=["RECIPIENT-001"],
        )
        return created["document_id"]


@pytest.fixture(scope="module")
def confidential_doc() -> str:
    return _create_document(title="POLICY EDIT CONFIDENTIAL", classification="CONFIDENTIAL")


@pytest.fixture(scope="module")
def secret_doc() -> str:
    return _create_document(title="POLICY EDIT SECRET", classification="SECRET")


@pytest.fixture(scope="module")
def revoked_grant_doc() -> str:
    return _create_document(title="POLICY EDIT REVOKED GRANT", classification="CONFIDENTIAL")


def _approve_fully(client, tokens, *, action: str, subject_id: str | None, justification: str) -> str:
    created = client.post(
        "/approvals",
        json={
            "action": action,
            "subject_id": subject_id,
            "justification": justification,
            "required_approvals": 2,
        },
        headers=headers(tokens["admin"]),
    )
    assert created.status_code == 200, created.text
    approval_id = created.json()["approval_id"]
    for approver in ("commander", "officer"):
        decided = client.post(
            f"/approvals/{approval_id}/approve",
            json={"reason": "Approved for the policy edit test."},
            headers=headers(tokens[approver]),
        )
        assert decided.status_code == 200, decided.text
    return approval_id


class TestPolicyEdit:
    def test_admin_can_widen_a_right_after_upload(self, client, tokens, confidential_doc):
        response = client.put(
            f"/documents/{confidential_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Field package must be printable for the briefing.",
                "changes": {"rights": {"PRINT": "ALLOW"}},
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["changes"]["PRINT"] == {"from": "DENY", "to": "ALLOW"}

        detail = client.get(
            f"/documents/{confidential_doc}", headers=headers(tokens["recipient_one"])
        ).json()["document"]["policy"]
        assert detail["rights"]["PRINT"] == "ALLOW"
        assert detail["right_sources"]["PRINT"] == "EXPLICIT_OVERRIDE"

    def test_edit_records_both_verdicts_and_the_reason_on_the_audit_chain(self, db, confidential_doc):
        from app.models.security import AuditRecord

        rows = [
            row
            for row in db.query(AuditRecord)
            .filter_by(action="DOCUMENT_PERMISSION_CHANGED", document_id=confidential_doc)
            .all()
            if row.target_type == "DOCUMENT"
        ]
        assert rows, "the policy edit must land on the audit chain"
        detail = json.loads(rows[-1].detail)
        assert detail["rights_verdicts_before"]["PRINT"] == "DENY"
        assert detail["rights_verdicts_after"]["PRINT"] == "ALLOW"
        assert detail["reason"].startswith("Field package")
        assert rows[-1].policy_version

    def test_settings_beyond_rights_can_be_edited(self, client, tokens, confidential_doc):
        response = client.put(
            f"/documents/{confidential_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Cap sessions at ten for this release cycle.",
                "changes": {"maximum_sessions": 10, "offline_max_hours": 6},
            },
        )
        assert response.status_code == 200, response.text
        changes = response.json()["changes"]
        assert changes["maximum_sessions"]["to"] == 10
        assert changes["offline_max_hours"]["to"] == 6

    def test_read_only_and_unprivileged_roles_are_refused(self, client, tokens, confidential_doc):
        payload = {
            "reason": "Trying to edit policy without the permission.",
            "changes": {"rights": {"COPY": "ALLOW"}},
        }
        for actor in ("auditor", "recipient_one", "recipient_two"):
            response = client.put(
                f"/documents/{confidential_doc}/policy",
                headers=headers(tokens[actor]),
                json=payload,
            )
            assert response.status_code == 403, f"{actor}: {response.text}"

    def test_unknown_policy_setting_is_rejected_loudly(self, client, tokens, confidential_doc):
        response = client.put(
            f"/documents/{confidential_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Typo in the settings name must not be a silent no-op.",
                "changes": {"print_allowed_now": True},
            },
        )
        assert response.status_code == 400
        error = response.json()["error"]
        assert "Unknown settings: print_allowed_now" in error["detail"]

    def test_a_no_op_edit_is_rejected_rather_than_logged_as_a_change(self, client, tokens, confidential_doc):
        response = client.put(
            f"/documents/{confidential_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Setting PRINT to the value it already has.",
                "changes": {"rights": {"PRINT": "ALLOW"}},
            },
        )
        assert response.status_code == 400
        assert "no effective change" in response.json()["error"]["detail"]

    def test_a_written_reason_is_mandatory(self, client, tokens, confidential_doc):
        response = client.put(
            f"/documents/{confidential_doc}/policy",
            headers=headers(tokens["admin"]),
            json={"reason": "short", "changes": {"rights": {"COPY": "ALLOW"}}},
        )
        assert response.status_code == 422

    def test_unknown_document_is_a_404(self, client, tokens):
        response = client.put(
            "/documents/DOC-NOPE/policy",
            headers=headers(tokens["admin"]),
            json={"reason": "There is no document with this identifier.", "changes": {"maximum_sessions": 5}},
        )
        assert response.status_code == 404


class TestHighClassificationTwoPerson:
    def test_secret_document_edit_without_approval_is_refused(self, client, tokens, secret_doc):
        response = client.put(
            f"/documents/{secret_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Attempting an unapproved high-classification edit.",
                "changes": {"rights": {"PRINT": "ALLOW"}},
            },
        )
        assert response.status_code == 428
        error = response.json()["error"]
        assert error["code"] == "TWO_PERSON_APPROVAL_REQUIRED"
        assert "DOCUMENT_ACCESS_HIGH_CLASSIFICATION" in error["detail"]

    def test_secret_document_edit_lands_with_a_second_identity(self, client, tokens, secret_doc):
        approval_id = _approve_fully(
            client,
            tokens,
            action="DOCUMENT_ACCESS_HIGH_CLASSIFICATION",
            subject_id=secret_doc,
            justification="Print is required for the sealed-briefing packet.",
        )
        response = client.put(
            f"/documents/{secret_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Print is required for the sealed-briefing packet.",
                "changes": {"rights": {"PRINT": "ALLOW"}},
                "approval_id": approval_id,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["approval_id"] == approval_id
        assert body["changes"]["PRINT"] == {"from": "DENY", "to": "ALLOW"}

    def test_the_approval_is_single_use(self, client, tokens, secret_doc):
        approval_id = _approve_fully(
            client,
            tokens,
            action="DOCUMENT_ACCESS_HIGH_CLASSIFICATION",
            subject_id=secret_doc,
            justification="Second edit under a fresh approval for the packet.",
        )
        first = client.put(
            f"/documents/{secret_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "First edit consumes the approval.",
                "changes": {"rights": {"COPY": "ALLOW"}},
                "approval_id": approval_id,
            },
        )
        assert first.status_code == 200, first.text
        second = client.put(
            f"/documents/{secret_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Second edit must not reuse the approval.",
                "changes": {"rights": {"FORWARD": "ALLOW"}},
                "approval_id": approval_id,
            },
        )
        assert second.status_code == 400
        assert "already been used" in second.json()["error"]["detail"]

    def test_an_approval_for_a_different_action_is_refused(self, client, tokens, secret_doc):
        approval_id = _approve_fully(
            client,
            tokens,
            action="SECURITY_POLICY_MODIFICATION",
            subject_id=None,
            justification="This approval is for the global policy, not a document.",
        )
        response = client.put(
            f"/documents/{secret_doc}/policy",
            headers=headers(tokens["admin"]),
            json={
                "reason": "Trying to spend a global-policy approval here.",
                "changes": {"rights": {"PRINT": "ALLOW"}},
                "approval_id": approval_id,
            },
        )
        assert response.status_code == 400
        assert "SECURITY_POLICY_MODIFICATION" in response.json()["error"]["detail"]


class TestGrantsListing:
    def test_grants_listing_names_the_holders_and_their_state(self, client, tokens, confidential_doc):
        response = client.get(
            f"/documents/{confidential_doc}/grants", headers=headers(tokens["recipient_one"])
        )
        assert response.status_code == 200, response.text
        grants = response.json()["grants"]
        holder = next(g for g in grants if g["recipient_id"] == "RECIPIENT-001")
        assert holder["status"] == "ACTIVE"
        assert holder["recipient_name"]
        assert holder["recipient_role"] == "RECIPIENT"

    def test_a_revoked_grant_shows_as_revoked(self, client, tokens, revoked_grant_doc):
        revoked = client.post(
            f"/documents/{revoked_grant_doc}/access/revoke",
            headers=headers(tokens["officer"]),
            json={"recipient_id": "RECIPIENT-001", "reason": "Need-to-know withdrawn for the test."},
        )
        assert revoked.status_code == 200, revoked.text

        response = client.get(
            f"/documents/{revoked_grant_doc}/grants", headers=headers(tokens["admin"])
        )
        assert response.status_code == 200, response.text
        holder = next(g for g in response.json()["grants"] if g["recipient_id"] == "RECIPIENT-001")
        assert holder["status"] == "REVOKED"
        assert holder["revoked_at"]

    def test_grants_are_readable_by_verification_roles_and_unknown_documents_404(self, client, tokens, confidential_doc):
        # Other suite files permanently revoke RECIPIENT-002, so use the
        # read-only auditor: verification roles must be able to audit grants.
        response = client.get(
            f"/documents/{confidential_doc}/grants", headers=headers(tokens["auditor"])
        )
        assert response.status_code == 200, response.text
        response = client.get(
            "/documents/DOC-NOPE/grants", headers=headers(tokens["admin"])
        )
        assert response.status_code == 404


class TestRevocationRegister:
    def test_auditor_can_read_the_register_but_a_plain_recipient_cannot(self, client, tokens):
        allowed = client.get("/revocations", headers=headers(tokens["auditor"]))
        assert allowed.status_code == 200, allowed.text
        assert isinstance(allowed.json()["revocations"], list)

        refused = client.get("/revocations", headers=headers(tokens["recipient_one"]))
        assert refused.status_code == 403

    def test_a_recorded_revocation_is_visible_in_the_register(self, client, tokens):
        from app.database.session import ops_session
        from app.security.revocation import record_revocation

        with ops_session() as session:
            record_revocation(
                session,
                subject_type="DEVICE",
                subject_id="DEV-REGISTER-TEST-001",
                scope="DECRYPTION",
                reason="test-only register entry",
                actor_id="SECURITY-001",
            )

        response = client.get(
            "/revocations", headers=headers(tokens["auditor"]), params={"subject_type": "DEVICE"}
        )
        assert response.status_code == 200, response.text
        rows = response.json()["revocations"]
        match = next((r for r in rows if r["subject_id"] == "DEV-REGISTER-TEST-001"), None)
        assert match is not None
        assert match["scope"] == "DECRYPTION"
        assert match["revoked_by"] == "SECURITY-001"


class TestDashboardFeeds:
    def test_dashboard_carries_denials_revocations_and_the_watchlist(self, client, tokens):
        response = client.get("/commander/dashboard", headers=headers(tokens["commander"]))
        assert response.status_code == 200, response.text
        body = response.json()
        assert "recent_policy_denials" in body
        assert "recent_revocations" in body
        assert isinstance(body["recent_revocations"], list)
        assert "risk_watchlist" in body
        assert all(
            {"recipient_id", "risk_score", "risk_level"} <= set(row)
            for row in body["risk_watchlist"]
        )
        assert body["kpis"]["policy_denials"] >= 0
        assert body["kpis"]["revocations_recorded"] >= 1

    def test_denials_feed_lists_denied_decryptions_with_the_reason(self, client, tokens):
        from app.database.session import ops_session
        from app.services import audit_service

        with ops_session() as session:
            audit_service.record(
                session,
                actor_id="RECIPIENT-002",
                action="DECRYPT_DENIED",
                target_type="DOCUMENT",
                target_id="DOC-FEED-TEST",
                document_id="DOC-FEED-TEST",
                reason="DECRYPT_RIGHT_DENIED",
            )

        body = client.get("/commander/dashboard", headers=headers(tokens["officer"])).json()
        assert body["kpis"]["policy_denials"] >= 1
        assert body["recent_policy_denials"], "denied decryptions must reach the board"
        newest = body["recent_policy_denials"][0]
        assert {"audit_id", "actor_id", "reason", "occurred_at"} <= set(newest)
