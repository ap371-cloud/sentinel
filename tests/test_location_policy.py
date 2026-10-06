"""Trusted-zone restriction on decryption.

Air-gapped by design: zones are locally declared identifiers carried in the
X-Sentinel-Zone header, never an external geolocation lookup. Every decision —
allow or deny — lands in the session's authorisation trace.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.exceptions import AuthorizationDenied, ForgeError
from app.database.session import ops_session
from app.models.sessions import DecryptionSession
from app.services import decryption_service, document_service, identity_service, seed_service

RECIPIENT = "RECIPIENT-001"
DEVICE = "DEV-RECIPIENT-001-A"
HQ = "HQ-CAMPUS"


def scratch_document(session, *, title: str, policy: dict | None = None) -> str:
    actor = identity_service.get(session, "ADMIN-001")
    source = seed_service.synthetic_document(title, "CONFIDENTIAL", "BRAVO", "ZONE-TEST", sections=1)
    return document_service.create_document(
        session,
        actor=actor,
        source=source,
        title=title,
        classification="CONFIDENTIAL",
        unit="BRAVO",
        recipient_ids=[RECIPIENT],
        policy=policy or {},
    )["document_id"]


def decrypt_zone(session, document_id: str, zone: str | None) -> dict:
    actor = identity_service.get(session, RECIPIENT)
    nonce = decryption_service.issue_nonce(
        session, recipient_id=RECIPIENT, document_id=document_id
    )
    return decryption_service.decrypt(
        session,
        actor=actor,
        document_id=document_id,
        device_id=DEVICE,
        nonce=nonce["nonce"],
        zone=zone,
    )


def trace_of(session, session_id: str) -> list[dict]:
    row = session.get(DecryptionSession, session_id)
    return json.loads(row.authorization_trace)


class TestZonePolicy:
    def test_zone_list_is_normalised_and_reported(self, db):
        document_id = scratch_document(
            db, title="ZONE POLICY SET", policy={"allowed_locations": [f"{HQ.lower()} ", "Field"]}
        )
        described = document_service.describe(db, document_id)
        assert described["policy"]["allowed_locations"] == [HQ, "FIELD"]
        assert described["location_policy"]["allowed_zones"] == [HQ, "FIELD"]
        assert described["location_policy"]["every_decision_logged"] is True
        assert "APPLICATION DEPENDENT" in described["location_policy"]["limitation"]

    @pytest.mark.parametrize(
        "bad",
        [
            "HQ-CAMPUS",
            {"zones": [HQ]},
            [""],
            [f"ZONE{i}" for i in range(9)],
            ["BAD ZONE!"],
        ],
    )
    def test_invalid_zone_policies_refuse(self, db, bad):
        actor = identity_service.get(db, "ADMIN-001")
        source = seed_service.synthetic_document("ZONE BAD", "CONFIDENTIAL", "BRAVO", "ZONE-TEST")
        with pytest.raises(ForgeError):
            document_service.create_document(
                db,
                actor=actor,
                source=source,
                title="ZONE BAD",
                classification="CONFIDENTIAL",
                unit="BRAVO",
                recipient_ids=[RECIPIENT],
                policy={"allowed_locations": bad},
            )


class TestZoneDecisions:
    def test_matching_zone_is_allowed_and_traced(self, db):
        document_id = scratch_document(
            db, title="ZONE MATCH", policy={"allowed_locations": [HQ]}
        )
        result = decrypt_zone(db, document_id, HQ)
        checks = trace_of(db, result["session_id"])
        assert any(
            c["check"] == "location_permitted" and c["reason_code"] == "LOCATION_OK"
            for c in checks
        )

    def test_other_zone_is_denied_with_the_zone_reason(self, db):
        document_id = scratch_document(
            db, title="ZONE MISMATCH", policy={"allowed_locations": [HQ]}
        )
        with pytest.raises(AuthorizationDenied) as failure:
            decrypt_zone(db, document_id, "REMOTE-HOME")
        assert failure.value.detail == "LOCATION_NOT_ALLOWED"
        assert "REMOTE-HOME" in failure.value.args[0]

    def test_no_declared_zone_is_a_distinct_denial(self, db):
        document_id = scratch_document(
            db, title="ZONE ABSENT", policy={"allowed_locations": [HQ]}
        )
        with pytest.raises(AuthorizationDenied) as failure:
            decrypt_zone(db, document_id, None)
        assert failure.value.detail == "LOCATION_UNKNOWN"

    def test_unrestricted_documents_ignore_the_zone_header(self, db, brief_id):
        result = decrypt_zone(db, brief_id, None)
        checks = trace_of(db, result["session_id"])
        assert any(
            c["check"] == "location_permitted"
            and c["reason_code"] == "LOCATION_NOT_RESTRICTED"
            for c in checks
        )


class TestZoneOverHttp:
    def test_gateway_header_reaches_the_decision(self, client, tokens):
        with ops_session() as session:
            document_id = scratch_document(
                session, title="ZONE HTTP", policy={"allowed_locations": [HQ]}
            )
        auth = headers_for(tokens["recipient_one"])
        nonce = client.post(
            "/decrypt/authorize",
            json={"document_id": document_id},
            headers=auth,
        ).json()["nonce"]
        allowed = client.post(
            "/decrypt",
            json={"document_id": document_id, "device_id": DEVICE, "nonce": nonce},
            headers={**auth, "X-Sentinel-Zone": f"  {HQ.lower()}  "},
        )
        assert allowed.status_code == 200, allowed.text

        nonce = client.post(
            "/decrypt/authorize",
            json={"document_id": document_id},
            headers=auth,
        ).json()["nonce"]
        refused = client.post(
            "/decrypt",
            json={"document_id": document_id, "device_id": DEVICE, "nonce": nonce},
            headers={**auth, "X-Sentinel-Zone": "ATTACKER-LIVING-ROOM"},
        )
        assert refused.status_code == 403
        error = refused.json()["error"]
        assert error["detail"] == "LOCATION_NOT_ALLOWED"
        assert error["code"] == "ACCESS_DENIED"


def headers_for(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
