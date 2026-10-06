"""Visible deterrent layer on top of the invisible forensic watermark.

The visible layer persuades a person; attribution must still come from the
invisible layer, so the decisive test here is that forensics still confirms a
leak of a visibly stamped copy.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pymupdf as fitz

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services import (
    decryption_service,
    document_service,
    forensic_service,
    identity_service,
    seed_service,
)

DEVICE = "DEV-RECIPIENT-001-A"
RECIPIENT = "RECIPIENT-001"


def decrypt(db, document_id: str) -> dict:
    actor = identity_service.get(db, RECIPIENT)
    nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=document_id)
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=DEVICE, nonce=nonce["nonce"]
    )


def scratch_document(db, *, title: str, visible_watermark: bool = True) -> str:
    actor = identity_service.get(db, "ADMIN-001")
    source = seed_service.synthetic_document(title, "CONFIDENTIAL", "BRAVO", "VISIBLE-WM-TEST", sections=1)
    result = document_service.create_document(
        db,
        actor=actor,
        source=source,
        title=title,
        classification="CONFIDENTIAL",
        unit="BRAVO",
        recipient_ids=[RECIPIENT],
        policy={"visible_watermark": visible_watermark},
    )
    return result["document_id"]


def page_text(path: str) -> str:
    with fitz.open(path) as copy:
        return "\n".join(page.get_text() for page in copy)


class TestVisibleLayer:
    def test_every_page_names_the_recipient_and_session(self, db, brief_id):
        result = decrypt(db, brief_id)
        text = page_text(result["output_path"])
        assert "AUTHORIZED USER ONLY" in text
        assert RECIPIENT in text
        assert result["session_id"] in text
        assert result["classification"] in text

    def test_the_response_reports_the_visible_layer(self, db, brief_id):
        result = decrypt(db, brief_id)
        visible = result["watermark_quality"]["visible"]
        assert visible["stamped"] is True
        assert visible["opacity"] > 0
        assert "deter" in visible["plain_explanation"]

    def test_document_policy_can_disable_the_visible_layer(self, db):
        document_id = scratch_document(db, title="VISIBLE WM DISABLED", visible_watermark=False)
        result = decrypt(db, document_id)
        assert result["watermark_quality"]["visible"]["stamped"] is False
        assert "AUTHORIZED USER ONLY" not in page_text(result["output_path"])

    def test_policy_reports_the_setting(self, db):
        document_id = scratch_document(db, title="VISIBLE WM POLICY FLAG", visible_watermark=False)
        policy = document_service.describe(db, document_id)["policy"]
        assert policy["visible_watermark"] is False

    def test_invisible_attribution_survives_the_visible_layer(self, db, tmp_path):
        document_id = scratch_document(db, title="VISIBLE WM FORENSICS")
        result = decrypt(db, document_id)
        investigator = identity_service.get(db, "INVESTIGATOR-001")
        case = forensic_service.open_case(
            db, investigator=investigator, title="visible layer forensics"
        )
        leaked = tmp_path / "LEAKED_VISIBLE_COPY.pdf"
        shutil.copy2(result["output_path"], leaked)
        evidence = forensic_service.store_evidence(
            db, case=case, investigator=investigator,
            leaked_path=leaked, original_filename="LEAKED_VISIBLE_COPY.pdf",
        )
        analysis = forensic_service.analyze(db, evidence=evidence)
        assert analysis["outcome"] == "VERIFIED ASSOCIATION"
        assert analysis["matched_recipient_id"] == RECIPIENT
