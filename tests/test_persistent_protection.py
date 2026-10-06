"""Persistent protection: the policy receipt that travels inside each copy.

A restriction nobody can check after the file leaves the viewer is not a
control, so this file tests both the embedded receipt and the honest
limitation statement shipped with it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pymupdf as fitz

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import headers  # noqa: E402

from app.documents import protection
from app.services import decryption_service, document_service, identity_service

DEVICE = "DEV-RECIPIENT-001-A"
RECIPIENT = "RECIPIENT-001"


def decrypt(db, document_id: str) -> dict:
    actor = identity_service.get(db, RECIPIENT)
    nonce = decryption_service.issue_nonce(db, recipient_id=RECIPIENT, document_id=document_id)
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=DEVICE, nonce=nonce["nonce"]
    )


class TestPolicyReceipt:
    def test_decryption_reports_what_travels_with_the_copy(self, db, brief_id):
        result = decrypt(db, brief_id)
        block = result["persistent_protection"]
        assert block["receipt_embedded"] is True
        assert block["receipt_file"] == protection.RECEIPT_FILE
        assert "invisible forensic watermark" in block["travels_with_file"]
        assert "POLICY ENFORCEMENT LIMITATION" in block["limitation"]

    def test_the_receipt_is_inside_the_output_pdf(self, db, brief_id):
        result = decrypt(db, brief_id)
        with fitz.open(result["output_path"]) as copy:
            assert protection.RECEIPT_FILE in copy.embfile_names()
            receipt = json.loads(copy.embfile_get(protection.RECEIPT_FILE))
            metadata = copy.metadata

        assert receipt["session_id"] == result["session_id"]
        assert receipt["document_id"] == brief_id
        assert receipt["classification"] == result["classification"]
        assert receipt["policy_version"]
        version = document_service.current_version(db, brief_id)
        assert receipt["document_sha256"] == version.content_sha256
        assert "DECRYPT" in receipt["rights"]
        assert "OFFLINE" in receipt["rights"]
        assert receipt["event_id"] == result["event_id"]
        assert "APPLICATION DEPENDENT" in receipt["notice"]

        assert result["classification"] in metadata["subject"]
        assert f"SESSION={result['session_id']}" in metadata["keywords"]
        assert f"RECIPIENT={RECIPIENT}" in metadata["keywords"]

    def test_document_detail_explains_the_limitation(self, db, brief_id):
        block = document_service.describe(db, brief_id)["persistent_protection"]
        assert block["policy_receipt_on_every_copy"] is True
        assert "POLICY ENFORCEMENT LIMITATION" in block["limitation"]

    def test_reattaching_a_receipt_replaces_the_previous_one(self, tmp_path):
        source = tmp_path / "copy.pdf"
        document = fitz.open()
        document.new_page().insert_text((72, 72), "sentinel persistent protection test")
        document.save(source)
        document.close()

        receipt = {"session_id": "SES-TEST", "classification": "CONFIDENTIAL"}
        protection.attach(source, receipt)
        protection.attach(source, receipt)
        with fitz.open(source) as copy:
            names = copy.embfile_names()
        assert names.count(protection.RECEIPT_FILE) == 1

    def test_api_decrypt_returns_the_protection_block(self, client, tokens, brief_id):
        token = tokens["recipient_one"]
        nonce = client.post(
            "/decrypt/authorize", headers=headers(token), json={"document_id": brief_id}
        )
        decrypted = client.post(
            "/decrypt",
            headers=headers(token),
            json={"document_id": brief_id, "device_id": DEVICE, "nonce": nonce.json()["nonce"]},
        )
        assert decrypted.status_code == 200, decrypted.text
        block = decrypted.json()["persistent_protection"]
        assert block["receipt_embedded"] is True
        assert "POLICY ENFORCEMENT LIMITATION" in block["limitation"]
