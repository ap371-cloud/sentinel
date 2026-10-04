"""Cryptographic primitive tests.

These cover the actual algorithms rather than a wrapper around them: real
ML-DSA-65 signing, real ML-KEM-768 key establishment, real authenticated
encryption, and the negative cases that matter.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import DocumentHashMismatch
from app.crypto.hashing import b64d, b64e, canonical_bytes, sha256_hex
from app.crypto.key_management import VAULT
from app.crypto.pqc import (
    CTX_DECRYPTION_EVENT,
    CTX_LEDGER_BLOCK,
    CTX_LEDGER_VOTE,
    PQC,
    PQCUnavailable,
)
from app.documents import encryption
from app.documents.pdf import normalize_to_pdf
from app.core.config import PATHS


class TestPostQuantumProvider:
    def test_backend_is_the_real_nist_implementation(self):
        assert PQC.available, "no post-quantum backend available"
        meta = PQC.metadata
        assert meta.production_grade is True
        assert "ml_dsa_65" in meta.backend_module
        assert "ml_kem_768" in meta.backend_module
        assert "pqcrypto" in meta.backend_library

    def test_signing_round_trip(self):
        keys = PQC.generate_signing_keypair()
        signature = PQC.sign(keys.secret_key, b"decryption event", context=CTX_DECRYPTION_EVENT)
        assert PQC.verify(keys.public_key, b"decryption event", signature.raw, context=CTX_DECRYPTION_EVENT)

    def test_tampered_message_fails_verification(self):
        keys = PQC.generate_signing_keypair()
        signature = PQC.sign(keys.secret_key, b"decryption event", context=CTX_DECRYPTION_EVENT)
        assert not PQC.verify(
            keys.public_key, b"decryption evenx", signature.raw, context=CTX_DECRYPTION_EVENT
        )

    def test_wrong_key_fails_verification(self):
        signer = PQC.generate_signing_keypair()
        other = PQC.generate_signing_keypair()
        signature = PQC.sign(signer.secret_key, b"payload", context=CTX_DECRYPTION_EVENT)
        assert not PQC.verify(other.public_key, b"payload", signature.raw, context=CTX_DECRYPTION_EVENT)

    def test_domain_separation_prevents_cross_use(self):
        """A signature minted for a decryption event must not verify as a ledger
        block or a vote, otherwise the contexts would be decorative."""
        keys = PQC.generate_signing_keypair()
        signature = PQC.sign(keys.secret_key, b"same bytes", context=CTX_DECRYPTION_EVENT)
        assert not PQC.verify(keys.public_key, b"same bytes", signature.raw, context=CTX_LEDGER_BLOCK)
        assert not PQC.verify(keys.public_key, b"same bytes", signature.raw, context=CTX_LEDGER_VOTE)

    def test_kem_round_trip(self):
        keys = PQC.generate_kem_keypair()
        encapsulation = PQC.encapsulate(keys.public_key)
        assert PQC.decapsulate(keys.secret_key, encapsulation.ciphertext) == encapsulation.shared_secret

    def test_kem_decapsulation_with_wrong_key_differs(self):
        keys = PQC.generate_kem_keypair()
        attacker = PQC.generate_kem_keypair()
        encapsulation = PQC.encapsulate(keys.public_key)
        assert PQC.decapsulate(attacker.secret_key, encapsulation.ciphertext) != encapsulation.shared_secret

    def test_two_encapsulations_differ(self):
        keys = PQC.generate_kem_keypair()
        first = PQC.encapsulate(keys.public_key)
        second = PQC.encapsulate(keys.public_key)
        assert first.ciphertext != second.ciphertext
        assert first.shared_secret != second.shared_secret


class TestAuthenticatedEncryption:
    def test_seal_and_open_for_every_recipient(self, tmp_path):
        source = tmp_path / "plain.pdf"
        source.write_bytes(b"%PDF-1.4\nsynthetic plaintext payload\n")
        recipient_ids = ["RECIPIENT-001", "RECIPIENT-002"]

        sealed = encryption.seal(
            plaintext_pdf=source,
            sealed_path=tmp_path / "sealed.bin",
            document_id="DOC-T1",
            version_id="VER-T1",
            recipient_ids=recipient_ids,
            content_sha256=sha256_hex(source.read_bytes()),
        )

        assert len(sealed["wrapped_keys"]) == 2
        for raw in sealed["wrapped_keys"]:
            wrap = encryption.KeyWrap.from_dict(raw)
            recovered = encryption.open_sealed(
                sealed_path=tmp_path / "sealed.bin",
                wrap=wrap,
                recipient_id=wrap.recipient_id,
                document_id="DOC-T1",
                version_id="VER-T1",
                content_sha256=sha256_hex(source.read_bytes()),
            )
            assert recovered == source.read_bytes()

    def test_recipient_cannot_open_another_recipients_wrap(self, tmp_path):
        source = tmp_path / "plain.pdf"
        source.write_bytes(b"%PDF-1.4\npayload\n")
        digest = sha256_hex(source.read_bytes())
        sealed = encryption.seal(
            plaintext_pdf=source,
            sealed_path=tmp_path / "sealed.bin",
            document_id="DOC-T2",
            version_id="VER-T2",
            recipient_ids=["RECIPIENT-001", "RECIPIENT-002"],
            content_sha256=digest,
        )
        wraps = {w["recipient_id"]: encryption.KeyWrap.from_dict(w) for w in sealed["wrapped_keys"]}
        with pytest.raises(Exception):
            encryption.open_sealed(
                sealed_path=tmp_path / "sealed.bin",
                wrap=wraps["RECIPIENT-002"],
                recipient_id="RECIPIENT-001",
                document_id="DOC-T2",
                version_id="VER-T2",
                content_sha256=digest,
            )

    def test_modified_ciphertext_is_detected(self, tmp_path):
        source = tmp_path / "plain.pdf"
        source.write_bytes(b"%PDF-1.4\npayload\n")
        digest = sha256_hex(source.read_bytes())
        sealed = encryption.seal(
            plaintext_pdf=source,
            sealed_path=tmp_path / "sealed.bin",
            document_id="DOC-T3",
            version_id="VER-T3",
            recipient_ids=["RECIPIENT-001"],
            content_sha256=digest,
        )
        blob = bytearray((tmp_path / "sealed.bin").read_bytes())
        position = blob.find(b"ciphertext")
        blob[position + 40] = blob[position + 40] ^ 0x01
        (tmp_path / "tampered.bin").write_bytes(bytes(blob))
        wrap = encryption.KeyWrap.from_dict(sealed["wrapped_keys"][0])
        with pytest.raises(Exception):
            encryption.open_sealed(
                sealed_path=tmp_path / "tampered.bin",
                wrap=wrap,
                recipient_id="RECIPIENT-001",
                document_id="DOC-T3",
                version_id="VER-T3",
                content_sha256=digest,
            )

    def test_mismatched_hash_is_refused(self, tmp_path):
        """The content hash is bound in as AEAD associated data, so a wrong hash
        breaks decryption outright rather than yielding plaintext that is then
        checked. Refusing earlier is the stronger behaviour."""
        source = tmp_path / "plain.pdf"
        source.write_bytes(b"%PDF-1.4\npayload\n")
        sealed = encryption.seal(
            plaintext_pdf=source,
            sealed_path=tmp_path / "sealed.bin",
            document_id="DOC-T4",
            version_id="VER-T4",
            recipient_ids=["RECIPIENT-001"],
            content_sha256=sha256_hex(source.read_bytes()),
        )
        wrap = encryption.KeyWrap.from_dict(sealed["wrapped_keys"][0])
        with pytest.raises(Exception) as caught:
            encryption.open_sealed(
                sealed_path=tmp_path / "sealed.bin",
                wrap=wrap,
                recipient_id="RECIPIENT-001",
                document_id="DOC-T4",
                version_id="VER-T4",
                content_sha256="0" * 64,
            )
        assert "InvalidTag" in type(caught.value).__name__

    def test_wrong_document_id_is_refused(self, tmp_path):
        """The document and version are bound into the wrap, so a wrap issued for
        one version cannot be replayed against another."""
        source = tmp_path / "plain.pdf"
        source.write_bytes(b"%PDF-1.4\npayload\n")
        digest = sha256_hex(source.read_bytes())
        sealed = encryption.seal(
            plaintext_pdf=source,
            sealed_path=tmp_path / "sealed.bin",
            document_id="DOC-T5",
            version_id="VER-T5",
            recipient_ids=["RECIPIENT-001"],
            content_sha256=digest,
        )
        wrap = encryption.KeyWrap.from_dict(sealed["wrapped_keys"][0])
        with pytest.raises(Exception):
            encryption.open_sealed(
                sealed_path=tmp_path / "sealed.bin",
                wrap=wrap,
                recipient_id="RECIPIENT-001",
                document_id="DOC-OTHER",
                version_id="VER-T5",
                content_sha256=digest,
            )


class TestKeyVault:
    def test_private_key_never_leaves_the_vault(self):
        metadata = VAULT.public_metadata("RECIPIENT-001")
        assert metadata
        for record in metadata:
            assert "secret_key" not in record
            assert "private" not in str(record).lower()

    def test_sign_as_and_verify_as(self):
        message = canonical_bytes({"event": "unit-test"})
        signature = VAULT.sign_as("RECIPIENT-001", message, CTX_DECRYPTION_EVENT)
        assert VAULT.verify_as("RECIPIENT-001", message, signature, CTX_DECRYPTION_EVENT)
        assert not VAULT.verify_as("RECIPIENT-001", b"other", signature, CTX_DECRYPTION_EVENT)

    def test_signing_key_of_one_identity_does_not_verify_for_another(self):
        message = b"cross-identity check"
        signature = VAULT.sign_as("RECIPIENT-001", message, CTX_DECRYPTION_EVENT)
        assert not VAULT.verify_as("RECIPIENT-002", message, signature, CTX_DECRYPTION_EVENT)

    def test_watermark_root_is_stable_and_long_enough(self):
        root = VAULT.watermark_root()
        assert len(root) == 32
        assert root == VAULT.watermark_root()


class TestCanonicalSerialisation:
    def test_key_order_does_not_change_the_bytes(self):
        assert canonical_bytes({"a": 1, "b": 2}) == canonical_bytes({"b": 2, "a": 1})

    def test_nested_structures_are_stable(self):
        left = {"outer": {"x": [1, 2], "y": {"p": True, "q": None}}}
        right = {"outer": {"y": {"q": None, "p": True}, "x": [1, 2]}}
        assert canonical_bytes(left) == canonical_bytes(right)

    def test_base64_round_trip(self):
        assert b64d(b64e(b"\x00\x01\x02binary")) == b"\x00\x01\x02binary"

    def test_hash_is_stable_across_processes(self):
        assert sha256_hex(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
