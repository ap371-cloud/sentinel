from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.exceptions import DocumentHashMismatch
from ..crypto.hashing import b64d, b64e, canonical_bytes, sha256_hex
from ..crypto.key_management import VAULT, derive_wrapping_key
from ..crypto.pqc import PQC

DEK_BYTES = 32
NONCE_BYTES = 12
CONTENT_CIPHER = "AES-256-GCM"
WRAP_ALGORITHM = "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"


@dataclass
class KeyWrap:
    recipient_id: str
    kem_ciphertext: str
    wrapped_key_nonce: str
    wrapped_key: str
    wrap_algorithm: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "recipient_id": self.recipient_id,
            "kem_ciphertext": self.kem_ciphertext,
            "wrapped_key_nonce": self.wrapped_key_nonce,
            "wrapped_key": self.wrapped_key,
            "wrap_algorithm": self.wrap_algorithm,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "KeyWrap":
        return KeyWrap(
            recipient_id=raw["recipient_id"],
            kem_ciphertext=raw["kem_ciphertext"],
            wrapped_key_nonce=raw["wrapped_key_nonce"],
            wrapped_key=raw["wrapped_key"],
            wrap_algorithm=raw["wrap_algorithm"],
            created_at=raw["created_at"],
        )


def _content_aad(document_id: str, version_id: str, content_sha256: str) -> bytes:
    return canonical_bytes(
        {"document_id": document_id, "version_id": version_id, "content_sha256": content_sha256}
    )


def _wrap_aad(version_id: str, recipient_id: str) -> bytes:
    return canonical_bytes({"version_id": version_id, "recipient_id": recipient_id})


def seal(
    *,
    plaintext_pdf: Path,
    sealed_path: Path,
    document_id: str,
    version_id: str,
    recipient_ids: list[str],
    content_sha256: str,
) -> dict[str, Any]:
    """Encrypt the content once, then wrap the content key separately for each
    recipient.

    That is the broadcast distribution model from the problem statement: one
    ciphertext, many recipients, each able to unwrap the content key only
    through their own post-quantum key-establishment key.
    """
    plaintext = plaintext_pdf.read_bytes()
    document_key = os.urandom(DEK_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    aad = _content_aad(document_id, version_id, content_sha256)
    ciphertext = AESGCM(document_key).encrypt(nonce, plaintext, aad)

    sealed_path.parent.mkdir(parents=True, exist_ok=True)
    sealed = {
        "document_key_id": f"DEK-{version_id}",
        "document_key": b64e(document_key),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "aad": b64e(aad),
        "content_sha256": content_sha256,
        "content_cipher": CONTENT_CIPHER,
        "key_wrap_algorithm": WRAP_ALGORITHM,
        "wrapped_keys": [wrap_document_key(
            document_key=document_key,
            recipient_id=recipient_id,
            document_id=document_id,
            version_id=version_id,
            content_sha256=content_sha256,
        ).to_dict() for recipient_id in recipient_ids],
    }
    sealed_path.write_bytes(canonical_bytes(sealed))
    return sealed


def wrap_document_key(
    *, document_key: bytes, recipient_id: str, document_id: str, version_id: str, content_sha256: str
) -> KeyWrap:
    encapsulation = PQC.encapsulate(VAULT.kem_public_key(recipient_id))
    wrapping_key = derive_wrapping_key(
        encapsulation.shared_secret, "forge:dek-wrap", document_id, version_id, content_sha256, recipient_id
    )
    nonce = os.urandom(NONCE_BYTES)
    wrapped = AESGCM(wrapping_key).encrypt(nonce, document_key, _wrap_aad(version_id, recipient_id))
    return KeyWrap(
        recipient_id=recipient_id,
        kem_ciphertext=b64e(encapsulation.ciphertext),
        wrapped_key_nonce=b64e(nonce),
        wrapped_key=b64e(wrapped),
        wrap_algorithm=WRAP_ALGORITHM,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def unwrap_document_key(*, wrap: KeyWrap, recipient_id: str, document_id: str, version_id: str, content_sha256: str) -> bytes:
    shared_secret = VAULT.decapsulate_for(recipient_id, b64d(wrap.kem_ciphertext))
    wrapping_key = derive_wrapping_key(
        shared_secret, "forge:dek-wrap", document_id, version_id, content_sha256, recipient_id
    )
    return AESGCM(wrapping_key).decrypt(
        b64d(wrap.wrapped_key_nonce), b64d(wrap.wrapped_key), _wrap_aad(version_id, recipient_id)
    )


def open_sealed(
    *,
    sealed_path: Path,
    wrap: KeyWrap,
    recipient_id: str,
    document_id: str,
    version_id: str,
    content_sha256: str,
) -> bytes:
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    document_key = unwrap_document_key(
        wrap=wrap,
        recipient_id=recipient_id,
        document_id=document_id,
        version_id=version_id,
        content_sha256=content_sha256,
    )
    plaintext = AESGCM(document_key).decrypt(
        b64d(sealed["nonce"]), b64d(sealed["ciphertext"]), b64d(sealed["aad"])
    )
    if sha256_hex(plaintext) != content_sha256:
        raise DocumentHashMismatch(
            "The decrypted content does not match the hash recorded for this version.",
            detail="Either the stored ciphertext or the recorded hash was altered.",
        )
    return plaintext


def crypto_note() -> dict[str, str]:
    return {
        "content_cipher": CONTENT_CIPHER,
        "content_note": (
            "Document content is encrypted with AES-256-GCM. FIPS 203 and FIPS 204 standardise "
            "key establishment and signatures; bulk data encryption remains a symmetric AEAD, and "
            "labelling AES as post-quantum would be incorrect."
        ),
        "key_wrap": WRAP_ALGORITHM,
        "key_wrap_note": (
            "Each recipient's copy of the content key is wrapped with a shared secret derived from "
            "ML-KEM-768 encapsulation to that recipient's public key."
        ),
    }
