from __future__ import annotations

from typing import Any

from ..core.exceptions import SignatureInvalid
from ..crypto.hashing import canonical_bytes
from ..crypto.key_management import VAULT
from ..crypto.pqc import CTX_DECRYPTION_EVENT, CTX_SESSION_ATTESTATION, PQC

#: The service's own signing identity. It signs blocks, votes and its own
#: administrative assertions — and deliberately not recipient decryption
#: events, because a server that could sign those could forge attribution.
SERVER_IDENTITY = "SENTINEL-SERVER"


def ensure_server_identity() -> None:
    if not {record["owner_id"] for record in VAULT.public_metadata()} >= {SERVER_IDENTITY}:
        VAULT.issue_identity(SERVER_IDENTITY)


def event_payload(
    *,
    event_id: str,
    event_type: str,
    session_id: str,
    recipient_id: str,
    document_id: str,
    version_id: str,
    version_number: int,
    document_hash: str,
    device_id: str,
    watermark_tag: str,
    policy_version: str,
    watermark_version: str,
    occurred_at: str,
    break_glass: bool = False,
    exported: bool = False,
) -> dict[str, Any]:
    """Canonical signed body.

    The watermark tag is inside the signed payload on purpose. Without it, a
    recipient could argue that the fingerprint was added after they signed, which
    would undermine the whole attribution claim. The ``exported`` flag is also
    signed so a renamed export copy is attributable, not just a decryption.
    """
    return {
        "event_id": event_id,
        "event_type": event_type,
        "session_id": session_id,
        "recipient_id": recipient_id,
        "document_id": document_id,
        "version_id": version_id,
        "version_number": version_number,
        "document_hash": document_hash,
        "device_id": device_id,
        "watermark_tag": watermark_tag,
        "policy_version": policy_version,
        "watermark_version": watermark_version,
        "occurred_at": occurred_at,
        "break_glass": break_glass,
        "exported": exported,
    }


def canonical_message(payload: dict[str, Any]) -> bytes:
    return canonical_bytes(payload)


def sign_as_recipient(recipient_id: str, payload: dict[str, Any]) -> tuple[str, str, str]:
    """Returns (signature, algorithm, signing_key_id)."""
    signature = VAULT.provider.sign(
        VAULT.signing_secret_for(recipient_id),
        canonical_message(payload),
        context=CTX_DECRYPTION_EVENT,
    )
    key_id = f"{recipient_id}-SIG-{signature.algorithm}"
    return _b64(signature.raw), signature.algorithm, key_id


def verify_recipient_signature(
    recipient_id: str, payload: dict[str, Any], signature_b64: str
) -> bool:
    return VAULT.verify_as(
        recipient_id,
        canonical_message(payload),
        _unb64(signature_b64),
        CTX_DECRYPTION_EVENT,
    )


def sign_session_attestation(recipient_id: str, payload: dict[str, Any]) -> str:
    return _b64(
        VAULT.provider.sign(
            VAULT.signing_secret_for(recipient_id), canonical_message(payload), context=CTX_SESSION_ATTESTATION
        ).raw
    )


def forge_attempt_with_service_key(recipient_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Deliberately wrong path used by the attack lab.

    Signing with the service key instead of the recipient's key produces a
    record that fails verification against the recipient's registered public
    key. That is the demonstration that a compromised server cannot manufacture
    attribution.
    """
    signature = PQC.sign(
        VAULT.signing_secret_for(SERVER_IDENTITY), canonical_message(payload), context=CTX_DECRYPTION_EVENT
    )
    return {
        "claimed_recipient_id": recipient_id,
        "signature": _b64(signature.raw),
        "algorithm": signature.algorithm,
        "signed_by": SERVER_IDENTITY,
        "verifies_against_recipient_key": verify_recipient_signature(
            recipient_id, payload, _b64(signature.raw)
        ),
        "plain_explanation": (
            "The service signed this record with its own key. Verification against the named "
            "recipient's public key fails, so the record cannot be attributed to them."
        ),
    }


def require_valid(recipient_id: str, payload: dict[str, Any], signature_b64: str) -> None:
    if not verify_recipient_signature(recipient_id, payload, signature_b64):
        raise SignatureInvalid(
            "The decryption event signature did not verify against the recipient's public key.",
            detail="The record cannot be attributed to this recipient.",
        )


def _b64(raw: bytes) -> str:
    from ..crypto.hashing import b64e

    return b64e(raw)


def _unb64(text: str) -> bytes:
    from ..crypto.hashing import b64d

    return b64d(text)
