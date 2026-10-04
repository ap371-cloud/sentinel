from __future__ import annotations

import hashlib
import hmac
from typing import Any

import numpy as np

from ..crypto.hashing import canonical_bytes, keyed_derive

WATERMARK_TAG_BITS = 64
CHECK_BITS = 16
PAYLOAD_BITS = WATERMARK_TAG_BITS + CHECK_BITS


def derivation_inputs(
    *,
    recipient_id: str,
    document_id: str,
    document_hash: str,
    session_id: str,
    nonce: str,
    watermark_version: str,
    policy_version: str,
) -> dict[str, Any]:
    """Exactly the fields that feed the tag. This same dictionary is what gets
    signed, so an investigator can prove the watermark belongs to this session
    rather than being added later."""
    return {
        "recipient_id": recipient_id,
        "document_id": document_id,
        "document_hash": document_hash,
        "session_id": session_id,
        "nonce": nonce,
        "watermark_version": watermark_version,
        "policy_version": policy_version,
    }


def derive_tag(root_secret: bytes, inputs: dict[str, Any]) -> str:
    """HMAC-SHA256 over the canonical derivation inputs, truncated to 64 bits.

    Nothing readable about the recipient is embedded. Recovering a tag without
    the root secret yields an opaque number that means nothing, and turning that
    number back into a person requires an authorised registry lookup.
    """
    material = canonical_bytes(inputs)
    digest = hmac.new(root_secret, b"forge:watermark-tag:v1" + material, hashlib.sha256).digest()
    return digest[: WATERMARK_TAG_BITS // 8].hex()


def carrier_seed(root_secret: bytes, *, document_id: str, document_hash: str, version_id: str, page: int) -> int:
    """Carrier pattern is bound to the document identity, never to the session.

    That is what makes extraction blind: an investigator holding only a leaked
    file and the public registry can rebuild the same carriers, and cannot learn
    them from the file itself.
    """
    digest = keyed_derive(
        root_secret,
        "forge:watermark-carrier:v1",
        document_id,
        document_hash,
        version_id,
        f"page{page}",
        length=8,
    )
    return int.from_bytes(digest, "big")


def _crc16(bits: np.ndarray) -> int:
    register = 0xFFFF
    for bit in bits:
        msb = (register >> 15) & 1
        register = ((register << 1) & 0xFFFF) ^ (0x1021 if (msb ^ int(bit)) else 0)
    return register


def encode_payload(tag_hex: str) -> np.ndarray:
    tag_value = int(tag_hex, 16)
    tag_bits = np.array(
        [(tag_value >> (WATERMARK_TAG_BITS - 1 - i)) & 1 for i in range(WATERMARK_TAG_BITS)],
        dtype=np.int8,
    )
    check = _crc16(tag_bits)
    check_bits = np.array([(check >> (CHECK_BITS - 1 - i)) & 1 for i in range(CHECK_BITS)], dtype=np.int8)
    return np.concatenate([tag_bits, check_bits])


def decode_payload(bits: np.ndarray) -> tuple[str, int, bool]:
    """Returns the recovered tag, how many tag bits are set, and whether the
    integrity check survived."""
    hard = (np.asarray(bits) > 0).astype(np.int8)
    tag_bits = hard[:WATERMARK_TAG_BITS]
    check_bits = hard[WATERMARK_TAG_BITS:WATERMARK_TAG_BITS + CHECK_BITS]
    value = 0
    for bit in tag_bits:
        value = (value << 1) | int(bit)
    expected = _crc16(tag_bits)
    observed = 0
    for bit in check_bits:
        observed = (observed << 1) | int(bit)
    return f"{value:0{len(tag_hex_digits())}x}", int(tag_bits.sum()), expected == observed


def tag_hex_digits() -> str:
    return str(WATERMARK_TAG_BITS // 4)


def hamming(a_hex: str, b_hex: str) -> int:
    return bin(int(a_hex, 16) ^ int(b_hex, 16)).count("1")
