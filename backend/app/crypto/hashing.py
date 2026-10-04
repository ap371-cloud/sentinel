from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

CHUNK = 1 << 20


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canonical_json(payload: Any) -> str:
    """Signing and hashing both depend on one byte-exact serialization, so every
    producer in the system routes through this function."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(payload: Any) -> bytes:
    return canonical_json(payload).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(CHUNK):
            digest.update(block)
    return digest.hexdigest()


def file_digest_bundle(path: Path) -> dict[str, Any]:
    """Hashes the content and records the size, because a forensic report needs
    both and an attacker can preserve one while changing the other."""
    sha256 = sha256_file(path)
    size = path.stat().st_size
    return {"sha256": sha256, "size_bytes": size, "hash_algorithm": "SHA-256"}


def hmac_hex(key: bytes, data: bytes, length: int = 32) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()[: length * 2]


def keyed_derive(key: bytes, *parts: str, length: int = 32) -> bytes:
    message = b"\x1f".join(part.encode("utf-8") for part in parts)
    return hmac.new(key, message, hashlib.sha256).digest()[:length]


def equal_digest(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def merkle_leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()
