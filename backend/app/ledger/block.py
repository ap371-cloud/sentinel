from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..core.identifiers import next_id
from ..crypto.hashing import b64d, b64e, canonical_bytes, sha256_hex
from ..crypto.pqc import CTX_LEDGER_BLOCK, PQC
from . import merkle


@dataclass
class Transaction:
    """A signed decryption event offered to the ledger. The payload carries the
    recipient's own ML-DSA signature, so the ledger records an assertion that a
    specific recipient authorised a specific decryption."""

    tx_id: str
    event_id: str
    event_hash: str
    event_type: str
    recipient_id: str
    document_id: str
    version_id: str
    document_hash: str
    watermark_tag: str
    session_id: str
    payload: dict[str, Any]
    recipient_signature: str
    signature_algorithm: str
    signing_key_id: str

    def body(self) -> dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "event_id": self.event_id,
            "event_hash": self.event_hash,
            "event_type": self.event_type,
            "recipient_id": self.recipient_id,
            "document_id": self.document_id,
            "version_id": self.version_id,
            "document_hash": self.document_hash,
            "watermark_tag": self.watermark_tag,
            "session_id": self.session_id,
            "payload": self.payload,
            "recipient_signature": self.recipient_signature,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
        }

    def tx_hash(self) -> str:
        return sha256_hex(canonical_bytes(self.body()))

    def canonical_signing_input(self) -> bytes:
        """Exactly the bytes the recipient signed, reconstructed rather than
        trusted from storage."""
        return canonical_bytes(
            {
                "event_id": self.event_id,
                "event_hash": self.event_hash,
                "document_id": self.document_id,
                "version_id": self.version_id,
                "document_hash": self.document_hash,
                "session_id": self.session_id,
                "watermark_tag": self.watermark_tag,
            }
        )

    @staticmethod
    def from_event(event_row) -> "Transaction":
        return Transaction(
            tx_id=next_id("TX", width=8),
            event_id=event_row.event_id,
            event_hash=event_row.event_hash,
            event_type=event_row.event_type,
            recipient_id=event_row.recipient_id,
            document_id=event_row.document_id,
            version_id=event_row.version_id,
            document_hash=event_row.document_hash,
            watermark_tag=event_row.watermark_tag,
            session_id=event_row.session_id,
            payload=json.loads(event_row.payload),
            recipient_signature=event_row.signature,
            signature_algorithm=event_row.signature_algorithm,
            signing_key_id=event_row.signing_key_id,
        )


@dataclass
class Block:
    block_id: str
    height: int
    previous_block_hash: str
    merkle_root: str
    timestamp: str
    proposer_id: str
    transactions: list[Transaction]
    state_root: str
    is_genesis: bool = False
    certificate: list[dict[str, Any]] = field(default_factory=list)

    def body(self) -> dict[str, Any]:
        """Content covered by the block hash.

        ``state_root`` is deliberately excluded: it is a running commitment
        derived *from* this block's hash, so including it would make the hash
        self-referential and the stored value could never be recomputed.
        """
        return {
            "block_id": self.block_id,
            "height": self.height,
            "previous_block_hash": self.previous_block_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "proposer_id": self.proposer_id,
            "is_genesis": self.is_genesis,
            "transactions": [tx.body() for tx in self.transactions],
        }

    def block_hash(self) -> str:
        return sha256_hex(canonical_bytes(self.body()))

    def proof_for(self, tx_id: str) -> merkle.MerkleProof | None:
        bodies = [tx.body() for tx in self.transactions]
        for index, transaction in enumerate(bodies):
            if transaction["tx_id"] == tx_id:
                return merkle.proofs(bodies)[index]
        return None

    def timestamp_iso(self) -> str:
        return self.timestamp


#: The anchor block is identical on every node. If each node minted its own
#: genesis the state roots could never agree, and cross-node agreement would be
#: meaningless. Fixed proposer and fixed timestamp make the anchor
#: deterministic; each node's own key signs it locally without the signature
#: entering the hashed body.
GENESIS_TIMESTAMP = "2026-01-01T00:00:00+00:00"
GENESIS_PROPOSER = "SENTINEL-CONSORTIUM"


def genesis() -> Block:
    block = Block(
        block_id="BLK-GENESIS",
        height=0,
        previous_block_hash="0" * 64,
        merkle_root=merkle.EMPTY_ROOT,
        timestamp=GENESIS_TIMESTAMP,
        proposer_id=GENESIS_PROPOSER,
        transactions=[],
        state_root="",
        is_genesis=True,
    )
    block.state_root = compute_state_root(merkle.EMPTY_ROOT, block.block_hash())
    return block


def compute_state_root(previous_state_root: str, block_hash: str) -> str:
    """A running commitment to chain history. Two nodes at the same height with
    different state roots are provably not looking at the same ledger, which is
    how single-node tampering is caught without knowing what was changed."""
    return sha256_hex(canonical_bytes({"previous": previous_state_root, "block": block_hash}))


def sign_block(block: Block, secret_key: bytes) -> tuple[str, str]:
    signature = PQC.sign(secret_key, canonical_bytes(block.body()), context=CTX_LEDGER_BLOCK)
    return b64e(signature.raw), signature.algorithm


def verify_block_signature(block: Block, block_hash: str, public_key: str, signature_b64: str) -> bool:
    return PQC.verify(
        public_key,
        canonical_bytes(block.body()),
        b64d(signature_b64),
        context=CTX_LEDGER_BLOCK,
    )
