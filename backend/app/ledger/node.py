from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto.hashing import b64e, canonical_bytes
from ..database.session import node_transaction
from ..models.ledger import LedgerBlock, LedgerTransaction, LedgerVote, PendingTransaction
from . import block as block_module
from .block import Block, Transaction


class ChainDivergence(Exception):
    """Raised when a node's history contradicts the quorum-certified chain."""


class LedgerNodeActor:
    """One local ledger node backed by its own SQLite file.

    The node has no method that updates or deletes an existing block or
    transaction. Combined with the storage-level triggers installed at schema
    creation, rewriting history requires going around the application entirely,
    which is precisely what the cross-node state-root comparison is designed to
    notice.
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.online = True

    # ---- storage -----------------------------------------------------------

    def ensure_genesis(self, secret_key: bytes) -> None:
        """Writes the shared anchor block, signed locally by this node.

        The signature is stored for operator inspection but is not part of the
        hashed body, so every node stores a byte-identical genesis block and the
        cross-node state roots line up from height zero.
        """
        with node_transaction(self.node_id) as session:
            if session.get(LedgerBlock, "BLK-GENESIS") is not None:
                return
            anchor = block_module.genesis()
            anchor_hash = anchor.block_hash()
            signature, algorithm = block_module.sign_block(anchor, secret_key)
            session.add(
                LedgerBlock(
                    block_id=anchor.block_id,
                    height=0,
                    previous_block_hash=anchor.previous_block_hash,
                    merkle_root=anchor.merkle_root,
                    block_hash=anchor_hash,
                    timestamp=anchor.timestamp_iso(),
                    proposer_id=anchor.proposer_id,
                    certificate=json.dumps([]),
                    signature_algorithm=algorithm,
                    block_signature=signature,
                    signing_key_id=f"{self.node_id}-LEDGER",
                    transaction_count=0,
                    tx_ids=json.dumps([]),
                    state_root=anchor.state_root,
                    is_genesis=True,
                )
            )

    def head(self) -> dict[str, Any] | None:
        with node_transaction(self.node_id) as session:
            row = session.execute(
                select(LedgerBlock).order_by(LedgerBlock.height.desc()).limit(1)
            ).scalar_one_or_none()
            return _block_row(row) if row else None

    def height(self) -> int:
        head = self.head()
        return head["height"] if head else 0

    def state_root(self) -> str:
        head = self.head()
        return head["state_root"] if head else ""

    def blocks(self) -> list[dict[str, Any]]:
        with node_transaction(self.node_id) as session:
            rows = list(session.execute(select(LedgerBlock).order_by(LedgerBlock.height)).scalars())
            return [_block_row(row) for row in rows]

    def block_at(self, height: int) -> dict[str, Any] | None:
        with node_transaction(self.node_id) as session:
            row = session.execute(
                select(LedgerBlock).where(LedgerBlock.height == height)
            ).scalar_one_or_none()
            return _block_row(row) if row else None

    def transactions(self) -> list[dict[str, Any]]:
        with node_transaction(self.node_id) as session:
            rows = list(
                session.execute(select(LedgerTransaction).order_by(LedgerTransaction.committed_at)).scalars()
            )
            return [_tx_row(row) for row in rows]

    def transaction(self, tx_id: str) -> dict[str, Any] | None:
        with node_transaction(self.node_id) as session:
            row = session.get(LedgerTransaction, tx_id)
            return _tx_row(row) if row else None

    def find_transaction_by_event(self, event_id: str) -> dict[str, Any] | None:
        with node_transaction(self.node_id) as session:
            row = session.execute(
                select(LedgerTransaction).where(LedgerTransaction.event_id == event_id)
            ).scalar_one_or_none()
            return _tx_row(row) if row else None

    def has_event(self, event_id: str) -> bool:
        return self.find_transaction_by_event(event_id) is not None

    # ---- writing -----------------------------------------------------------

    def append_block(
        self,
        block: Block,
        block_hash: str,
        certificate: list[dict[str, Any]],
        proposer_signature: str,
        signature_algorithm: str,
    ) -> None:
        with node_transaction(self.node_id) as session:
            existing = session.get(LedgerBlock, block.block_id)
            if existing is not None:
                raise ChainDivergence(
                    f"{self.node_id} already holds block {block.block_id}; refusing to replace it."
                )
            session.add(
                LedgerBlock(
                    block_id=block.block_id,
                    height=block.height,
                    previous_block_hash=block.previous_block_hash,
                    merkle_root=block.merkle_root,
                    block_hash=block_hash,
                    timestamp=block.timestamp,
                    proposer_id=block.proposer_id,
                    certificate=json.dumps(certificate),
                    signature_algorithm=signature_algorithm,
                    block_signature=proposer_signature,
                    signing_key_id=f"{block.proposer_id}-LEDGER",
                    transaction_count=len(block.transactions),
                    tx_ids=json.dumps([tx.tx_id for tx in block.transactions]),
                    state_root=block.state_root,
                    is_genesis=block.is_genesis,
                )
            )
            for index, transaction in enumerate(block.transactions):
                if session.get(LedgerTransaction, transaction.tx_id) is not None:
                    continue
                session.add(
                    LedgerTransaction(
                        tx_id=transaction.tx_id,
                        event_id=transaction.event_id,
                        event_hash=transaction.event_hash,
                        event_type=transaction.event_type,
                        recipient_id=transaction.recipient_id,
                        document_id=transaction.document_id,
                        version_id=transaction.version_id,
                        document_hash=transaction.document_hash,
                        watermark_tag=transaction.watermark_tag,
                        session_id=transaction.session_id,
                        payload=json.dumps(transaction.payload, sort_keys=True),
                        recipient_signature=transaction.recipient_signature,
                        signature_algorithm=transaction.signature_algorithm,
                        signing_key_id=transaction.signing_key_id,
                        tx_hash=transaction.tx_hash(),
                        committed_block_id=block.block_id,
                        merkle_index=index,
                        submitted_by_node=self.node_id,
                    )
                )
            # Votes are persisted by record_vote at the moment each node signs,
            # not here, so a node's own vote record is written exactly once.

    def record_vote(self, block_id: str, height: int, block_hash: str, entry: dict[str, Any]) -> None:
        if not entry.get("signature"):
            return
        with node_transaction(self.node_id) as session:
            session.merge(
                LedgerVote(
                    vote_id=f"{block_id}:{entry['node_id']}",
                    block_id=block_id,
                    node_id=entry["node_id"],
                    height=height,
                    block_hash=block_hash,
                    signature_algorithm=entry.get("algorithm", ""),
                    signature=entry["signature"],
                    signing_key_id=f"{entry['node_id']}-LEDGER",
                )
            )

    # ---- offline queue -----------------------------------------------------

    def queue(self, transaction: Transaction) -> None:
        """Holds a signed event for later replay.

        Idempotent on purpose: the same event can be offered again after a
        partition heals, and re-queueing it would either duplicate the row or
        mask a genuine duplicate submission.
        """
        with node_transaction(self.node_id) as session:
            queue_id = f"{self.node_id}:{transaction.tx_id}"
            existing = session.get(PendingTransaction, queue_id)
            if existing is not None:
                return
            if session.get(LedgerTransaction, transaction.tx_id) is not None:
                return
            session.add(
                PendingTransaction(
                    queue_id=queue_id,
                    tx_hash=transaction.tx_hash(),
                    event_id=transaction.event_id,
                    payload=json.dumps(transaction.body(), sort_keys=True),
                    state="PENDING",
                )
            )

    def pending(self) -> list[Transaction]:
        with node_transaction(self.node_id) as session:
            rows = list(
                session.execute(
                    select(PendingTransaction).where(PendingTransaction.state == "PENDING")
                ).scalars()
            )
            return [_tx_from_body(json.loads(row.payload)) for row in rows]

    def pending_count(self) -> int:
        with node_transaction(self.node_id) as session:
            return len(
                list(
                    session.execute(
                        select(PendingTransaction).where(PendingTransaction.state == "PENDING")
                    ).scalars()
                )
            )

    def mark_queue(self, tx_id: str, state: str, note: str | None = None) -> None:
        with node_transaction(self.node_id) as session:
            row = session.execute(
                select(PendingTransaction).where(
                    PendingTransaction.queue_id == f"{self.node_id}:{tx_id}"
                )
            ).scalar_one_or_none()
            if row is None:
                return
            row.state = state
            row.conflict_note = note
            if state == "COMMITTED":
                row.flushed_at = datetime.now(timezone.utc)

    def set_online(self, online: bool) -> None:
        self.online = online


def _tx_from_body(body: dict[str, Any]) -> Transaction:
    return Transaction(
        tx_id=body["tx_id"],
        event_id=body["event_id"],
        event_hash=body["event_hash"],
        event_type=body["event_type"],
        recipient_id=body["recipient_id"],
        document_id=body["document_id"],
        version_id=body["version_id"],
        document_hash=body["document_hash"],
        watermark_tag=body["watermark_tag"],
        session_id=body["session_id"],
        payload=body["payload"],
        recipient_signature=body["recipient_signature"],
        signature_algorithm=body["signature_algorithm"],
        signing_key_id=body["signing_key_id"],
    )


def _block_row(row: LedgerBlock) -> dict[str, Any]:
    return {
        "block_id": row.block_id,
        "height": row.height,
        "previous_block_hash": row.previous_block_hash,
        "merkle_root": row.merkle_root,
        "block_hash": row.block_hash,
        "timestamp": row.timestamp,
        "proposer_id": row.proposer_id,
        "certificate": json.loads(row.certificate or "[]"),
        "signature_algorithm": row.signature_algorithm,
        "block_signature": row.block_signature,
        "signing_key_id": row.signing_key_id,
        "transaction_count": row.transaction_count,
        "tx_ids": json.loads(row.tx_ids or "[]"),
        "state_root": row.state_root,
        "is_genesis": row.is_genesis,
        "note": row.note,
    }


def _tx_row(row: LedgerTransaction) -> dict[str, Any]:
    return {
        "tx_id": row.tx_id,
        "event_id": row.event_id,
        "event_hash": row.event_hash,
        "event_type": row.event_type,
        "recipient_id": row.recipient_id,
        "document_id": row.document_id,
        "version_id": row.version_id,
        "document_hash": row.document_hash,
        "watermark_tag": row.watermark_tag,
        "session_id": row.session_id,
        "payload": json.loads(row.payload),
        "recipient_signature": row.recipient_signature,
        "signature_algorithm": row.signature_algorithm,
        "signing_key_id": row.signing_key_id,
        "tx_hash": row.tx_hash,
        "committed_block_id": row.committed_block_id,
        "merkle_index": row.merkle_index,
        "committed_at": row.committed_at.isoformat(timespec="seconds"),
        "submitted_by_node": row.submitted_by_node,
    }


def state_root_of_chain(blocks: list[dict[str, Any]]) -> str:
    root = merkle_empty()
    for entry in blocks:
        root = block_module.compute_state_root(root, entry["block_hash"])
    return root


def merkle_empty() -> str:
    from .merkle import EMPTY_ROOT

    return EMPTY_ROOT


def tx_body_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Reconstructs the canonical transaction body from a stored row.

    The Merkle root and the block hash are computed over exactly this shape.
    Hashing the raw storage row instead would fold in columns such as
    ``committed_at`` and ``merkle_index``, which are node-local bookkeeping and
    differ per node.
    """
    return {
        "tx_id": row["tx_id"],
        "event_id": row["event_id"],
        "event_hash": row["event_hash"],
        "event_type": row["event_type"],
        "recipient_id": row["recipient_id"],
        "document_id": row["document_id"],
        "version_id": row["version_id"],
        "document_hash": row["document_hash"],
        "watermark_tag": row["watermark_tag"],
        "session_id": row["session_id"],
        "payload": row["payload"],
        "recipient_signature": row["recipient_signature"],
        "signature_algorithm": row["signature_algorithm"],
        "signing_key_id": row["signing_key_id"],
    }


def block_body_for_verification(row: dict[str, Any], transactions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "block_id": row["block_id"],
        "height": row["height"],
        "previous_block_hash": row["previous_block_hash"],
        "merkle_root": row["merkle_root"],
        "timestamp": row["timestamp"],
        "proposer_id": row["proposer_id"],
        "is_genesis": row["is_genesis"],
        "transactions": transactions,
    }


def block_signature_payload(row: dict[str, Any], transactions: list[dict[str, Any]]) -> bytes:
    return canonical_bytes(block_body_for_verification(row, transactions))


def signature_blob(signature: bytes) -> str:
    return b64e(signature)
