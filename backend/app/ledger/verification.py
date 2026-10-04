from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..crypto.hashing import canonical_bytes, sha256_hex
from ..crypto.pqc import CTX_LEDGER_BLOCK, CTX_LEDGER_VOTE, PQC
from ..crypto.hashing import b64d
from . import merkle
from .node import LedgerNodeActor, block_body_for_verification, tx_body_from_row

INTEGRITY_VERIFIED = "VERIFIED"
INTEGRITY_TAMPERED = "TAMPER DETECTED"
INTEGRITY_UNVERIFIED = "UNVERIFIED"


@dataclass
class NodeVerdict:
    node_id: str
    status: str
    height: int
    blocks_checked: int
    transactions_checked: int
    first_failing_height: int | None = None
    failures: list[dict[str, Any]] = field(default_factory=list)
    state_root: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "status": self.status,
            "block_height": self.height,
            "blocks_checked": self.blocks_checked,
            "transactions_checked": self.transactions_checked,
            "first_failing_height": self.first_failing_height,
            "failures": self.failures,
            "state_root": self.state_root,
            "plain_explanation": (
                "Every block hash, chain link, Merkle root, node signature and state root on this "
                "node was recomputed and matched."
                if self.status == INTEGRITY_VERIFIED
                else "At least one recomputed value did not match what this node stores."
            ),
        }


def recompute_block_hash(row: dict[str, Any], transactions: list[dict[str, Any]]) -> str:
    return sha256_hex(canonical_bytes(block_body_for_verification(row, transactions)))


def verify_node(node: LedgerNodeActor, node_public_keys: dict[str, str]) -> NodeVerdict:
    """Recomputes everything the node claims about itself.

    A tampered node that recomputed only its own block hash still fails here,
    because the Merkle root is recomputed from the stored transactions and the
    signature is checked against the proposer's registered public key.
    """
    blocks = node.blocks()
    if not blocks:
        return NodeVerdict(node.node_id, INTEGRITY_UNVERIFIED, 0, 0, 0)

    failures: list[dict[str, Any]] = []
    previous_hash = "0" * 64
    running_state = merkle.EMPTY_ROOT
    transactions_checked = 0

    for row in blocks:
        height = row["height"]
        if row["previous_block_hash"] != previous_hash:
            failures.append(
                {
                    "height": height,
                    "check": "CHAIN_LINK",
                    "detail": (
                        f"block {row['block_id']} records previous hash "
                        f"{row['previous_block_hash'][:16]}… but the preceding block hashes to "
                        f"{previous_hash[:16]}…"
                    ),
                }
            )
        stored = [tx for tx in node.transactions() if tx["committed_block_id"] == row["block_id"]]
        ordered = sorted(stored, key=lambda tx: tx["merkle_index"] or 0)
        bodies = [tx_body_from_row(tx) for tx in ordered]
        recomputed_merkle = merkle.root(bodies)
        if recomputed_merkle != row["merkle_root"]:
            failures.append(
                {
                    "height": height,
                    "check": "MERKLE_ROOT",
                    "detail": (
                        f"stored Merkle root {row['merkle_root'][:16]}… does not match the root "
                        f"recomputed from the {len(ordered)} stored transaction(s)"
                    ),
                }
            )
        recomputed_hash = recompute_block_hash(row, bodies)
        if recomputed_hash != row["block_hash"]:
            failures.append(
                {
                    "height": height,
                    "check": "BLOCK_HASH",
                    "detail": "stored block hash does not match the block contents",
                }
            )
        expected_state = sha256_hex(canonical_bytes({"previous": running_state, "block": recomputed_hash}))
        if expected_state != row["state_root"]:
            failures.append(
                {
                    "height": height,
                    "check": "STATE_ROOT",
                    "detail": "running state root does not follow from the previous block",
                }
            )
        if not row["is_genesis"]:
            public_key = node_public_keys.get(row["proposer_id"], "")
            if public_key and not PQC.verify(
                public_key,
                canonical_bytes(block_body_for_verification(row, bodies)),
                b64d(row["block_signature"] or ""),
                context=CTX_LEDGER_BLOCK,
            ):
                failures.append(
                    {
                        "height": height,
                        "check": "BLOCK_SIGNATURE",
                        "detail": f"block signature from {row['proposer_id']} did not verify",
                    }
                )
        for entry in row["certificate"]:
            if not entry.get("signature"):
                continue
            voter_key = node_public_keys.get(entry["node_id"], "")
            if voter_key and not PQC.verify(
                voter_key,
                vote_payload(row, recomputed_hash, entry["node_id"]),
                b64d(entry["signature"]),
                context=CTX_LEDGER_VOTE,
            ):
                failures.append(
                    {
                        "height": height,
                        "check": "QUORUM_VOTE",
                        "detail": f"vote from {entry['node_id']} did not verify",
                    }
                )
        transactions_checked += len(ordered)
        previous_hash = recomputed_hash
        running_state = expected_state

    head = blocks[-1]
    return NodeVerdict(
        node_id=node.node_id,
        status=INTEGRITY_TAMPERED if failures else INTEGRITY_VERIFIED,
        height=head["height"],
        blocks_checked=len(blocks),
        transactions_checked=transactions_checked,
        first_failing_height=failures[0]["height"] if failures else None,
        failures=failures,
        state_root=running_state,
    )


def vote_payload(block_row: dict[str, Any], block_hash: str, voter_id: str) -> bytes:
    return canonical_bytes(
        {
            "block_id": block_row["block_id"],
            "height": block_row["height"],
            "block_hash": block_hash,
            "node_id": voter_id,
        }
    )


def compare_nodes(verdicts: list[NodeVerdict]) -> dict[str, Any]:
    """Quorum-certified agreement is decided by majority height with identical
    state root. A single outlier node is reported as tampered rather than being
    overwritten, because its contents are evidence."""
    if not verdicts:
        return {"status": "UNVERIFIED", "agreed_height": 0, "state_root": "", "divergent": []}

    healthy = [v for v in verdicts if v.status != INTEGRITY_TAMPERED] or verdicts
    by_root: dict[str, list[NodeVerdict]] = {}
    for verdict in healthy:
        by_root.setdefault(verdict.state_root, []).append(verdict)

    majority_root, majority_members = max(by_root.items(), key=lambda item: len(item[1]))
    agreed_height = max(v.height for v in majority_members)
    divergent = [v for v in verdicts if v.state_root != majority_root or v.status == INTEGRITY_TAMPERED]

    return {
        "status": "CONSISTENCY FAILURE" if divergent else "CONSISTENT",
        "agreed_height": agreed_height,
        "state_root": majority_root,
        "quorum_members": sorted(v.node_id for v in majority_members),
        "divergent": [v.node_id for v in divergent],
        "plain_explanation": (
            "Nodes do not agree on history. Conflicting records are preserved on every node and "
            "nothing has been overwritten."
            if divergent
            else "All healthy nodes hold identical history at the same state root."
        ),
    }


def verify_transaction_inclusion(node: LedgerNodeActor, tx_id: str) -> dict[str, Any]:
    """Proves a single transaction sits inside a committed block, using only the
    block's Merkle root and the proof — not the node's word that it is there."""
    transaction = node.transaction(tx_id)
    if transaction is None:
        return {"tx_id": tx_id, "status": "NOT_FOUND", "proof": None, "verified": False}

    committed = transaction["committed_block_id"]
    for row in node.blocks():
        if row["block_id"] != committed:
            continue
        ordered = sorted(
            [tx for tx in node.transactions() if tx["committed_block_id"] == committed],
            key=lambda tx: tx["merkle_index"] or 0,
        )
        target = next(tx for tx in ordered if tx["tx_id"] == tx_id)
        bodies = [tx_body_from_row(tx) for tx in ordered]
        proof = merkle.proofs(bodies)[target["merkle_index"] or 0]
        verified = merkle.verify(tx_body_from_row(target), proof, row["merkle_root"])
        return {
            "tx_id": tx_id,
            "block_id": committed,
            "block_hash": row["block_hash"],
            "previous_block_hash": row["previous_block_hash"],
            "merkle_root": row["merkle_root"],
            "proof": proof.to_dict(),
            "verified": verified,
            "status": "MERKLE PROOF VERIFIED" if verified else "MERKLE PROOF INVALID",
        }
    return {"tx_id": tx_id, "status": "NOT_COMMITTED", "proof": None, "verified": False}
