from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..core.config import SETTINGS
from ..core.identifiers import next_id
from ..crypto.hashing import b64e, canonical_bytes
from ..crypto.key_management import VAULT
from ..crypto.pqc import CTX_LEDGER_VOTE, PQC
from . import merkle
from .block import Block, Transaction, compute_state_root, sign_block
from .node import LedgerNodeActor
from .verification import compare_nodes, verify_node, verify_transaction_inclusion, vote_payload

GENESIS_HASH_CACHE: dict[str, str] = {}


class LedgerNetwork:
    """Three local logical nodes with deterministic rotation and a quorum
    certificate.

    Consensus is intentionally simple and inspectable: the node whose index
    matches the next height proposes, every reachable node independently
    validates the proposal against its own chain and votes with its own
    post-quantum key, and the block is written only once a quorum of signed
    votes exists. This is closer to a permissioned BFT round than to
    proof-of-work, which is the right trade for a fixed, air-gapped node set.

    When fewer than a quorum of nodes are reachable, transactions are queued
    locally instead of being dropped, and synchronisation later replays them
    through the same validation path.
    """

    def __init__(self, node_ids: tuple[str, ...] = SETTINGS.ledger_nodes, quorum_size: int | None = None):
        self.node_ids = node_ids
        self.quorum_size = quorum_size or SETTINGS.quorum_size
        self.nodes: dict[str, LedgerNodeActor] = {node_id: LedgerNodeActor(node_id) for node_id in node_ids}
        self._ready = False

    def ensure_ready(self) -> None:
        """Issues node identities and writes the genesis anchor.

        Deliberately not called at import time: creating a node requires its
        schema to exist first, and doing storage work as a module side effect
        turns a start-up ordering mistake into an import crash.
        """
        if self._ready:
            return
        existing = {record["owner_id"] for record in VAULT.public_metadata()}
        for node_id in self.node_ids:
            if node_id not in existing:
                VAULT.issue_identity(node_id)
        for node_id in self.node_ids:
            self.nodes[node_id].ensure_genesis(VAULT.signing_secret_for(node_id))
        self._ready = True

    # ---- reachability ------------------------------------------------------

    def online_nodes(self) -> list[LedgerNodeActor]:
        return [node for node in self.nodes.values() if node.online]

    def set_node_online(self, node_id: str, online: bool) -> None:
        self.nodes[node_id].set_online(online)

    def partition(self, offline_node_ids: list[str]) -> dict[str, Any]:
        for node_id in offline_node_ids:
            self.nodes[node_id].set_online(False)
        return self.status()

    def heal(self) -> dict[str, Any]:
        for node in self.nodes.values():
            node.set_online(True)
        return self.status()

    # ---- submission --------------------------------------------------------

    def submit(self, transaction: Transaction) -> dict[str, Any]:
        self.ensure_ready()
        reachable = self.online_nodes()
        if len(reachable) < self.quorum_size:
            for node in reachable:
                node.queue(transaction)
            return {
                "tx_id": transaction.tx_id,
                "status": "QUEUED_OFFLINE",
                "committed": False,
                "reachable_nodes": [n.node_id for n in reachable],
                "quorum_required": self.quorum_size,
                "pending_sync": sum(n.pending_count() for n in self.nodes.values()),
                "plain_explanation": (
                    "Fewer nodes are reachable than the quorum requires, so the signed event is held "
                    "locally and will be committed on synchronisation. Nothing has been discarded."
                ),
            }

        proposer = self._proposer_for(self._next_height())
        queued = proposer.pending()
        batch: list[Transaction] = []
        for candidate in queued + [transaction]:
            # An event the proposer already holds is never re-offered; replaying
            # it would duplicate the transaction rather than commit anything new.
            if proposer.has_event(candidate.event_id):
                continue
            if any(existing.tx_id == candidate.tx_id for existing in batch):
                continue
            batch.append(candidate)
        block, block_hash = self._propose(proposer.node_id, batch)
        votes = self._collect_votes(block, block_hash, reachable)
        if len({v["node_id"] for v in votes}) < self.quorum_size:
            for node in reachable:
                for queued_tx in batch:
                    node.queue(queued_tx)
            return {
                "tx_id": transaction.tx_id,
                "status": "QUORUM_NOT_REACHED",
                "committed": False,
                "votes": len(votes),
                "plain_explanation": "The proposal did not gather enough signed votes; it remains queued.",
            }

        certificate = votes + [self._own_vote(proposer.node_id, block, block_hash)]
        proposer_signature, signature_algorithm = sign_block(
            block, VAULT.signing_secret_for(proposer.node_id)
        )
        for node in reachable:
            node.append_block(block, block_hash, certificate, proposer_signature, signature_algorithm)
            for queued_tx in batch:
                node.mark_queue(queued_tx.tx_id, "COMMITTED")
        return {
            "tx_id": transaction.tx_id,
            "status": "COMMITTED",
            "committed": True,
            "block_id": block.block_id,
            "block_hash": block_hash,
            "height": block.height,
            "merkle_root": block.merkle_root,
            "quorum_votes": sorted({v["node_id"] for v in certificate}),
            "quorum_size": self.quorum_size,
            "committed_on": [n.node_id for n in reachable],
            "pending_on_reachable_nodes": [n.node_id for n in self.nodes.values() if not n.online],
            "plain_explanation": (
                "A quorum of ledger nodes signed this block, so the decryption event is now part of "
                "tamper-evident history."
            ),
        }

    def _next_height(self) -> int:
        return max(node.height() for node in self.nodes.values()) + 1

    def _proposer_for(self, height: int) -> LedgerNodeActor:
        reachable = self.online_nodes()
        pool = reachable or list(self.nodes.values())
        return pool[(height - 1) % len(pool)]

    def _propose(self, proposer_id: str, batch: list[Transaction]) -> tuple[Block, str]:
        proposer = self.nodes[proposer_id]
        head = proposer.head()
        height = (head["height"] if head else -1) + 1
        bodies = [tx.body() for tx in batch]
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        block = Block(
            block_id=next_id("BLK", width=8),
            height=height,
            previous_block_hash=head["block_hash"] if head else "0" * 64,
            merkle_root=merkle.root(bodies),
            timestamp=stamp,
            proposer_id=proposer_id,
            transactions=batch,
            state_root="",
        )
        block_hash = block.block_hash()
        block.state_root = compute_state_root(head["state_root"] if head else merkle.EMPTY_ROOT, block_hash)
        return block, block_hash

    def _own_vote(self, node_id: str, block: Block, block_hash: str) -> dict[str, Any]:
        return self._sign_vote(node_id, block, block_hash)

    def _sign_vote(self, node_id: str, block: Block, block_hash: str) -> dict[str, Any]:
        signature = PQC.sign(
            VAULT.signing_secret_for(node_id),
            vote_payload(
                {
                    "block_id": block.block_id,
                    "height": block.height,
                },
                block_hash,
                node_id,
            ),
            context=CTX_LEDGER_VOTE,
        )
        return {
            "node_id": node_id,
            "vote": "ACCEPT",
            "signature": b64e(signature.raw),
            "algorithm": signature.algorithm,
            "at": block.timestamp,
        }

    def _collect_votes(self, block: Block, block_hash: str, reachable: list[LedgerNodeActor]) -> list[dict[str, Any]]:
        votes: list[dict[str, Any]] = []
        for node in reachable:
            if node.node_id == block.proposer_id:
                continue
            if not self._node_accepts(node, block, block_hash):
                continue
            vote = self._sign_vote(node.node_id, block, block_hash)
            node.record_vote(block.block_id, block.height, block_hash, vote)
            votes.append(vote)
        return votes

    def _node_accepts(self, node: LedgerNodeActor, block: Block, block_hash: str) -> bool:
        """Independent validation. A node refuses a proposal that does not extend
        its own chain, so a Byzantine proposer cannot fork a node silently."""
        head = node.head()
        expected_previous = head["block_hash"] if head else "0" * 64
        if block.previous_block_hash != expected_previous:
            return False
        if block.height != (head["height"] if head else -1) + 1:
            return False
        return merkle.root([tx.body() for tx in block.transactions]) == block.merkle_root

    # ---- synchronisation ---------------------------------------------------

    def sync(self) -> dict[str, Any]:
        """Replays queued transactions through full validation once peers are
        reachable again. A transaction whose event already exists on the target
        node is recorded as already-present rather than duplicated, and any
        genuine conflict is recorded without overwriting either copy."""
        report: list[dict[str, Any]] = []
        for node in self.online_nodes():
            for transaction in node.pending():
                if node.has_event(transaction.event_id):
                    node.mark_queue(transaction.tx_id, "ALREADY_PRESENT")
                    report.append(
                        {
                            "node_id": node.node_id,
                            "tx_id": transaction.tx_id,
                            "result": "ALREADY_PRESENT",
                            "detail": "This node already holds the event; the queued copy was not written again.",
                        }
                    )
                    continue
                outcome = self.submit(transaction)
                if outcome.get("committed"):
                    node.mark_queue(transaction.tx_id, "COMMITTED")
                report.append(
                    {
                        "node_id": node.node_id,
                        "tx_id": transaction.tx_id,
                        "result": outcome["status"],
                        "detail": outcome.get("plain_explanation", ""),
                    }
                )
        remaining = sum(n.pending_count() for n in self.nodes.values())
        return {
            "processed": report,
            "pending_after_sync": remaining,
            "status": "SYNCHRONIZATION VERIFIED" if remaining == 0 else "PENDING SYNCHRONIZATION",
            "conflicts_detected": sum(1 for r in report if r["result"] == "CONFLICT"),
            "plain_explanation": (
                "Every locally queued event has been validated and committed through the normal "
                "quorum path."
                if remaining == 0
                else f"{remaining} event(s) remain queued because a quorum of nodes is still unreachable."
            ),
        }

    # ---- verification ------------------------------------------------------

    def verify(self) -> dict[str, Any]:
        self.ensure_ready()
        # Raw key bytes, not base64: PQC.verify takes the encoded ML-DSA public
        # key directly and silently fails on a base64 string.
        public_keys = {node_id: VAULT.signing_public_key(node_id) for node_id in self.node_ids}
        verdicts = [verify_node(node, public_keys) for node in self.nodes.values()]
        agreement = compare_nodes(verdicts)
        overall = "LEDGER INTEGRITY: VERIFIED"
        if any(v.status == "TAMPER DETECTED" for v in verdicts) or agreement["status"] != "CONSISTENT":
            overall = "LEDGER INTEGRITY: TAMPER DETECTED"
        return {
            "headline": overall,
            "nodes": [v.as_dict() for v in verdicts],
            "agreement": agreement,
            "quorum_size": self.quorum_size,
            "node_count": len(self.node_ids),
            "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def prove_transaction(self, tx_id: str) -> dict[str, Any]:
        self.ensure_ready()
        for node in self.nodes.values():
            proof = verify_transaction_inclusion(node, tx_id)
            if proof.get("verified"):
                return {**proof, "verified_by_node": node.node_id}
        for node in self.nodes.values():
            proof = verify_transaction_inclusion(node, tx_id)
            if proof["status"] != "NOT_FOUND":
                return {**proof, "verified_by_node": node.node_id}
        return {"tx_id": tx_id, "status": "NOT_FOUND", "proof": None, "verified": False}

    def status(self) -> dict[str, Any]:
        self.ensure_ready()
        nodes = []
        for node_id in self.node_ids:
            node = self.nodes[node_id]
            head = node.head() or {}
            nodes.append(
                {
                    "node_id": node_id,
                    "status": "ONLINE" if node.online else "OFFLINE",
                    "block_height": head.get("height", 0),
                    "latest_block_hash": head.get("block_hash", ""),
                    "previous_block_hash": head.get("previous_block_hash", ""),
                    "latest_merkle_root": head.get("merkle_root", ""),
                    "state_root": head.get("state_root", ""),
                    "pending_sync_count": node.pending_count(),
                    "public_key": b64e(VAULT.signing_public_key(node_id))[:32] + "…",
                }
            )
        reachable = len(self.online_nodes())
        pending = sum(n.pending_count() for n in self.nodes.values())
        return {
            "nodes": nodes,
            "node_count": len(self.node_ids),
            "reachable_nodes": reachable,
            "quorum_size": self.quorum_size,
            "quorum_reachable": reachable >= self.quorum_size,
            "consensus": "Deterministic leader rotation with post-quantum quorum certificates",
            "pending_sync_total": pending,
            "offline_mode": not self.nodes[self.node_ids[0]].online or reachable < self.quorum_size,
            "plain_explanation": (
                "Ledger nodes replicate locally. No public blockchain and no proof-of-work is used."
            ),
        }

    def resilience(self) -> dict[str, Any]:
        """One operational view that joins reachability with integrity.

        Every node gets an ONLINE/OFFLINE + HEIGHT line, and the same
        recomputation the full verification does. A node whose head disagrees
        with the quorum is surfaced with its conflicting block and affected
        transactions; it is never overwritten, because its stored copy is the
        evidence.
        """
        self.ensure_ready()
        reachability = self.status()
        integrity = self.verify()
        verdicts = {v["node_id"]: v for v in integrity["nodes"]}
        live = {n["node_id"]: n for n in reachability["nodes"]}

        nodes = []
        online_heads: list[dict[str, Any]] = []
        for node_id in self.node_ids:
            line = live[node_id]
            verdict = verdicts[node_id]
            entry = {
                "node_id": node_id,
                "status": line["status"],
                "block_height": line["block_height"],
                "latest_block_hash": line["latest_block_hash"],
                "previous_block_hash": line["previous_block_hash"],
                "merkle_root": line["latest_merkle_root"],
                "state_root": line["state_root"],
                "integrity_status": verdict["status"],
                "blocks_checked": verdict["blocks_checked"],
                "transactions_checked": verdict["transactions_checked"],
                "first_failing_height": verdict["first_failing_height"],
                "pending_sync_count": line["pending_sync_count"],
            }
            nodes.append(entry)
            if line["status"] == "ONLINE":
                online_heads.append(entry)

        online_heights = sorted({line["block_height"] for line in online_heads})
        integrity_failure = any(line["integrity_status"] == "TAMPER DETECTED" for line in nodes)
        agreement_failure = integrity["agreement"]["status"] != "CONSISTENT"
        # Un-explained height spread between online peers is a consistency
        # failure, not harmless replication lag: genuine lag only shows up on
        # nodes that are out of reach.
        height_mismatch = len(online_heads) > 1 and len(online_heights) > 1

        reasons = []
        if integrity_failure:
            reasons.append("INTEGRITY_TAMPER_DETECTED")
        if agreement_failure:
            reasons.append("CROSS_NODE_AGREEMENT_BROKEN")
        if height_mismatch:
            reasons.append("ONLINE_NODE_HEIGHTS_DIVERGE")
        consistent = not reasons

        majority_root = integrity["agreement"]["state_root"]
        majority_members = set(integrity["agreement"].get("quorum_members", []))
        diverged = set(integrity["agreement"].get("divergent", []))

        # Convenient labels for the conflicting-head report.
        majority_height = integrity["agreement"]["agreed_height"]

        conflicting: list[dict[str, Any]] = []
        affected_transactions: list[dict[str, Any]] = []
        for line in nodes:
            node = self.nodes[line["node_id"]]
            head = node.block_at(line["block_height"])
            disagrees = (
                line["integrity_status"] == "TAMPER DETECTED"
                or (line["status"] == "ONLINE" and line["state_root"] != majority_root)
            )
            if disagrees:
                conflicting.append(
                    {
                        "node_id": line["node_id"],
                        "height": line["block_height"],
                        "block_id": head["block_id"] if head else "",
                        "block_hash": head["block_hash"] if head else "",
                        "previous_block_hash": head["previous_block_hash"] if head else "",
                        "merkle_root": head["merkle_root"] if head else "",
                        "state_root": head["state_root"] if head else "",
                        "transaction_count": head["transaction_count"] if head else 0,
                        "integrity_verdict": line["integrity_status"],
                    }
                )
                affected_transactions.append(
                    {
                        "node_id": line["node_id"],
                        "transaction_count": head["transaction_count"] if head else 0,
                        "pending_sync_count": line["pending_sync_count"],
                    }
                )
            elif line["status"] == "OFFLINE" and line["pending_sync_count"]:
                affected_transactions.append(
                    {
                        "node_id": line["node_id"],
                        "transaction_count": head["transaction_count"] if head else 0,
                        "pending_sync_count": line["pending_sync_count"],
                    }
                )

        expected_head = {}
        for line in nodes:
            # Only a node that itself recomputed clean counts as the expected
            # reference; a tampered node still stores the original state root,
            # so matching on root alone would echo the forged head back.
            if (
                line["status"] == "ONLINE"
                and line["integrity_status"] == "VERIFIED"
                and majority_root
                and line["state_root"] == majority_root
            ):
                head = self.nodes[line["node_id"]].block_at(majority_height)
                if head:
                    expected_head = {
                        "node_id": line["node_id"],
                        "block_id": head["block_id"],
                        "block_hash": head["block_hash"],
                        "merkle_root": head["merkle_root"],
                        "state_root": head["state_root"],
                    }
                break

        replication_lag = [
            {
                "node_id": line["node_id"],
                "status": "OFFLINE",
                "block_height": line["block_height"],
                "stored_head_hash": line["latest_block_hash"],
                "pending_sync_count": line["pending_sync_count"],
            }
            for line in nodes
            if line["status"] == "OFFLINE"
        ]

        affected_nodes = sorted(
            {entry["node_id"] for entry in conflicting}
            | {entry["node_id"] for entry in replication_lag}
        )

        return {
            "ledger_consistency": (
                "LEDGER CONSISTENCY FAILURE" if not consistent else "CONSISTENT"
            ),
            "consistency_reasons": reasons,
            "nodes": nodes,
            "online_nodes": sorted(line["node_id"] for line in online_heads),
            "offline_nodes": [line["node_id"] for line in nodes if line["status"] == "OFFLINE"],
            "replication_lag": replication_lag,
            "conflicting_blocks": conflicting,
            "expected_head": expected_head if diverged else {},
            "affected_nodes": affected_nodes,
            "affected_transactions": affected_transactions,
            "verification_state": {
                "integrity_headline": integrity["headline"],
                "agreement_status": integrity["agreement"]["status"],
                "agreed_height": majority_height,
                "quorum_members": majority_members or None,
                "divergent_nodes": diverged or None,
                "verified_at": integrity["verified_at"],
            },
            "quorum": {
                "required": self.quorum_size,
                "reachable": reachability["reachable_nodes"],
                "reachable_ok": reachability["quorum_reachable"],
            },
            "never_overwritten_note": (
                "No conflicting block is repaired silently: each node keeps its own stored copy so "
                "the divergence and its hashes remain inspectable evidence."
            ),
            "plain_explanation": (
                "All online nodes agree on identical history at the same state root."
                if consistent
                else "At least one node disagrees with the quorum. The conflicting block, its hashes "
                "and the affected nodes are reported; nothing has been overwritten."
            ),
        }

    def transactions(self) -> list[dict[str, Any]]:
        self.ensure_ready()
        for node in self.online_nodes():
            found = node.transactions()
            if found:
                return found
        return self.nodes[self.node_ids[0]].transactions()

    def blocks(self) -> list[dict[str, Any]]:
        self.ensure_ready()
        for node in self.online_nodes():
            found = node.blocks()
            if len(found) > 1:
                return found
        return self.nodes[self.node_ids[0]].blocks()


NETWORK = LedgerNetwork()
