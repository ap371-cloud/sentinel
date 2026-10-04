from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..crypto.hashing import canonical_bytes, merkle_leaf_hash, merkle_node_hash

EMPTY_ROOT = merkle_node_hash(b"", b"").hex()


@dataclass(frozen=True)
class MerkleProof:
    """RFC 6962 style inclusion proof: sibling hashes bottom-up plus the leaf
    index, so one transaction can be verified without trusting the node that
    stored it."""

    index: int
    total: int
    siblings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "total": self.total, "siblings": list(self.siblings)}

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "MerkleProof":
        return MerkleProof(
            index=int(raw["index"]),
            total=int(raw["total"]),
            siblings=tuple(raw["siblings"]),
        )


def leaf_hash(transaction: dict[str, Any]) -> bytes:
    return merkle_leaf_hash(canonical_bytes(transaction))


def _fold(items: list[bytes]) -> list[bytes]:
    padded = items + [items[-1]] if len(items) % 2 == 1 else items
    return [merkle_node_hash(padded[i], padded[i + 1]) for i in range(0, len(padded), 2)]


def root(transactions: list[dict[str, Any]]) -> str:
    if not transactions:
        return EMPTY_ROOT
    level = [leaf_hash(tx) for tx in transactions]
    while len(level) > 1:
        level = _fold(level)
    return level[0].hex()


def proofs(transactions: list[dict[str, Any]]) -> list[MerkleProof]:
    """One inclusion proof per leaf.

    Odd levels are padded by duplicating their last node, which is why proof
    construction must look siblings up in the *padded* level: for five leaves,
    the sixth slot of level zero exists only inside the fold.
    """
    if not transactions:
        return []
    total = len(transactions)
    levels: list[list[bytes]] = [[leaf_hash(tx) for tx in transactions]]
    while len(levels[-1]) > 1:
        levels.append(_fold(levels[-1]))

    padded_levels = [_pad(level) for level in levels[:-1]]

    out: list[MerkleProof] = []
    for leaf_index in range(total):
        siblings: list[bytes] = []
        position = leaf_index
        for depth in range(len(padded_levels)):
            level = padded_levels[depth]
            # Even index is a left child, so its partner sits to the right.
            sibling = level[position + 1] if position % 2 == 0 else level[position - 1]
            siblings.append(sibling)
            position //= 2
        out.append(
            MerkleProof(index=leaf_index, total=total, siblings=tuple(s.hex() for s in siblings))
        )
    return out


def _pad(level: list[bytes]) -> list[bytes]:
    return level + [level[-1]] if len(level) % 2 == 1 else list(level)


def verify(transaction: dict[str, Any], proof: MerkleProof, expected_root: str) -> bool:
    """Recomputes the root from the leaf and the proof. A wrong index, a missing
    sibling or an altered transaction all produce a different root."""
    computed = leaf_hash(transaction)
    position = proof.index
    for sibling_hex in proof.siblings:
        sibling = bytes.fromhex(sibling_hex)
        computed = (
            merkle_node_hash(computed, sibling) if position % 2 == 0
            else merkle_node_hash(sibling, computed)
        )
        position //= 2
    return computed.hex() == expected_root
