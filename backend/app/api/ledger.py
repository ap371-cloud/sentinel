from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..models.forensic import LedgerNode
from ..models.identity import Recipient
from ..services import audit_service
from .deps import db, permitted, readable

router = APIRouter(prefix="/ledger", tags=["ledger", "nodes"])


@router.get("/status")
def status(session: Session = Depends(db), _: Recipient = Depends(readable("ledger.read"))) -> dict[str, Any]:
    from ..ledger.chain import NETWORK

    live = NETWORK.status()
    registry = {
        row.node_id: row
        for row in session.query(LedgerNode).all()
    }
    for node in live["nodes"]:
        row = registry.get(node["node_id"])
        if row is not None:
            row.last_block_height = node["block_height"]
            row.last_block_hash = node["latest_block_hash"]
            row.last_merkle_root = node["latest_merkle_root"]
            row.state_root = node["state_root"]
            row.status = node["status"]
            row.pending_sync_count = node["pending_sync_count"]
    return {
        **live,
        "registered_nodes": [
            {
                "node_id": row.node_id,
                "integrity_status": row.integrity_status,
                "integrity_detail": row.integrity_detail,
                "divergent_from_peers": row.divergent_from_peers,
                "last_sync_result": row.last_sync_result,
            }
            for row in registry.values()
        ],
        "design_note": (
            "A local permissioned ledger. No public blockchain, no proof-of-work and no external "
            "network dependency. Each node keeps its own database file, which is what makes "
            "single-node tampering detectable."
        ),
    }


@router.get("/verify")
def verify(_: Recipient = Depends(readable("ledger.verify"))) -> dict[str, Any]:
    """Recomputes every block hash, chain link, Merkle root, node signature and
    running state root, then compares nodes against each other."""
    from ..ledger.chain import NETWORK

    return NETWORK.verify()


@router.get("/blocks")
def blocks(_: Recipient = Depends(readable("ledger.read"))) -> dict[str, Any]:
    from ..ledger.chain import NETWORK

    return {"blocks": NETWORK.blocks()}


@router.get("/transactions")
def transactions(_: Recipient = Depends(readable("ledger.read"))) -> dict[str, Any]:
    from ..ledger.chain import NETWORK

    return {"transactions": NETWORK.transactions()}


@router.get("/transactions/{tx_id}")
def transaction(tx_id: str, _: Recipient = Depends(readable("ledger.read"))) -> dict[str, Any]:
    from ..ledger.chain import NETWORK

    proof = NETWORK.prove_transaction(tx_id)
    return {"transaction_id": tx_id, "inclusion_proof": proof}


@router.post("/sync")
def sync(
    payload: "SyncRequest",
    session: Session = Depends(db),
    operator: Recipient = Depends(readable("ledger.verify")),
) -> dict[str, Any]:
    """Replays locally queued events through full validation. Conflicts are
    recorded, never resolved by overwriting either copy."""
    from ..ledger.chain import NETWORK
    from ..security import incident_engine

    if payload.offline_node_ids:
        NETWORK.partition(payload.offline_node_ids)
    report = NETWORK.sync()
    audit_service.record(
        session,
        actor_id=operator.recipient_id,
        action="LEDGER_OPERATION",
        target_type="LEDGER_NETWORK",
        target_id=None,
        detail={"operation": "SYNC", "status": report["status"], "processed": len(report["processed"])},
    )
    if report["conflicts_detected"]:
        incident_engine.raise_event(
            session,
            "LEDGER_DIVERGENCE",
            what_happened=f"{report['conflicts_detected']} conflicting ledger record(s) found during synchronisation.",
            why_it_matters="Nodes disagree on history, so at least one copy was altered outside the protocol.",
            recommended_action="Quarantine the affected node and compare signed block certificates.",
        )
    return report


class SyncRequest(BaseModel):
    offline_node_ids: list[str] = Field(default_factory=list)


class NodeAdminRequest(BaseModel):
    node_id: str
    operation: str = Field(pattern="^(ONLINE|OFFLINE)$")
    reason: str = Field(min_length=5, max_length=400)
    approval_id: str | None = None


@router.post("/nodes/admin")
def node_admin(
    payload: NodeAdminRequest,
    session: Session = Depends(db),
    operator: Recipient = Depends(permitted("ledger.admin")),
) -> dict[str, Any]:
    """Ledger node administration is a two-person controlled action.

    An administrator cannot both make the change and approve it, which is why
    the approval record has to be presented by a second identity.
    """
    from ..ledger.chain import NETWORK
    from ..services import approval_service
    from ..security import incident_engine

    approval = approval_service.consume(
        session,
        approval_id=payload.approval_id or "",
        acting_role=operator.role,
        expected_action="LEDGER_NODE_ADMINISTRATION",
    )
    result = NETWORK.partition([payload.node_id]) if payload.operation == "OFFLINE" else NETWORK.heal()
    row = session.get(LedgerNode, payload.node_id)
    if row is not None:
        row.status = payload.operation
    audit_service.record(
        session,
        actor_id=operator.recipient_id,
        action="LEDGER_NODE_ADMIN",
        target_type="LEDGER_NODE",
        target_id=payload.node_id,
        detail={"operation": payload.operation, "reason": payload.reason, "approval_id": approval.approval_id},
    )
    incident_engine.raise_event(
        session,
        "NODE_FAILURE" if payload.operation == "OFFLINE" else "LEDGER_OPERATION",
        title=f"Ledger node {payload.node_id} set {payload.operation}",
        what_happened=f"{operator.recipient_id} set {payload.node_id} to {payload.operation}. Reason: {payload.reason}",
        why_it_matters="Node reachability changes what the ledger can commit without queuing.",
        what_was_affected=payload.node_id,
        recommended_action="Restore the node and run synchronisation when the fault is cleared.",
        severity="MEDIUM",
        subject_id=payload.node_id,
    )
    return {"node_id": payload.node_id, "status": payload.operation, "ledger": result}
