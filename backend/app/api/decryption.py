from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import PATHS, DeviceTrust
from ..core.exceptions import NotFound
from ..core.rights import require_right
from ..core.timeutil import utcnow
from ..database import shared as shared_store
from ..models.documents import Document
from ..models.identity import Device, Recipient
from ..security import incident_engine, revocation
from ..services import audit_service, decryption_service, identity_service
from .deps import db, permitted, readable

router = APIRouter(tags=["decryption", "sessions", "recipients", "devices"])


class NonceRequest(BaseModel):
    document_id: str


class DecryptRequest(BaseModel):
    document_id: str
    device_id: str = Field(min_length=3, max_length=48)
    nonce: str = Field(min_length=8, max_length=128)
    request_id: str | None = Field(default=None, max_length=64)
    offline: bool = False
    break_glass_approval_id: str | None = None
    export_as: str | None = Field(default=None, max_length=120)


@router.post("/decrypt/authorize")
def authorize(
    payload: NonceRequest,
    session: Session = Depends(db),
    recipient: Recipient = Depends(permitted("document.decrypt")),
) -> dict[str, Any]:
    """Issues a single-use authorisation nonce.

    Step one of the decryption flow. The nonce is bound to this identity and this
    document, and can be presented exactly once.
    """
    return decryption_service.issue_nonce(
        session, recipient_id=recipient.recipient_id, document_id=payload.document_id
    )


@router.post("/decrypt")
def decrypt(
    payload: DecryptRequest,
    session: Session = Depends(db),
    recipient: Recipient = Depends(permitted("document.decrypt")),
) -> dict[str, Any]:
    """The full authorised decryption.

    Every authorisation input is re-read from live state before any plaintext
    exists: account status, need-to-know grant, clearance, unit scope, document
    policy and lifecycle, device registration and trust, key status, replay
    freshness and emergency lockdown state.
    """
    return decryption_service.decrypt(
        session,
        actor=recipient,
        document_id=payload.document_id,
        device_id=payload.device_id,
        nonce=payload.nonce,
        request_id=payload.request_id,
        offline=payload.offline,
        break_glass_approval_id=payload.break_glass_approval_id,
        export_as=payload.export_as,
    )


@router.get("/sessions")
def sessions(
    session: Session = Depends(db),
    recipient: Recipient = Depends(readable("document.decrypt")),
    recipient_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    return {
        "sessions": decryption_service.list_sessions(
            session, recipient_id=recipient_id or recipient.recipient_id, limit=min(limit, 500)
        )
    }


@router.get("/sessions/{session_id}")
def session_detail(
    session_id: str, session: Session = Depends(db), _: Recipient = Depends(readable("document.decrypt"))
) -> dict[str, Any]:
    """Shows the whole forensic relationship for one session: authorisation
    trace, watermark, signature and ledger state."""
    return {"session": decryption_service.describe_session(session, session_id)}


@router.get("/sessions/{session_id}/document")
def session_document(
    session_id: str, session: Session = Depends(db), _: Recipient = Depends(readable("document.decrypt"))
) -> Any:
    """Streams the recipient's own watermarked copy.

    The path is derived from the session, not from client input, so this cannot
    be used to reach another recipient's artefact.
    """
    record = decryption_service.describe_session(session, session_id)
    document = session.get(Document, record["document_id"])
    if document is None:
        raise NotFound(f"No document {record['document_id']} behind this session.")
    require_right(document, "DOWNLOAD", operation="Downloading this session's copy")
    stored = _locate_artefact(session_id)
    if stored is None:
        raise NotFound(f"No stored artefact for session {session_id}.")
    return FileResponse(
        stored,
        media_type="application/pdf",
        filename=f"{session_id}.pdf",
        headers={
            "X-Sentinel-Watermark-Id": record.get("watermark_id") or "",
            "X-Sentinel-Attribution": record.get("watermark_tag") or "",
        },
    )


def _locate_artefact(session_id: str) -> Path | None:
    pattern = f"*/{session_id}/*.pdf"
    matches = sorted((PATHS.evidence / "recipient_copies").glob(pattern))
    if matches:
        return matches[0]
    # The copy may live only on the instance that produced it; pull it down
    # from the shared store before giving up.
    for candidate in shared_store.artefact_glob(str(PATHS.evidence / "recipient_copies" / pattern)):
        materialized = shared_store.artefact_materialize(Path(candidate))
        if materialized.exists():
            return materialized
    return None


@router.get("/sessions/{session_id}/evidence-chain")
def session_chain(
    session_id: str, session: Session = Depends(db), _: Recipient = Depends(readable("document.decrypt"))
) -> dict[str, Any]:
    from ..ledger.chain import NETWORK

    record = decryption_service.describe_session(session, session_id)
    tx_id = record.get("ledger_tx_id")
    proof = NETWORK.prove_transaction(tx_id) if tx_id else {"status": "NO TRANSACTION"}
    return {
        "session": record,
        "event_chain": decryption_service.verify_event_chain(session),
        "ledger_proof": proof,
    }


# ---- recipients and devices ------------------------------------------------


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=400)


@router.post("/recipients/{recipient_id}/revoke")
def revoke_recipient(
    recipient_id: str,
    payload: RevokeRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("recipient.revoke")),
) -> dict[str, Any]:
    """Immediate revocation. New decryptions and sessions fail from this moment;
    every record of earlier activity is preserved."""
    return revocation.revoke_recipient(
        session, recipient_id=recipient_id, actor_id=officer.recipient_id, reason=payload.reason
    )


@router.post("/recipients/{recipient_id}/suspend")
def suspend_recipient(
    recipient_id: str,
    payload: RevokeRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("recipient.revoke")),
) -> dict[str, Any]:
    return revocation.suspend_recipient(
        session, recipient_id=recipient_id, actor_id=officer.recipient_id, reason=payload.reason
    )


@router.post("/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    payload: RevokeRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("device.manage")),
) -> dict[str, Any]:
    return revocation.revoke_device(
        session, device_id=device_id, actor_id=officer.recipient_id, reason=payload.reason
    )


class KeyRevokeRequest(BaseModel):
    purpose: str = Field(pattern="^(SIGNING|KEM)$")
    reason: str = Field(min_length=5, max_length=400)
    cascade: bool = True


@router.post("/recipients/{recipient_id}/keys/revoke")
def revoke_key(
    recipient_id: str,
    payload: KeyRevokeRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("key.manage")),
) -> dict[str, Any]:
    """Key compromise workflow.

    Withdrawing a key also revokes the recipient's devices and blocks new
    sessions, while every event the key already signed remains valid evidence.
    """
    result = revocation.revoke_key(
        session,
        owner_id=recipient_id,
        purpose=payload.purpose,
        actor_id=officer.recipient_id,
        reason=payload.reason,
    )
    if payload.cascade:
        for device in session.execute(
            select(Device).where(Device.recipient_id == recipient_id)
        ).scalars():
            device.status = "REVOKED"
            device.revoked_at = utcnow()
        result["cascaded"] = "all registered devices for this identity revoked; new sessions blocked"
    return result


@router.get("/recipients")
def list_recipients(session: Session = Depends(db), _: Recipient = Depends(readable("recipient.create"))) -> dict[str, Any]:
    return {
        "identities": identity_service.list_all(session),
        "counts": identity_service.active_counts(session),
    }


@router.get("/devices")
def list_devices(session: Session = Depends(db), _: Recipient = Depends(readable("device.manage"))) -> dict[str, Any]:
    rows = session.execute(select(Device).order_by(Device.device_id)).scalars()
    return {
        "devices": [
            {
                "device_id": row.device_id,
                "recipient_id": row.recipient_id,
                "device_name": row.device_name,
                "status": row.status,
                "trust_state": row.trust_state,
                "trust_assessed_at": row.trust_assessed_at.isoformat(timespec="seconds")
                if row.trust_assessed_at
                else None,
                "trust_note": row.trust_note,
                "registered_at": row.registered_at.isoformat(timespec="seconds"),
                "last_seen_at": row.last_seen_at.isoformat(timespec="seconds") if row.last_seen_at else None,
                "attestation_note": row.attestation_note,
            }
            for row in rows
        ],
        "trust_states": ["TRUSTED", "SUSPICIOUS", "COMPROMISED", "REVOKED", "PENDING"],
        "limitation": (
            "A client-supplied fingerprint is not hardware attestation. Production requires "
            "TPM-backed device identity, which this prototype does not implement."
        ),
    }


class TrustRequest(BaseModel):
    trust_state: str = Field(pattern="^(TRUSTED|SUSPICIOUS|COMPROMISED|REVOKED)$")
    note: str = Field(min_length=5, max_length=400)


@router.post("/devices/{device_id}/trust")
def set_trust(
    device_id: str,
    payload: TrustRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("device.manage")),
) -> dict[str, Any]:
    device = session.get(Device, device_id)
    if device is None:
        raise NotFound(f"No device {device_id}.")
    device.trust_state = payload.trust_state
    device.trust_assessed_at = utcnow()
    device.trust_note = payload.note
    if payload.trust_state == DeviceTrust.REVOKED:
        device.status = "REVOKED"
        device.revoked_at = utcnow()
    audit_service.record(
        session,
        actor_id=officer.recipient_id,
        action="DEVICE_REVOKED" if payload.trust_state == "REVOKED" else "DEVICE_TRUST_CHANGED",
        target_type="DEVICE",
        target_id=device_id,
        detail={"trust_state": payload.trust_state, "note": payload.note},
    )
    incident_engine.raise_event(
        session,
        "DEVICE_IDENTITY_CHANGE" if payload.trust_state != "REVOKED" else "DEVICE_REVOKED",
        what_happened=f"Device {device_id} trust state set to {payload.trust_state} by {officer.recipient_id}.",
        what_was_affected=device_id,
        subject_id=device.recipient_id,
    )
    return {"device_id": device_id, "trust_state": payload.trust_state, "note": payload.note}
