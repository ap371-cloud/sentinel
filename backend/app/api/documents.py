from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.config import PATHS, CLEARIFICATIONS, DocumentLifecycle
from ..core.exceptions import ForgeError, NotFound
from ..core.rights import require_right
from ..models.documents import Document
from ..models.identity import Recipient
from ..security.revocation import revoke_document_access
from ..services import approval_service, document_service, sharing_service
from .deps import db, permitted, readable

router = APIRouter(prefix="/documents", tags=["documents"])


class PolicyPayload(BaseModel):
    download_allowed: bool | None = None
    print_allowed: bool | None = None
    export_allowed: bool | None = None
    offline_allowed: bool | None = None
    watermark_required: bool | None = None
    second_approval_required: bool | None = None
    maximum_sessions: int | None = Field(default=None, ge=0, le=10_000)
    access_expiry_days: int | None = Field(default=None, ge=1, le=3650)


@router.post("")
def upload(
    title: str = Form(..., min_length=2, max_length=200),
    classification: str = Form(...),
    unit: str = Form(..., min_length=2, max_length=40),
    mission_reference: str | None = Form(default=None, max_length=64),
    permitted_units: str = Form(default=""),
    permitted_roles: str = Form(default="RECIPIENT,COMMANDER,SECURITY_OFFICER"),
    recipients: str = Form(default=""),
    policy: str = Form(default="{}"),
    file: UploadFile = File(...),
    session: Session = Depends(db),
    sender: Recipient = Depends(permitted("document.upload")),
) -> dict[str, Any]:
    """Upload → normalise → hash → classify → encrypt.

    The plaintext is encrypted before the request returns and the response
    contains no document content and no key material.
    """
    import json

    try:
        policy_body = json.loads(policy or "{}")
    except json.JSONDecodeError as exc:
        raise ForgeError("The document policy must be valid JSON.") from exc

    suffix = Path(file.filename or "upload.pdf").suffix or ".pdf"
    staged = PATHS.uploads / f"staged-{uuid.uuid4().hex}{suffix}"
    staged.write_bytes(file.file.read())

    created = document_service.create_document(
        session,
        actor=sender,
        source=staged,
        title=title,
        classification=classification,
        unit=unit,
        mission_reference=mission_reference,
        permitted_units=[item.strip() for item in permitted_units.split(",") if item.strip()],
        permitted_roles=[item.strip() for item in permitted_roles.split(",") if item.strip()],
        recipient_ids=[item.strip() for item in recipients.split(",") if item.strip()],
        policy=policy_body,
    )
    staged.unlink(missing_ok=True)
    return {
        "document": created,
        "plain_explanation": (
            "The document was hashed, classified and encrypted. Each authorised recipient holds their "
            "own wrapped copy of the content key, derived through ML-KEM-768."
        ),
    }


@router.get("")
def list_documents(session: Session = Depends(db), _: Recipient = Depends(readable("document.read"))) -> dict[str, Any]:
    return {"documents": document_service.list_documents(session)}


@router.get("/classifications")
def classifications() -> dict[str, Any]:
    return {
        "levels": CLEARIFICATIONS,
        "note": (
            "Application-level prototype labels. They do not reproduce any official classification "
            "framework and carry no certification."
        ),
    }


@router.get("/lifecycle")
def lifecycle() -> dict[str, Any]:
    return {
        "states": list(DocumentLifecycle.ALLOWED_TRANSITIONS),
        "transitions": {k: list(v) for k, v in DocumentLifecycle.ALLOWED_TRANSITIONS.items()},
    }


@router.get("/{document_id}")
def get_document(document_id: str, session: Session = Depends(db), _: Recipient = Depends(readable("document.read"))) -> dict[str, Any]:
    document = session.get(Document, document_id)
    if document is None:
        raise NotFound(f"No document {document_id}.")
    require_right(document, "VIEW", operation="Viewing this document")
    return {"document": document_service.describe(session, document_id)}


class GrantRequest(BaseModel):
    recipient_id: str
    note: str | None = None


@router.post("/{document_id}/grants")
def grant(
    document_id: str,
    payload: GrantRequest,
    session: Session = Depends(db),
    admin: Recipient = Depends(permitted("document.grant")),
) -> dict[str, Any]:
    """Need-to-know is granted per document, separately from clearance."""
    return document_service.grant(
        session,
        document_id=document_id,
        recipient_id=payload.recipient_id,
        actor_id=admin.recipient_id,
        note=payload.note,
    )


class ShareRequestBody(BaseModel):
    recipient_id: str
    justification: str = Field(min_length=10, max_length=1000)
    expires_in_days: int = Field(default=0, ge=0, le=365)


@router.post("/{document_id}/shares")
def request_share(
    document_id: str,
    payload: ShareRequestBody,
    session: Session = Depends(db),
    granter: Recipient = Depends(permitted("document.grant")),
) -> dict[str, Any]:
    """External sharing: identify → verify clearance, unit, role, need-to-know
    and policy → grant or route to two-person approval → log. The share carries
    an optional end date; every decision lands on the share register."""
    return sharing_service.request_share(
        session,
        document_id=document_id,
        target_recipient_id=payload.recipient_id,
        requested_by=granter.recipient_id,
        justification=payload.justification,
        expires_in_days=payload.expires_in_days,
    )


@router.get("/{document_id}/shares")
def list_shares(
    document_id: str,
    session: Session = Depends(db),
    _: Recipient = Depends(readable("document.read")),
) -> dict[str, Any]:
    document = session.get(Document, document_id)
    if document is None:
        raise NotFound(f"No document {document_id}.")
    return {"shares": sharing_service.list_shares(session, document_id=document_id)}


class AccessRevokeRequest(BaseModel):
    recipient_id: str
    reason: str = Field(min_length=5, max_length=400)


@router.post("/{document_id}/access/revoke")
def revoke_access(
    document_id: str,
    payload: AccessRevokeRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("recipient.revoke")),
) -> dict[str, Any]:
    """Withdraws one recipient's need-to-know on this document. Any offline
    window the recipient still holds for it dies in the same transaction."""
    return revoke_document_access(
        session,
        document_id=document_id,
        recipient_id=payload.recipient_id,
        actor_id=officer.recipient_id,
        reason=payload.reason,
    )


class TransitionRequest(BaseModel):
    target: str
    reason: str = Field(min_length=5, max_length=400)


@router.post("/{document_id}/lifecycle")
def transition(
    document_id: str,
    payload: TransitionRequest,
    session: Session = Depends(db),
    admin: Recipient = Depends(permitted("document.lifecycle")),
) -> dict[str, Any]:
    return document_service.transition(
        session,
        document_id=document_id,
        target=payload.target,
        actor_id=admin.recipient_id,
        reason=payload.reason,
    )


class VersionRequest(BaseModel):
    recipients: list[str] | None = None
    policy: dict[str, Any] | None = None


@router.post("/{document_id}/versions")
def add_version(
    document_id: str,
    payload: VersionRequest,
    file: UploadFile = File(...),
    session: Session = Depends(db),
    sender: Recipient = Depends(permitted("document.upload")),
) -> dict[str, Any]:
    """Adds an immutable revision. Earlier versions keep their own hash and key
    material so a leak can be tied to an exact revision."""
    suffix = Path(file.filename or "version.pdf").suffix or ".pdf"
    staged = PATHS.uploads / f"staged-{uuid.uuid4().hex}{suffix}"
    staged.write_bytes(file.file.read())
    result = document_service.add_version(
        session,
        actor=sender,
        document_id=document_id,
        source=staged,
        recipient_ids=payload.recipients,
        policy=payload.policy,
    )
    staged.unlink(missing_ok=True)
    return {"document": result}


@router.post("/{document_id}/suspend")
def suspend(
    document_id: str,
    payload: TransitionRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("recipient.revoke")),
) -> dict[str, Any]:
    return document_service.suspend(
        session, document_id=document_id, actor_id=officer.recipient_id, reason=payload.reason
    )


@router.post("/{document_id}/purge-plaintext")
def purge_plaintext(
    document_id: str,
    session: Session = Depends(db),
    admin: Recipient = Depends(permitted("document.lifecycle")),
) -> dict[str, Any]:
    """Removes the pre-encryption working copy once a version is sealed."""
    return document_service.purge_plaintext(session, document_id, admin.recipient_id)


@router.get("/policies/current")
def current_policy(session: Session = Depends(db), _: Recipient = Depends(readable("document.decrypt"))) -> dict[str, Any]:
    policy = approval_service.active_policy(session)
    return {
        "policy": {
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_hash": policy.policy_hash or approval_service.policy_hash(approval_service.policy_config(policy)),
            "name": policy.name,
            "device_access_policy": policy.device_access_policy,
            "replay_window_seconds": policy.replay_window_seconds,
            "break_glass_enabled": policy.break_glass_enabled,
            "high_risk_actions": __import__("json").loads(policy.high_risk_actions or "[]"),
            "updated_by": policy.updated_by,
            "updated_at": policy.updated_at.isoformat(timespec="seconds") if policy.updated_at else None,
            "change_reason": policy.change_reason,
        },
        "versions": approval_service.policy_history(session),
        "limitation": (
            "historical decisions keep the policy version and digest that governed them; "
            "only the active version applies to new decisions"
        ),
    }
