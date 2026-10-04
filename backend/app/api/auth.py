from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.config import Role
from ..models.identity import Recipient
from ..services import audit_service, identity_service
from .deps import current_recipient, db, permitted, readable

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    recipient_id: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=200)
    device_id: str | None = Field(default=None, max_length=48)


class LogoutRequest(BaseModel):
    reason: str = Field(default="User-initiated sign out", max_length=200)


@router.post("/login")
def login(payload: LoginRequest, session: Session = Depends(db)) -> dict[str, Any]:
    """Authenticates locally. No external identity provider is contacted, which
    is a requirement of the air-gapped deployment."""
    recipient, token = identity_service.authenticate(
        session,
        recipient_id=payload.recipient_id,
        password=payload.password,
        device_id=payload.device_id,
    )
    return {
        "token": token,
        "token_type": "bearer",
        "expires_in_seconds": 8 * 3600,
        "identity": identity_service.to_public(recipient),
        "devices": identity_service.devices_for(session, recipient.recipient_id),
        "plain_explanation": (
            "Signed in. This token identifies you for audit purposes; every sensitive action is "
            "still re-authorised from live state on each call."
        ),
    }


@router.post("/logout")
def logout(
    payload: LogoutRequest,
    session: Session = Depends(db),
    recipient: Recipient = Depends(current_recipient),
) -> dict[str, Any]:
    audit_service.record(
        session,
        actor_id=recipient.recipient_id,
        action="LOGOUT",
        target_type="RECIPIENT",
        target_id=recipient.recipient_id,
        detail={"reason": payload.reason},
    )
    return {
        "recipient_id": recipient.recipient_id,
        "signed_out": True,
        "note": (
            "Tokens are stateless and short-lived. Revocation takes effect immediately on the next "
            "request regardless of any token still being held."
        ),
    }


@router.get("/whoami")
def whoami(session: Session = Depends(db), recipient: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    from ..core.permissions import PERMISSIONS

    return {
        "identity": identity_service.to_public(recipient),
        "permissions": sorted(PERMISSIONS.get(recipient.role, frozenset())),
        "devices": identity_service.devices_for(session, recipient.recipient_id),
        "clearance_label": identity_service.to_public(recipient)["clearance_label"],
    }


@router.get("/directory")
def directory(
    session: Session = Depends(db), recipient: Recipient = Depends(current_recipient)
) -> dict[str, Any]:
    """Identity list for authorised operators. Password material is never part of
    any response shape in this system."""
    return {
        "identities": identity_service.list_all(session),
        "synthetic_data_notice": (
            "Every identity in this environment is invented for demonstration and describes no real "
            "personnel or unit."
        ),
    }


class CreateRecipientRequest(BaseModel):
    recipient_id: str = Field(min_length=3, max_length=32)
    display_name: str = Field(min_length=2, max_length=120)
    role: str
    unit: str = Field(min_length=2, max_length=40)
    clearance: int = Field(ge=0, le=4)
    password: str = Field(min_length=8, max_length=200)
    email: str | None = Field(default=None, max_length=160)


@router.post("/identities")
def create_identity(
    payload: CreateRecipientRequest,
    session: Session = Depends(db),
    admin: Recipient = Depends(permitted("recipient.create")),
) -> dict[str, Any]:
    """Issues a cryptographic identity: an ML-DSA signing key and an ML-KEM
    key-establishment key, both held only in the encrypted key vault."""
    created = identity_service.create(
        session,
        recipient_id=payload.recipient_id,
        display_name=payload.display_name,
        role=payload.role,
        unit=payload.unit,
        clearance=payload.clearance,
        password=payload.password,
        actor_id=admin.recipient_id,
        email=payload.email,
    )
    return {
        "identity": created,
        "keys": identity_service.key_inventory(session, payload.recipient_id),
        "plain_explanation": (
            "A post-quantum signing key and key-establishment key were generated for this identity and "
            "stored encrypted. Private key material is never returned by this API."
        ),
    }


class RegisterDeviceRequest(BaseModel):
    device_id: str = Field(min_length=3, max_length=48)
    device_name: str = Field(min_length=2, max_length=120)
    fingerprint: str = Field(min_length=8, max_length=128)


@router.post("/devices")
def register_device(
    payload: RegisterDeviceRequest,
    session: Session = Depends(db),
    admin: Recipient = Depends(permitted("device.manage")),
) -> dict[str, Any]:
    return identity_service.register_device(
        session,
        recipient_id=payload.recipient_id,
        device_id=payload.device_id,
        device_name=payload.device_name,
        fingerprint=payload.fingerprint,
        actor_id=admin.recipient_id,
    )


@router.get("/keys")
def keys(
    session: Session = Depends(db),
    admin: Recipient = Depends(readable("key.manage")),
) -> dict[str, Any]:
    return {"inventory": identity_service.key_inventory(session)}


@router.get("/roles")
def roles(_: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    from ..core.permissions import separation_of_duties_report

    return {
        "roles": list(Role.ALL),
        "approver_roles": list(Role.APPROVERS),
        "read_only_roles": list(Role.READ_ONLY),
        "separation_of_duties": separation_of_duties_report(),
    }
