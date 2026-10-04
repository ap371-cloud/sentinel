from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from ..core.exceptions import AuthenticationError
from ..core.permissions import require_permission, require_writable
from ..database.session import OpsSession
from ..models.identity import Recipient
from ..services import identity_service


def db() -> Iterator[Session]:
    """One transaction per request.

    Committed on success and rolled back on any failure, so a refused security
    operation leaves no partial state behind: a denied decryption must not leave
    a half-created session row behind.
    """
    session = OpsSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthenticationError("An authentication token is required for this endpoint.")
    return authorization.split(" ", 1)[1].strip()


def current_recipient(
    session: Session = Depends(db), token: str = Depends(bearer_token)
) -> Recipient:
    return identity_service.identify(session, token)


def writable(recipient: Recipient = Depends(current_recipient)) -> Recipient:
    require_writable(recipient.role)
    return recipient


def readable(permission: str):
    """Read guard. Read-only roles are allowed here, which is the whole point of
    an auditor: they may verify anything and change nothing."""

    def dependency(recipient: Recipient = Depends(current_recipient)) -> Recipient:
        require_permission(recipient.role, permission)
        return recipient

    return dependency


def permitted(permission: str):
    """Write guard. Refuses read-only roles and asserts one permission before the
    handler body runs."""

    def dependency(recipient: Recipient = Depends(current_recipient)) -> Recipient:
        require_writable(recipient.role)
        require_permission(recipient.role, permission)
        return recipient

    return dependency


def auditor_or(recipient: Recipient = Depends(current_recipient)) -> Recipient:
    return recipient


def ok(**payload: Any) -> dict[str, Any]:
    return payload
