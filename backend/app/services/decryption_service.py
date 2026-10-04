from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import PATHS, SETTINGS, Clearance
from ..core.exceptions import ForgeError, NotFound, ReplayDetected
from ..core.identifiers import next_id
from ..core.timeutil import as_utc, has_expired, iso, utcnow
from ..core.permissions import (
    RequestContext,
    evaluate_decryption,
    raise_for_decision,
    require_permission,
)
from ..crypto.hashing import b64e, canonical_bytes, sha256_hex
from ..crypto.signatures import event_payload, sign_as_recipient
from ..documents import encryption
from ..ledger.block import Transaction as LedgerTransaction
from ..models.documents import Document, DocumentVersion
from ..models.identity import Device, KeyMetadata, Recipient
from ..models.sessions import DecryptionEvent, DecryptionSession, RequestNonce, Watermark
from ..security import anomaly_detection, incident_engine
from ..security.lockdown import is_active as lockdown_active
from . import approval_service, audit_service, document_service, watermark_service

GENESIS_EVENT_HASH = "0" * 64
SESSION_TTL_SECONDS = 300


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# session bootstrap
# --------------------------------------------------------------------------


def issue_nonce(session: Session, *, recipient_id: str, document_id: str) -> dict[str, Any]:
    """Server-issued single-use nonce.

    The client cannot supply its own value: a captured request replayed later
    presents a nonce this table already shows as consumed.
    """
    nonce = b64e(os.urandom(32))
    session.add(
        RequestNonce(
            nonce=nonce,
            recipient_id=recipient_id,
            document_id=document_id,
            issued_at=_utcnow(),
            expires_at=_utcnow() + timedelta(seconds=SETTINGS.replay_window_seconds),
        )
    )
    audit_service.record(
        session,
        actor_id=recipient_id,
        action="DECRYPTION_REQUEST_AUTHORIZED",
        target_type="DOCUMENT",
        target_id=document_id,
        detail={"nonce_issued": True},
    )
    return {
        "nonce": nonce,
        "issued_at": _utcnow().isoformat(timespec="seconds"),
        "expires_at": (_utcnow() + timedelta(seconds=SETTINGS.replay_window_seconds)).isoformat(timespec="seconds"),
        "single_use": True,
        "plain_explanation": (
            "This one-time value must accompany the decryption request. Replaying the request will be "
            "refused."
        ),
    }


def _assert_nonce_fresh(session: Session, *, nonce: str, recipient_id: str, document_id: str) -> RequestNonce:
    """Replay gate.

    Runs before authorisation so a replayed request is reported as a replay
    rather than as a generic policy denial, and so the security event names the
    real cause.
    """
    row = session.get(RequestNonce, nonce)
    if row is None:
        incident_engine.raise_event(
            session,
            "REPLAY_ATTACK",
            what_happened=f"{recipient_id} submitted a decryption request carrying a nonce this service never issued.",
            why_it_matters="The request was not authorised here, so it cannot be trusted.",
            what_was_affected=document_id,
            severity="HIGH",
            subject_id=recipient_id,
            document_id=document_id,
        )
        raise ReplayDetected(
            "This decryption request was not issued by the service.",
            detail="Request a fresh authorisation token and retry.",
        )

    if row.consumed_at is not None or row.recipient_id != recipient_id:
        incident_engine.raise_event(
            session,
            "REPLAY_ATTACK",
            title="Replay attack detected",
            what_happened=(
                f"{recipient_id} presented a decryption authorisation that had already been consumed"
                + (" by a different identity." if row.recipient_id != recipient_id else ".")
            ),
            why_it_matters=(
                "A captured request is being replayed to obtain a second authorised decryption of the "
                "same document."
            ),
            what_was_affected=document_id,
            recommended_action="Treat the captured request as evidence and investigate its origin.",
            subject_id=recipient_id,
            document_id=document_id,
        )
        raise ReplayDetected(
            "This decryption request has already been used.",
            detail="Each authorised request may be presented exactly once.",
        )
    return row


def _consume_nonce(session: Session, *, nonce: str, session_id: str) -> None:
    row = session.get(RequestNonce, nonce)
    if row is not None:
        row.consumed_at = _utcnow()
        row.session_id = session_id


# --------------------------------------------------------------------------
# the decryption path
# --------------------------------------------------------------------------


def decrypt(
    session: Session,
    *,
    actor: Recipient,
    document_id: str,
    device_id: str,
    nonce: str,
    request_id: str | None = None,
    offline: bool = False,
    break_glass_approval_id: str | None = None,
    export_as: str | None = None,
) -> dict[str, Any]:
    """Full authorised decryption.

    Order matters: every authorisation input is re-read from live state before a
    single byte of plaintext exists, and the signed event is written only after
    the watermarked artefact has been produced.
    """
    require_permission(actor.role, "document.decrypt")

    document = session.get(Document, document_id)
    if document is None:
        raise NotFound(f"No document {document_id}.")
    version = document_service.current_version(session, document_id)
    device = session.get(Device, device_id)
    policy = approval_service.active_policy(session)
    _assert_nonce_fresh(
        session, nonce=nonce, recipient_id=actor.recipient_id, document_id=document_id
    )

    session_id = next_id("SES", width=8)
    break_glass = False
    break_glass_reason: str | None = None
    if break_glass_approval_id:
        approval = approval_service.consume(
            session,
            approval_id=break_glass_approval_id,
            acting_role=actor.role,
            expected_action="EMERGENCY_ACCESS",
        )
        break_glass = True
        break_glass_reason = approval.justification
        incident_engine.raise_event(
            session,
            "EMERGENCY_ACCESS",
            what_happened=(
                f"{actor.recipient_id} used two-person-approved emergency access on {document_id}."
            ),
            why_it_matters="A normal authorisation rule was overridden, so the access must be reviewed afterwards.",
            what_was_affected=f"{document_id} version {version.version_number}",
            recommended_action="Complete the mandatory post-event review of the justification.",
            subject_id=actor.recipient_id,
            document_id=document_id,
        )

    decision = _authorize(
        session,
        actor=actor,
        document=document,
        version=version,
        device=device,
        nonce=nonce,
        policy=policy,
        offline=offline,
        break_glass=break_glass,
    )

    decryption_session = DecryptionSession(
        session_id=session_id,
        document_id=document_id,
        version_id=version.version_id,
        version_number=version.version_number,
        recipient_id=actor.recipient_id,
        device_id=device_id,
        request_nonce=nonce,
        request_id=request_id or next_id("REQ", width=8),
        nonce=b64e(os.urandom(24)),
        issued_at=_utcnow(),
        status="AUTHORIZED",
        is_break_glass=break_glass,
        break_glass_reason=break_glass_reason,
        break_glass_approval_id=break_glass_approval_id,
        policy_version=policy.policy_version,
        watermark_version=SETTINGS.watermark_version,
        authorization_trace=json.dumps(decision.trace()),
    )
    session.add(decryption_session)
    session.flush()

    _consume_nonce(session, nonce=nonce, session_id=session_id)

    plaintext = _unwrap_document(session, document, version, actor.recipient_id)

    tag, inputs = watermark_service.issue_tag(
        recipient_id=actor.recipient_id,
        document_id=document_id,
        document_hash=version.content_sha256,
        session_id=session_id,
        nonce=decryption_session.nonce,
    )
    output_path = _output_path(document, version, actor.recipient_id, session_id, export_as)
    quality = watermark_service.embed_for_session(
        source_pdf=Path(version.normalized_pdf_path),
        output_pdf=output_path,
        recipient_id=actor.recipient_id,
        document=document,
        version=version,
        session_id=session_id,
        nonce=decryption_session.nonce,
        tag=tag,
    )
    watermark_service.register(
        session,
        session_row=decryption_session,
        document=document,
        version=version,
        tag=tag,
        inputs=inputs,
        quality=quality,
    )

    event, ledger = _record_signed_event(
        session,
        actor=actor,
        document=document,
        version=version,
        decryption_session=decryption_session,
        device_id=device_id,
        tag=tag,
        break_glass=break_glass,
    )

    decryption_session.status = "COMPLETED"
    decryption_session.completed_at = _utcnow()
    if device is not None:
        device.last_seen_at = _utcnow()

    verdicts = anomaly_detection.run_for_decryption(session, actor, device_id)
    for verdict in verdicts:
        if verdict.triggered:
            incident_engine.raise_event(
                session,
                verdict.rule,
                what_happened=verdict.explanation,
                what_was_affected=document_id,
                subject_id=actor.recipient_id,
                severity=verdict.severity,
            )

    audit_service.record(
        session,
        actor_id=actor.recipient_id,
        action="DOCUMENT_DECRYPTED",
        target_type="DECRYPTION_SESSION",
        target_id=session_id,
        detail={
            "document_id": document_id,
            "version_number": version.version_number,
            "device_id": device_id,
            "watermark_id": f"WM-{session_id}",
            "event_id": event.event_id,
            "ledger_tx_id": event.ledger_tx_id,
            "break_glass": break_glass,
        },
    )
    audit_service.record(
        session,
        actor_id=actor.recipient_id,
        action="LEDGER_OPERATION",
        target_type="LEDGER_TRANSACTION",
        target_id=event.ledger_tx_id,
        detail={"status": ledger["status"], "block_id": ledger.get("block_id")},
    )

    return {
        "session_id": session_id,
        "document_id": document_id,
        "version_id": version.version_id,
        "version_number": version.version_number,
        "classification": document.classification,
        "recipient_id": actor.recipient_id,
        "device_id": device_id,
        "watermark_id": f"WM-{session_id}",
        "watermark_tag": tag,
        "watermark_quality": quality,
        "output_path": str(output_path),
        "event_id": event.event_id,
        "event_hash": event.event_hash,
        "signature_algorithm": event.signature_algorithm,
        "ledger": ledger,
        "break_glass": break_glass,
        "authorization_checks": decision.trace(),
        "decrypted_at": decryption_session.completed_at.isoformat(timespec="seconds"),
        "viewer_note": (
            "Production deployment would require a hardened endpoint and a controlled viewer. This "
            "prototype writes a watermarked copy to the recipient's session directory, which is a "
            "demonstration of the flow rather than a secure document-delivery product."
        ),
    }


def _authorize(
    session: Session,
    *,
    actor: Recipient,
    document: Document,
    version: DocumentVersion,
    device: Device | None,
    nonce: str,
    policy,
    offline: bool,
    break_glass: bool,
):
    nonce_row = session.get(RequestNonce, nonce)
    signing_key = session.execute(
        select(KeyMetadata).where(
            KeyMetadata.owner_id == actor.recipient_id, KeyMetadata.purpose == "SIGNING"
        )
    ).scalars().first()
    kem_key = session.execute(
        select(KeyMetadata).where(
            KeyMetadata.owner_id == actor.recipient_id, KeyMetadata.purpose == "KEM"
        )
    ).scalars().first()

    signing_expired = has_expired(signing_key.expires_at if signing_key else None)

    context = RequestContext(
        actor_id=actor.recipient_id,
        role=actor.role,
        unit=actor.unit,
        clearance=actor.clearance,
        account_status=actor.status,
        device_id=device.device_id if device else None,
        document_classification=Clearance[document.classification].value,
        document_status=document.status,
        document_unit_scope=json.loads(document.need_to_know_units or "[]"),
        document_role_scope=json.loads(document.permitted_roles or "[]"),
        granted=document_service.has_active_grant(session, document.document_id, actor.recipient_id),
        device_status=device.status if device else None,
        device_trust=device.trust_state if device else None,
        device_owner_id=device.recipient_id if device else None,
        signing_key_status=signing_key.status if signing_key else None,
        signing_key_expired=signing_expired,
        kem_key_status=kem_key.status if kem_key else None,
        nonce_consumed=bool(nonce_row and nonce_row.consumed_at is not None),
        nonce_expired=bool(nonce_row and has_expired(nonce_row.expires_at)),
        nonce_owner_match=bool(nonce_row and nonce_row.recipient_id == actor.recipient_id),
        lockdown_active=lockdown_active(session),
        document_expired=document_service.is_expired(document),
        session_budget_exhausted=bool(
            document.maximum_sessions
            and document_service.sessions_used(session, document.document_id) >= document.maximum_sessions
        ),
        offline_requested=offline,
        offline_allowed=document.offline_allowed,
        break_glass_approved=break_glass,
    )
    decision = evaluate_decryption(context, device_policy=policy.device_access_policy)
    raise_for_decision(decision, recipient_status=actor.status)
    return decision


def _unwrap_document(
    session: Session, document: Document, version: DocumentVersion, recipient_id: str
) -> bytes:
    if version.sealed_path is None:
        raise ForgeError(f"{version.version_id} has not been sealed.")
    wrap = document_service.key_wrap_for(session, version, recipient_id)
    if wrap is None:
        raise ForgeError(
            "No content-key material was ever wrapped for this recipient on this version.",
            detail="Being authorised to read a document is not the same as having been sent the key.",
        )
    plaintext = encryption.open_sealed(
        sealed_path=Path(version.sealed_path),
        wrap=wrap,
        recipient_id=recipient_id,
        document_id=document.document_id,
        version_id=version.version_id,
        content_sha256=version.content_sha256,
    )
    if sha256_hex(plaintext) != version.content_sha256:
        from ..core.exceptions import DocumentHashMismatch

        raise DocumentHashMismatch(
            "Decrypted content does not match the hash recorded for this version.",
            detail="Either the stored ciphertext or the recorded hash was altered.",
        )
    return plaintext


def _output_path(
    document: Document, version: DocumentVersion, recipient_id: str, session_id: str, export_as: str | None
) -> Path:
    folder = PATHS.evidence / "recipient_copies" / recipient_id / session_id
    folder.mkdir(parents=True, exist_ok=True)
    name = export_as or f"{document.document_id}-v{version.version_number}-{session_id}.pdf"
    if not name.lower().endswith(".pdf"):
        name = f"{name}.pdf"
    return folder / name


def _record_signed_event(
    session: Session,
    *,
    actor: Recipient,
    document: Document,
    version: DocumentVersion,
    decryption_session: DecryptionSession,
    device_id: str,
    tag: str,
    break_glass: bool,
) -> tuple[DecryptionEvent, dict[str, Any]]:
    from ..ledger.chain import NETWORK

    event_id = next_id("EVT", width=8)
    previous = _last_event_hash(session)
    payload = event_payload(
        event_id=event_id,
        event_type="DOCUMENT_DECRYPTED",
        session_id=decryption_session.session_id,
        recipient_id=actor.recipient_id,
        document_id=document.document_id,
        version_id=version.version_id,
        version_number=version.version_number,
        document_hash=version.content_sha256,
        device_id=device_id,
        watermark_tag=tag,
        policy_version=SETTINGS.policy_version,
        watermark_version=SETTINGS.watermark_version,
        occurred_at=_utcnow().isoformat(timespec="seconds"),
        break_glass=break_glass,
    )
    signature, algorithm, key_id = sign_as_recipient(actor.recipient_id, payload)
    event_hash = sha256_hex(canonical_bytes(payload))

    event = DecryptionEvent(
        event_id=event_id,
        event_type="DOCUMENT_DECRYPTED",
        session_id=decryption_session.session_id,
        watermark_id=f"WM-{decryption_session.session_id}",
        recipient_id=actor.recipient_id,
        document_id=document.document_id,
        version_id=version.version_id,
        version_number=version.version_number,
        document_hash=version.content_sha256,
        device_id=device_id,
        watermark_tag=tag,
        signing_key_id=key_id,
        signature_algorithm=algorithm,
        signature=signature,
        payload=json.dumps(payload, sort_keys=True),
        event_hash=event_hash,
        prev_event_hash=previous,
        occurred_at=_utcnow(),
        break_glass=break_glass,
    )

    # The ledger transaction is offered before the event row is written, so the
    # row never has to be updated afterwards. That keeps the signed-event table
    # genuinely append-only rather than append-only in principle only.
    transaction = LedgerTransaction.from_event(event)
    ledger = NETWORK.submit(transaction)
    event.ledger_tx_id = transaction.tx_id
    session.add(event)
    session.flush()

    watermark_row = session.execute(
        select(Watermark).where(Watermark.session_id == decryption_session.session_id)
    ).scalar_one_or_none()
    if watermark_row is not None:
        watermark_row.ledger_anchor_tx = transaction.tx_id

    return event, ledger


def _last_event_hash(session: Session) -> str:
    row = session.execute(
        select(DecryptionEvent.event_hash).order_by(DecryptionEvent.event_id.desc()).limit(1)
    ).scalar()
    return row or GENESIS_EVENT_HASH


# --------------------------------------------------------------------------
# read models
# --------------------------------------------------------------------------


def describe_session(session: Session, session_id: str) -> dict[str, Any]:
    row = session.get(DecryptionSession, session_id)
    if row is None:
        raise NotFound(f"No decryption session {session_id}.")
    event = session.execute(
        select(DecryptionEvent).where(DecryptionEvent.session_id == session_id)
    ).scalar_one_or_none()
    watermark = session.execute(
        select(Watermark).where(Watermark.session_id == session_id)
    ).scalar_one_or_none()
    return {
        "session_id": row.session_id,
        "document_id": row.document_id,
        "version_id": row.version_id,
        "version_number": row.version_number,
        "recipient_id": row.recipient_id,
        "device_id": row.device_id,
        "issued_at": row.issued_at.isoformat(timespec="seconds"),
        "completed_at": row.completed_at.isoformat(timespec="seconds") if row.completed_at else None,
        "status": row.status,
        "request_id": row.request_id,
        "break_glass": row.is_break_glass,
        "break_glass_reason": row.break_glass_reason,
        "policy_version": row.policy_version,
        "watermark_version": row.watermark_version,
        "nonce_consumed": True,
        "single_use_enforced": SETTINGS.session_single_use,
        "authorization_checks": json.loads(row.authorization_trace or "[]"),
        "watermark_id": watermark.watermark_id if watermark else None,
        "watermark_tag": watermark.tag if watermark else None,
        "watermark_quality": (
            {"psnr_db": watermark.psnr_db, "ssim": watermark.ssim, "carriers_per_bit": watermark.carriers_per_bit}
            if watermark
            else None
        ),
        "signature": (
            {
                "event_id": event.event_id,
                "event_hash": event.event_hash,
                "algorithm": event.signature_algorithm,
                "signing_key_id": event.signing_key_id,
                "signature": event.signature,
                "prev_event_hash": event.prev_event_hash,
            }
            if event
            else None
        ),
        "ledger_tx_id": event.ledger_tx_id if event else None,
        "ledger_committed": bool(event and event.ledger_tx_id),
    }


def list_sessions(session: Session, *, recipient_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    statement = select(DecryptionSession).order_by(DecryptionSession.issued_at.desc()).limit(limit)
    if recipient_id:
        statement = statement.where(DecryptionSession.recipient_id == recipient_id)
    tags = {row.session_id: row.tag for row in session.execute(select(Watermark)).scalars()}
    return [
        {
            "session_id": row.session_id,
            "recipient_id": row.recipient_id,
            "document_id": row.document_id,
            "version_number": row.version_number,
            "device_id": row.device_id,
            "issued_at": row.issued_at.isoformat(timespec="seconds"),
            "status": row.status,
            "break_glass": row.is_break_glass,
            "watermark_tag": tags.get(row.session_id),
        }
        for row in session.execute(statement).scalars()
    ]


def verify_event_chain(session: Session) -> dict[str, Any]:
    """The signed-event chain is hash-linked independently of the ledger, so
    removing an event from the operational database is detectable even if the
    ledger copy is untouched."""
    rows = list(session.execute(select(DecryptionEvent).order_by(DecryptionEvent.event_id)).scalars())
    previous = GENESIS_EVENT_HASH
    broken_at: str | None = None
    for row in rows:
        payload = json.loads(row.payload)
        if row.prev_event_hash != previous or sha256_hex(canonical_bytes(payload)) != row.event_hash:
            broken_at = row.event_id
            break
        previous = row.event_hash
    return {
        "events": len(rows),
        "status": "VERIFIED" if broken_at is None else "TAMPER DETECTED",
        "first_broken_event": broken_at,
        "head": previous,
        "plain_explanation": (
            "Each signed decryption event is chained to the previous one, so deleting or editing any "
            "event is detectable."
        ),
    }
