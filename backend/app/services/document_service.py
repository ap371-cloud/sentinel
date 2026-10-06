from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import PATHS, SETTINGS, Clearance, DocumentAccess, DocumentLifecycle, Role
from ..core.identifiers import next_id
from ..core.timeutil import has_expired, iso, utcnow
from ..core.exceptions import ForgeError, NotFound
from ..core import rights
from ..crypto.hashing import file_digest_bundle
from ..database import shared as shared_store
from ..documents import encryption, pdf, protection
from ..models.documents import Document, DocumentVersion, OfflineGrant, RecipientGrant
from ..models.identity import Recipient
from ..models.sessions import DecryptionSession
from ..security import locations
from . import audit_service


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def next_document_id() -> str:
    return next_id("DOC", width=3)


def create_document(
    session: Session,
    *,
    actor: Recipient,
    source: Path,
    title: str,
    classification: str,
    unit: str,
    mission_reference: str | None = None,
    permitted_units: list[str] | None = None,
    permitted_roles: list[str] | None = None,
    recipient_ids: list[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Upload → normalise → hash → classify → encrypt.

    The plaintext is written once to a controlled working path, encrypted
    immediately, and the artefact the rest of the system references is the
    sealed file. Nothing downstream ever needs the plaintext again except an
    authorised decryption.
    """
    if classification not in {level.name for level in Clearance}:
        raise ForgeError(f"Unknown classification {classification}.")

    document_id = next_document_id()
    version_number = 1
    version_id = f"{document_id}-VERSION-{version_number:03d}"
    normalized = PATHS.uploads / f"{version_id}.pdf"
    normalization = pdf.normalize_to_pdf(source, normalized)
    digest = file_digest_bundle(normalized)

    document = Document(
        document_id=document_id,
        title=title,
        classification=classification,
        owner_id=actor.recipient_id,
        owning_unit=unit,
        current_version=version_number,
        status=DocumentAccess.DRAFT,
        lifecycle_state=DocumentLifecycle.CREATED,
        policy_version=SETTINGS.policy_version,
        mission_reference=mission_reference,
        need_to_know_units=json.dumps(permitted_units or [unit]),
        permitted_roles=json.dumps(permitted_roles or [Role.RECIPIENT]),
    )
    # The boolean columns record the classification's baseline decision, so a
    # document created without an explicit policy still carries an explicit
    # per-right verdict instead of the model's blanket defaults.
    baseline = rights.classification_defaults(classification)
    for right, column in rights.LEGACY_COLUMNS.items():
        setattr(document, column, baseline[right] == rights.ALLOW)
    _apply_policy(document, policy or {})
    session.add(document)
    session.flush()

    version = DocumentVersion(
        version_id=version_id,
        document_id=document_id,
        version_number=version_number,
        content_sha256=digest["sha256"],
        size_bytes=digest["size_bytes"],
        page_count=normalization["page_count"],
        normalized_pdf_path=str(normalized),
        classification=classification,
        created_by=actor.recipient_id,
    )
    session.add(version)
    session.flush()

    seal_document(session, document=document, version=version, recipient_ids=recipient_ids or [])
    _advance(session, document, DocumentLifecycle.CLASSIFIED, actor.recipient_id, "Classification assigned at upload.")
    _advance(
        session,
        document,
        DocumentLifecycle.APPROVED,
        actor.recipient_id,
        "Sender approval recorded for initial distribution.",
    )
    _advance(
        session,
        document,
        DocumentLifecycle.DISTRIBUTED,
        actor.recipient_id,
        f"Key material distributed to {len(recipient_ids or [])} recipient(s).",
    )
    _advance(session, document, DocumentLifecycle.ACTIVE, actor.recipient_id, "Document is available for decryption.")

    audit_service.record(
        session,
        actor_id=actor.recipient_id,
        action="DOCUMENT_UPLOADED",
        target_type="DOCUMENT",
        target_id=document_id,
        detail={
            "title": title,
            "classification": classification,
            "content_sha256": digest["sha256"],
            "version_id": version_id,
            "page_count": normalization["page_count"],
        },
    )
    audit_service.record(
        session,
        actor_id=actor.recipient_id,
        action="DOCUMENT_SEALED",
        target_type="DOCUMENT_VERSION",
        target_id=version_id,
        detail={
            "content_cipher": encryption.CONTENT_CIPHER,
            "key_wrap_algorithm": encryption.WRAP_ALGORITHM,
        },
    )
    for recipient_id in recipient_ids or []:
        grant(session, document_id=document_id, recipient_id=recipient_id, actor_id=actor.recipient_id)

    return describe(session, document.document_id)


def _apply_policy(document: Document, policy: dict[str, Any]) -> None:
    fields = (
        "download_allowed", "print_allowed", "export_allowed", "offline_allowed",
        "watermark_required", "visible_watermark", "second_approval_required", "maximum_sessions",
    )
    for name in fields:
        if name in policy:
            setattr(document, name, bool(policy[name]))
    if policy.get("access_expiry_days"):
        document.access_expiry = _utcnow() + timedelta(days=int(policy["access_expiry_days"]))
    if "offline_max_hours" in policy:
        hours = int(policy["offline_max_hours"])
        if not 0 <= hours <= 8760:
            raise ForgeError("offline_max_hours must be between 0 (no time cap) and 8760.")
        document.offline_max_hours = hours
    if "rights" in policy:
        overrides = policy["rights"]
        if not isinstance(overrides, dict):
            raise ForgeError("The rights policy must be an object of right-name to ALLOW/DENY.")
        document.rights = json.dumps(rights.validate_overrides(overrides))
    if "allowed_locations" in policy:
        document.allowed_locations = json.dumps(
            locations.validate_zones(policy["allowed_locations"])
        )


def add_version(
    session: Session,
    *,
    actor: Recipient,
    document_id: str,
    source: Path,
    recipient_ids: list[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Adds a new immutable revision.

    Earlier versions keep their own hash and key material. That is what lets a
    forensic report state exactly which revision leaked rather than which
    document.
    """
    document = _require(session, document_id)
    if document.status == DocumentAccess.REVOKED:
        raise ForgeError("A revoked document cannot receive new versions.")

    version_number = document.current_version + 1
    version_id = f"{document_id}-VERSION-{version_number:03d}"
    normalized = PATHS.uploads / f"{version_id}.pdf"
    normalization = pdf.normalize_to_pdf(source, normalized)
    digest = file_digest_bundle(normalized)

    for existing in session.execute(
        select(DocumentVersion).where(DocumentVersion.document_id == document_id)
    ).scalars():
        existing.is_current = False
        existing.superseded_at = _utcnow()

    version = DocumentVersion(
        version_id=version_id,
        document_id=document_id,
        version_number=version_number,
        content_sha256=digest["sha256"],
        size_bytes=digest["size_bytes"],
        page_count=normalization["page_count"],
        normalized_pdf_path=str(normalized),
        classification=document.classification,
        created_by=actor.recipient_id,
    )
    session.add(version)
    document.current_version = version_number
    session.flush()

    targets = recipient_ids if recipient_ids is not None else _granted_recipients(session, document_id)
    seal_document(session, document=document, version=version, recipient_ids=targets)
    if policy:
        _apply_policy(document, policy)

    audit_service.record(
        session,
        actor_id=actor.recipient_id,
        action="DOCUMENT_VERSION_CREATED",
        target_type="DOCUMENT_VERSION",
        target_id=version_id,
        detail={"version_number": version_number, "content_sha256": digest["sha256"]},
    )
    return describe(session, document_id)


def seal_document(
    session: Session,
    *,
    document: Document,
    version: DocumentVersion,
    recipient_ids: list[str],
) -> dict[str, Any]:
    """Encrypts the normalised PDF once and wraps the content key per recipient."""
    sealed_path = PATHS.sealed / f"{version.version_id}.sealed"
    eligible = [
        recipient_id
        for recipient_id in recipient_ids
        if _has_usable_keys(recipient_id)
    ]
    sealed = encryption.seal(
        plaintext_pdf=Path(version.normalized_pdf_path),
        sealed_path=sealed_path,
        document_id=document.document_id,
        version_id=version.version_id,
        recipient_ids=eligible,
        content_sha256=version.content_sha256,
    )
    version.sealed_path = str(sealed_path)
    version.document_key_id = sealed["document_key_id"]
    version.wrap_algorithm = sealed["key_wrap_algorithm"]
    version.key_wraps = json.dumps(sealed["wrapped_keys"])
    document.status = DocumentAccess.SEALED
    if document.sealed_at is None:
        document.sealed_at = _utcnow()
    return sealed


def _has_usable_keys(recipient_id: str) -> bool:
    from ..crypto.key_management import VAULT

    try:
        VAULT.signing_public_key(recipient_id)
        VAULT.kem_public_key(recipient_id)
        return True
    except Exception:
        return False


def grant(
    session: Session, *, document_id: str, recipient_id: str, actor_id: str, note: str | None = None
) -> dict[str, Any]:
    existing = session.execute(
        select(RecipientGrant).where(
            RecipientGrant.document_id == document_id,
            RecipientGrant.recipient_id == recipient_id,
            RecipientGrant.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        return {"grant_id": existing.grant_id, "status": "ALREADY_GRANTED"}

    recipient = session.get(Recipient, recipient_id)
    if recipient is None:
        raise NotFound(f"No identity {recipient_id}.")

    grant_id = next_id("GRT", width=6)
    session.add(
        RecipientGrant(
            grant_id=grant_id,
            document_id=document_id,
            recipient_id=recipient_id,
            granted_by=actor_id,
            note=note,
        )
    )
    document = _require(session, document_id)
    if document.status == DocumentAccess.DRAFT:
        document.status = DocumentAccess.SEALED
    audit_service.record(
        session,
        actor_id=actor_id,
        action="DOCUMENT_PERMISSION_CHANGED",
        target_type="DOCUMENT_GRANT",
        target_id=grant_id,
        detail={"document_id": document_id, "recipient_id": recipient_id, "grant": "ADDED", "note": note},
    )
    return {"grant_id": grant_id, "status": "GRANTED", "recipient_id": recipient_id, "document_id": document_id}


def has_active_grant(session: Session, document_id: str, recipient_id: str) -> bool:
    return (
        session.execute(
            select(func.count())
            .select_from(RecipientGrant)
            .where(
                RecipientGrant.document_id == document_id,
                RecipientGrant.recipient_id == recipient_id,
                RecipientGrant.revoked_at.is_(None),
            )
        ).scalar_one()
        > 0
    )


def _granted_recipients(session: Session, document_id: str) -> list[str]:
    return [
        row.recipient_id
        for row in session.execute(
            select(RecipientGrant).where(
                RecipientGrant.document_id == document_id, RecipientGrant.revoked_at.is_(None)
            )
        ).scalars()
    ]


def _advance(
    session: Session, document: Document, target: str, actor_id: str, reason: str
) -> None:
    allowed = DocumentLifecycle.ALLOWED_TRANSITIONS.get(document.lifecycle_state, ())
    if target not in allowed:
        raise ForgeError(
            f"Cannot move {document.document_id} from {document.lifecycle_state} to {target}."
        )
    history = json.loads(document.lifecycle_history or "[]")
    history.append(
        {"from": document.lifecycle_state, "to": target, "at": _utcnow().isoformat(timespec="seconds"), "reason": reason}
    )
    document.lifecycle_state = target
    document.lifecycle_history = json.dumps(history)
    audit_service.record(
        session,
        actor_id=actor_id,
        action="DOCUMENT_LIFECYCLE_CHANGED",
        target_type="DOCUMENT",
        target_id=document.document_id,
        detail={"to": target, "reason": reason},
    )


def transition(
    session: Session, *, document_id: str, target: str, actor_id: str, reason: str
) -> dict[str, Any]:
    document = _require(session, document_id)
    if target == DocumentLifecycle.REVOKED:
        document.status = DocumentAccess.REVOKED
        document.revoked_at = _utcnow()
        from ..security import offline_grants as _offline_grants
        from ..security.revocation import record_revocation

        dead_leases = _offline_grants.revoke(
            session, document_id=document_id, actor_id=actor_id, reason=reason
        )
        record_revocation(
            session,
            subject_type="DOCUMENT",
            subject_id=document_id,
            scope="ALL",
            reason=reason,
            actor_id=actor_id,
            cascaded_to=[f"offline_grant:{gid}" for gid in dead_leases],
        )
    if target == DocumentLifecycle.EXPIRED:
        document.status = DocumentAccess.SUSPENDED
    _advance(session, document, target, actor_id, reason)
    return describe(session, document_id)


def suspend(session: Session, *, document_id: str, actor_id: str, reason: str) -> dict[str, Any]:
    document = _require(session, document_id)
    document.status = DocumentAccess.SUSPENDED
    document.suspended_at = _utcnow()
    audit_service.record(
        session,
        actor_id=actor_id,
        action="DOCUMENT_SUSPENDED",
        target_type="DOCUMENT",
        target_id=document_id,
        detail={"reason": reason},
    )
    return describe(session, document_id)


def _require(session: Session, document_id: str) -> Document:
    document = session.get(Document, document_id)
    if document is None:
        raise NotFound(f"No document {document_id}.")
    return document


def current_version(session: Session, document_id: str) -> DocumentVersion:
    document = _require(session, document_id)
    version = session.execute(
        select(DocumentVersion).where(
            DocumentVersion.document_id == document_id,
            DocumentVersion.version_number == document.current_version,
        )
    ).scalar_one_or_none()
    if version is None:
        raise NotFound(f"{document_id} has no version {document.current_version}.")
    return version


def version_by_number(session: Session, document_id: str, number: int) -> DocumentVersion | None:
    return session.execute(
        select(DocumentVersion).where(
            DocumentVersion.document_id == document_id, DocumentVersion.version_number == number
        )
    ).scalar_one_or_none()


def key_wrap_for(session: Session, version: DocumentVersion, recipient_id: str) -> encryption.KeyWrap | None:
    for raw in json.loads(version.key_wraps or "[]"):
        if raw["recipient_id"] == recipient_id:
            return encryption.KeyWrap.from_dict(raw)
    return None


def is_expired(document: Document) -> bool:
    return has_expired(document.access_expiry)


def sessions_used(session: Session, document_id: str) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(DecryptionSession)
            .where(
                DecryptionSession.document_id == document_id,
                DecryptionSession.status == "COMPLETED",
            )
        ).scalar_one()
    )


def list_documents(session: Session, *, unit: str | None = None) -> list[dict[str, Any]]:
    statement = select(Document).order_by(Document.document_id)
    if unit:
        statement = statement.where(Document.owning_unit == unit)
    return [summary(session, document) for document in session.execute(statement).scalars()]


def summary(session: Session, document: Document) -> dict[str, Any]:
    version = current_version(session, document.document_id)
    return {
        "document_id": document.document_id,
        "uuid": document.uuid,
        "title": document.title,
        "classification": document.classification,
        "classification_label": f"CLASSIFICATION: {document.classification.replace('_', ' ')}",
        "owner_id": document.owner_id,
        "owning_unit": document.owning_unit,
        "current_version": document.current_version,
        "status": document.status,
        "lifecycle_state": document.lifecycle_state,
        "current_version_sha256": version.content_sha256,
        "page_count": version.page_count,
        "size_bytes": version.size_bytes,
        "authorized_recipients": _granted_recipients(session, document.document_id),
        "created_at": document.created_at.isoformat(timespec="seconds"),
        "access_expiry": document.access_expiry.isoformat(timespec="seconds") if document.access_expiry else None,
        "sessions_used": sessions_used(session, document.document_id),
        "maximum_sessions": document.maximum_sessions,
    }


def describe(session: Session, document_id: str) -> dict[str, Any]:
    document = _require(session, document_id)
    versions = list(
        session.execute(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document_id)
            .order_by(DocumentVersion.version_number.desc())
        ).scalars()
    )
    history = list(
        session.execute(
            select(DecryptionSession)
            .where(DecryptionSession.document_id == document_id)
            .order_by(DecryptionSession.issued_at.desc())
            .limit(50)
        ).scalars()
    )
    leases = list(
        session.execute(
            select(OfflineGrant)
            .where(OfflineGrant.document_id == document_id)
            .order_by(OfflineGrant.granted_at.desc())
            .limit(50)
        ).scalars()
    )
    out = summary(session, document)
    out.update(
        {
            "policy": document.policy(),
            "policy_note": (
                "Prototype application-level labels only. These do not reproduce any official "
                "classification scheme and carry no certification."
            ),
            "mission_reference": document.mission_reference,
            "versions": [
                {
                    "version_id": v.version_id,
                    "version_number": v.version_number,
                    "label": v.label,
                    "content_sha256": v.content_sha256,
                    "size_bytes": v.size_bytes,
                    "page_count": v.page_count,
                    "classification": v.classification,
                    "is_current": v.is_current,
                    "created_at": v.created_at.isoformat(timespec="seconds"),
                    "created_by": v.created_by,
                    "encrypted": v.sealed_path is not None,
                    "key_wrap_algorithm": v.wrap_algorithm,
                    "recipient_key_wraps": len(json.loads(v.key_wraps or "[]")),
                }
                for v in versions
            ],
            "lifecycle_history": json.loads(document.lifecycle_history or "[]"),
            "access_history": [
                {
                    "session_id": s.session_id,
                    "recipient_id": s.recipient_id,
                    "device_id": s.device_id,
                    "version_number": s.version_number,
                    "issued_at": s.issued_at.isoformat(timespec="seconds"),
                    "completed_at": s.completed_at.isoformat(timespec="seconds") if s.completed_at else None,
                    "status": s.status,
                    "break_glass": s.is_break_glass,
                }
                for s in history
            ],
            "offline_grants": [
                {
                    "offline_grant_id": g.offline_grant_id,
                    "recipient_id": g.recipient_id,
                    "device_id": g.device_id,
                    "session_id": g.session_id,
                    "status": g.status,
                    "granted_at": g.granted_at.isoformat(timespec="seconds"),
                    "expires_at": g.expires_at.isoformat(timespec="seconds") if g.expires_at else None,
                    "closed_at": g.closed_at.isoformat(timespec="seconds") if g.closed_at else None,
                    "closed_reason": g.closed_reason,
                    "policy_version": g.policy_version,
                }
                for g in leases
            ],
            "crypto": encryption.crypto_note(),
            "persistent_protection": {
                "policy_receipt_on_every_copy": True,
                "travels_with_file": [
                    "embedded policy receipt (JSON) written at each decryption",
                    "classification and session stamps in document info",
                    "invisible forensic watermark",
                    "visible deterrent text where enabled",
                ],
                "limitation": protection.LIMITATION,
            },
            "location_policy": {
                "allowed_zones": json.loads(document.allowed_locations or "[]"),
                "zone_source": "X-Sentinel-Zone request header (declared trusted-zone identifier)",
                "every_decision_logged": True,
                "limitation": locations.LIMITATION,
            },
        }
    )
    return out


def purge_plaintext(session: Session, document_id: str, actor_id: str) -> dict[str, Any]:
    """Removes the pre-encryption working copy once a version is sealed.

    The sealed artefact and the decryption path no longer need it, and leaving
    plaintext lying next to the ciphertext weakens the at-rest story.
    """
    removed: list[str] = []
    for version in session.execute(
        select(DocumentVersion).where(DocumentVersion.document_id == document_id)
    ).scalars():
        if not version.sealed_path:
            continue
        target = Path(version.normalized_pdf_path)
        # The shared row goes too, or a sibling instance could re-materialise
        # the very plaintext this call just removed.
        shared_removed = shared_store.artefact_delete(target)
        if target.exists():
            target.unlink()
            removed.append(version.normalized_pdf_path)
        elif shared_removed:
            removed.append(version.normalized_pdf_path)
    audit_service.record(
        session,
        actor_id=actor_id,
        action="PLAINTEXT_WORKING_COPY_REMOVED",
        target_type="DOCUMENT",
        target_id=document_id,
        detail={"removed": removed},
    )
    return {"document_id": document_id, "removed": removed}


def copy_for_demo(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination
