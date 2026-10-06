from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .identity import utcnow


def new_uuid() -> str:
    import uuid

    return str(uuid.uuid4())


class Document(Base):
    __tablename__ = "documents"

    document_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(200))
    classification: Mapped[str] = mapped_column(String(24), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("recipients.recipient_id"), index=True)
    owning_unit: Mapped[str] = mapped_column(String(40), index=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)

    #: Access availability and lifecycle are tracked separately: a document can
    #: be ARCHIVED yet still have been ACTIVE when it leaked, and the forensic
    #: record must show which.
    status: Mapped[str] = mapped_column(String(20), default="SEALED", index=True)
    lifecycle_state: Mapped[str] = mapped_column(String(20), default="CREATED", index=True)

    policy_version: Mapped[str] = mapped_column(String(24))
    mission_reference: Mapped[str | None] = mapped_column(String(64), nullable=True)
    need_to_know_units: Mapped[str] = mapped_column(Text, default="[]")
    permitted_roles: Mapped[str] = mapped_column(Text, default="[]")

    #: Per-document usage-right overrides ({"PRINT": "DENY", ...}), layered on
    #: top of the classification defaults and the boolean columns below.
    rights: Mapped[str] = mapped_column(Text, default="{}")

    # ---- document access policy -------------------------------------------
    download_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    print_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    export_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    offline_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    #: How long one offline grant lasts once issued. 0 = no time cap beyond
    #: the document's own expiry; the right OFFLINE still gates every request.
    offline_max_hours: Mapped[int] = mapped_column(Integer, default=0)
    watermark_required: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Deterrent overlay (recipient/session/classification text) on each copy;
    #: separate from watermark_required, which governs the invisible layer.
    visible_watermark: Mapped[bool] = mapped_column(Boolean, default=True)
    #: JSON list of trusted zones the document may be decrypted from
    #: (["HQ-CAMPUS", ...]); "[]" = no zone restriction.
    allowed_locations: Mapped[str] = mapped_column(Text, default="[]")
    second_approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    access_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    maximum_sessions: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lifecycle_history: Mapped[str] = mapped_column(Text, default="[]")

    versions: Mapped[list["DocumentVersion"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )

    def policy(self) -> dict[str, object]:
        import json

        from ..core.rights import policy_matrix

        return {
            "document_id": self.document_id,
            "classification": self.classification,
            "permitted_roles": json.loads(self.permitted_roles or "[]"),
            "permitted_units": json.loads(self.need_to_know_units or "[]"),
            "need_to_know_units": json.loads(self.need_to_know_units or "[]"),
            "download_allowed": self.download_allowed,
            "print_allowed": self.print_allowed,
            "export_allowed": self.export_allowed,
            "offline_allowed": self.offline_allowed,
            "watermark_required": self.watermark_required,
            "visible_watermark": self.visible_watermark,
            "allowed_locations": json.loads(self.allowed_locations or "[]"),
            "second_approval_required": self.second_approval_required,
            "access_expiry": self.access_expiry.isoformat(timespec="seconds") if self.access_expiry else None,
            "maximum_sessions": self.maximum_sessions,
            "mission_reference": self.mission_reference,
            "policy_version": self.policy_version,
            **policy_matrix(self),
        }


class DocumentVersion(Base):
    """One immutable revision of the content. Forensics must be able to answer
    "which exact version leaked", so the content hash is bound to the version
    number and never overwritten."""

    __tablename__ = "document_versions"

    version_id: Mapped[str] = mapped_column(String(56), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=new_uuid)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.document_id"), index=True)
    version_number: Mapped[int] = mapped_column(Integer)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    page_count: Mapped[int] = mapped_column(Integer, default=1)
    normalized_pdf_path: Mapped[str] = mapped_column(Text)
    sealed_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Populated by the sealing step, which runs after the version row is
    #: created so the version id exists first.
    document_key_id: Mapped[str | None] = mapped_column(String(56), nullable=True)
    wrap_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_wraps: Mapped[str] = mapped_column(Text, default="[]")
    classification: Mapped[str] = mapped_column(String(24))
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)

    document: Mapped["Document"] = relationship(back_populates="versions")

    @property
    def label(self) -> str:
        return f"VERSION-{self.version_number:03d}"


class RecipientGrant(Base):
    """Need-to-know is granted per document, separately from clearance. A
    recipient with TOP_SECRET clearance is still refused a document they are not
    assigned to."""

    __tablename__ = "recipient_grants"

    grant_id: Mapped[str] = mapped_column(String(56), primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.document_id"), index=True)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    granted_by: Mapped[str] = mapped_column(String(32))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class OfflineGrant(Base):
    """One offline-access window: who, which device, until when, under which
    policy version. Rows are never deleted — they expire, get superseded by a
    later online session, or are revoked, and every one of those states stays
    visible for audit and forensics."""

    __tablename__ = "offline_grants"

    offline_grant_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.document_id"), index=True)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(48), index=True)
    session_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
