from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Recipient(Base):
    """A human or system identity. The cryptographic keys behind this identity
    live in the encrypted key vault, never in this table."""

    __tablename__ = "recipients"

    recipient_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    display_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(40), index=True)
    unit: Mapped[str] = mapped_column(String(80), index=True)
    clearance: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", index=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    password_salt: Mapped[str] = mapped_column(String(80))
    email: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    devices: Mapped[list["Device"]] = relationship(back_populates="recipient")

    def is_active(self) -> bool:
        return self.status == "ACTIVE"


class Device(Base):
    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    recipient_id: Mapped[str] = mapped_column(ForeignKey("recipients.recipient_id"), index=True)
    device_name: Mapped[str] = mapped_column(String(120))
    device_fingerprint: Mapped[str] = mapped_column(String(128))
    device_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", index=True)
    trust_state: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    trust_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trust_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attestation_note: Mapped[str] = mapped_column(
        Text,
        default=(
            "DEVELOPMENT LIMITATION: this fingerprint is asserted by the caller and is not "
            "hardware-attested. Production requires TPM-backed device identity."
        ),
    )

    recipient: Mapped["Recipient"] = relationship(back_populates="devices")


class KeyMetadata(Base):
    """Public half of a cryptographic key plus its lifecycle state. Secret key
    material is deliberately absent from this schema."""

    __tablename__ = "key_metadata"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    owner_id: Mapped[str] = mapped_column(String(32), index=True)
    purpose: Mapped[str] = mapped_column(String(16), index=True)
    algorithm: Mapped[str] = mapped_column(String(32))
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", index=True)
    public_key: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_devices_recipient_status", Device.recipient_id, Device.status)
