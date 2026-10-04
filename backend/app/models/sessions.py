from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base
from .identity import utcnow


class DecryptionSession(Base):
    """One authorized decryption attempt that succeeded. Every session is
    single-use, which is also the replay guard."""

    __tablename__ = "decryption_sessions"

    session_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.document_id"), index=True)
    version_id: Mapped[str] = mapped_column(String(48), index=True)
    version_number: Mapped[int] = mapped_column(Integer)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(48), index=True)
    request_nonce: Mapped[str] = mapped_column(String(64), unique=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    nonce: Mapped[str] = mapped_column(String(48))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)
    is_break_glass: Mapped[bool] = mapped_column(Boolean, default=False)
    break_glass_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    break_glass_approval_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_version: Mapped[str] = mapped_column(String(24))
    watermark_version: Mapped[str] = mapped_column(String(24))
    authorization_trace: Mapped[str] = mapped_column(Text, default="[]")


class Watermark(Base):
    """The registry of issued watermark tags. Deleting a row here would hide a
    leak, so every row is also anchored into the signed ledger event chain."""

    __tablename__ = "watermarks"

    watermark_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    session_id: Mapped[str] = mapped_column(ForeignKey("decryption_sessions.session_id"), index=True)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    document_id: Mapped[str] = mapped_column(String(32), index=True)
    version_id: Mapped[str] = mapped_column(String(48), index=True)
    document_hash: Mapped[str] = mapped_column(String(64), index=True)
    derivation_inputs_hash: Mapped[str] = mapped_column(String(64))
    tag: Mapped[str] = mapped_column(String(24), index=True)
    payload_bits: Mapped[int] = mapped_column(Integer)
    carriers_per_bit: Mapped[int] = mapped_column(Integer, default=256)
    watermark_version: Mapped[str] = mapped_column(String(24))
    policy_version: Mapped[str] = mapped_column(String(24))
    embedding_strength: Mapped[float] = mapped_column()
    psnr_db: Mapped[float | None] = mapped_column(nullable=True)
    ssim: Mapped[float | None] = mapped_column(nullable=True)
    output_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ledger_anchor_tx: Mapped[str | None] = mapped_column(String(48), nullable=True)


class DecryptionEvent(Base):
    """The signed, hash-chained record that anchors a decryption to a
    recipient's cryptographic identity."""

    __tablename__ = "decryption_events"

    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    event_type: Mapped[str] = mapped_column(String(40), default="DOCUMENT_DECRYPTED")
    session_id: Mapped[str] = mapped_column(String(40), index=True)
    watermark_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    document_id: Mapped[str] = mapped_column(String(32), index=True)
    version_id: Mapped[str] = mapped_column(String(48), index=True)
    version_number: Mapped[int] = mapped_column(Integer)
    document_hash: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(48))
    watermark_tag: Mapped[str] = mapped_column(String(24))
    signing_key_id: Mapped[str] = mapped_column(String(64))
    signature_algorithm: Mapped[str] = mapped_column(String(32))
    signature: Mapped[str] = mapped_column(Text)
    payload: Mapped[str] = mapped_column(Text)
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    prev_event_hash: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ledger_tx_id: Mapped[str | None] = mapped_column(String(48), nullable=True, index=True)
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)


class RequestNonce(Base):
    """Server-issued single-use nonces. A replayed decryption request fails
    because its nonce is already consumed."""

    __tablename__ = "request_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    document_id: Mapped[str] = mapped_column(String(32))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
