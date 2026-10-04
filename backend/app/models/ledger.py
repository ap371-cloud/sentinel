from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, declarative_base, mapped_column

LedgerBase = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LedgerBlock(LedgerBase):
    """One block in a local node's chain. Append-only; there is no code path
    that updates or deletes a row in this table."""

    __tablename__ = "ledger_blocks"

    block_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    height: Mapped[int] = mapped_column(Integer, index=True)
    previous_block_hash: Mapped[str] = mapped_column(String(64))
    merkle_root: Mapped[str] = mapped_column(String(64), index=True)
    block_hash: Mapped[str] = mapped_column(String(64), index=True)
    #: Stored as text, not a datetime column. The block hash is computed over
    #: this exact string, and a datetime round-trip through SQLite drops the
    #: timezone offset, which would silently invalidate every stored hash.
    timestamp: Mapped[str] = mapped_column(Text)
    #: 32, not 16: the genesis block is proposed by "SENTINEL-CONSORTIUM", and
    #: SQLite ignores a declared length where PostgreSQL raises on overflow.
    proposer_id: Mapped[str] = mapped_column(String(32), index=True)
    certificate: Mapped[str] = mapped_column(Text, default="[]")
    signature_algorithm: Mapped[str] = mapped_column(String(32))
    block_signature: Mapped[str] = mapped_column(Text)
    signing_key_id: Mapped[str] = mapped_column(String(64))
    transaction_count: Mapped[int] = mapped_column(Integer, default=0)
    tx_ids: Mapped[str] = mapped_column(Text, default="[]")
    state_root: Mapped[str] = mapped_column(String(64))
    is_genesis: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class LedgerTransaction(LedgerBase):
    __tablename__ = "ledger_transactions"

    tx_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(48), index=True)
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    document_id: Mapped[str] = mapped_column(String(32), index=True)
    version_id: Mapped[str] = mapped_column(String(48), index=True)
    document_hash: Mapped[str] = mapped_column(String(64), index=True)
    watermark_tag: Mapped[str] = mapped_column(String(24), index=True)
    session_id: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[str] = mapped_column(Text)
    recipient_signature: Mapped[str] = mapped_column(Text)
    signature_algorithm: Mapped[str] = mapped_column(String(32))
    signing_key_id: Mapped[str] = mapped_column(String(64))
    tx_hash: Mapped[str] = mapped_column(String(64), index=True)
    committed_block_id: Mapped[Optional[str]] = mapped_column(String(48), nullable=True, index=True)
    merkle_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    submitted_by_node: Mapped[str] = mapped_column(String(16))


class LedgerVote(LedgerBase):
    __tablename__ = "ledger_votes"

    vote_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    block_id: Mapped[str] = mapped_column(String(48), index=True)
    node_id: Mapped[str] = mapped_column(String(16), index=True)
    height: Mapped[int] = mapped_column(Integer)
    block_hash: Mapped[str] = mapped_column(String(64))
    signature_algorithm: Mapped[str] = mapped_column(String(32))
    signature: Mapped[str] = mapped_column(Text)
    signing_key_id: Mapped[str] = mapped_column(String(64))
    voted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PendingTransaction(LedgerBase):
    """Queue used when the other nodes cannot be reached. Nothing is dropped;
    a queued transaction is replayed on reconnect and conflicts are recorded
    rather than overwritten."""

    __tablename__ = "pending_transactions"

    queue_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    tx_hash: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[str] = mapped_column(String(48), index=True)
    payload: Mapped[str] = mapped_column(Text)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    flushed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    conflict_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
