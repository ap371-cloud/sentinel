from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .identity import utcnow

ANALYSIS_TOOL = "sentinel-forensic-engine/1.0 (ML-DSA-65, ML-KEM-768, DCT spread-spectrum watermark)"


class LedgerNode(Base):
    """Registry and health view for one local ledger node. Each node keeps its
    own chain in its own database file, which is what makes single-node tamper
    detectable rather than merely improbable."""

    __tablename__ = "ledger_nodes"

    node_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    label: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16), default="ONLINE", index=True)
    last_block_height: Mapped[int] = mapped_column(Integer, default=0)
    last_block_hash: Mapped[str] = mapped_column(String(64), default="")
    last_merkle_root: Mapped[str] = mapped_column(String(64), default="")
    state_root: Mapped[str] = mapped_column(String(64), default="")
    integrity_status: Mapped[str] = mapped_column(String(24), default="UNVERIFIED", index=True)
    integrity_detail: Mapped[str] = mapped_column(Text, default="")
    signing_key_id: Mapped[str] = mapped_column(String(64), default="")
    public_key: Mapped[str] = mapped_column(Text, default="")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_result: Mapped[str] = mapped_column(String(32), default="NEVER_SYNCED")
    divergent_from_peers: Mapped[bool] = mapped_column(Boolean, default=False)
    pending_sync_count: Mapped[int] = mapped_column(Integer, default=0)


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    case_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    title: Mapped[str] = mapped_column(String(200))
    investigator_id: Mapped[str] = mapped_column(ForeignKey("recipients.recipient_id"), index=True)
    status: Mapped[str] = mapped_column(String(28), default="OPEN", index=True)
    suspected_document_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    suspected_version_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="[]")
    final_verification_status: Mapped[Optional[str]] = mapped_column(String(48), nullable=True)
    attributed_recipient_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    attributed_session_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    report_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    report_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence: Mapped[list["EvidenceItem"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class EvidenceItem(Base):
    """Chain of custody: who collected the artefact, who analysed it, when, with
    which tool version, and what came out."""

    __tablename__ = "evidence_items"

    evidence_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    case_id: Mapped[str] = mapped_column(ForeignKey("investigation_cases.case_id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    original_filename: Mapped[str] = mapped_column(String(200))
    stored_path: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)

    #: Hash of the pre-watermark original. A leaked copy is *expected* to differ
    #: from this, which is exactly why it cannot be used as an integrity check.
    original_document_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    matched_document_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    matched_version_id: Mapped[Optional[str]] = mapped_column(String(56), nullable=True)
    matched_version_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    extracted_watermark_tag: Mapped[Optional[str]] = mapped_column(String(24), nullable=True, index=True)
    watermark_confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    watermark_verdict: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    matched_watermark_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    matched_event_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    matched_session_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    matched_recipient_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    matched_device_id: Mapped[Optional[str]] = mapped_column(String(48), nullable=True)

    signature_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ledger_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    merkle_proof_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    chain_links: Mapped[str] = mapped_column(Text, default="[]")
    verification_status: Mapped[str] = mapped_column(String(48), default="PENDING", index=True)
    report_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    report_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    collected_by: Mapped[str] = mapped_column(String(32))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    analysed_by: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    analysed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    analysis_tool: Mapped[str] = mapped_column(Text, default=ANALYSIS_TOOL)
    limitations: Mapped[str] = mapped_column(Text, default="[]")

    case: Mapped["InvestigationCase"] = relationship(back_populates="evidence")
