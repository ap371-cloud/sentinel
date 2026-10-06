from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base
from .identity import utcnow


class Policy(Base):
    __tablename__ = "policies"

    policy_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    policy_version: Mapped[str] = mapped_column(String(24), index=True)
    name: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    device_access_policy: Mapped[str] = mapped_column(String(32), default="ALLOW")
    replay_window_seconds: Mapped[int] = mapped_column(Integer, default=45)
    break_glass_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    high_risk_actions: Mapped[str] = mapped_column(Text, default="[]")
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    updated_by: Mapped[str] = mapped_column(String(32))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    change_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    #: sha256 over the enforced config; stored at creation so a later edit to
    #: the row itself becomes visible against the recorded digest.
    policy_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class ApprovalRequest(Base):
    """Two-person control. A request stays inert until the required number of
    distinct identities approve it, and the requester can never be one of
    them."""

    __tablename__ = "approval_requests"

    approval_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    action: Mapped[str] = mapped_column(String(48), index=True)
    subject_id: Mapped[Optional[str]] = mapped_column(String(56), nullable=True)
    justification: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(32), index=True)
    required_approvals: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approvals: Mapped[str] = mapped_column(Text, default="[]")
    rejections: Mapped[str] = mapped_column(Text, default="[]")
    #: The policy version in force when the request was raised, so a decision
    #: can never be read against a later policy than the one it faced.
    policy_version: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)

    def approver_ids(self) -> list[str]:
        return json.loads(self.approvals or "[]")

    def rejector_ids(self) -> list[str]:
        return json.loads(self.rejections or "[]")

    def counted_approvals(self) -> set[str]:
        return set(self.approver_ids()) - {self.requested_by}

    def is_satisfied(self) -> bool:
        return len(self.counted_approvals()) >= self.required_approvals

    def is_expired(self, moment: datetime) -> bool:
        from ..core.timeutil import as_utc

        return as_utc(moment) > as_utc(self.expires_at)


class Incident(Base):
    """A security event promoted into something with an owner, a timeline and a
    recommended response. Never deleted; closed instead."""

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(12), index=True)
    status: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    what_happened: Mapped[str] = mapped_column(Text)
    why_it_matters: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    affected_resources: Mapped[str] = mapped_column(Text, default="[]")
    recommended_response: Mapped[str] = mapped_column(Text, default="[]")
    timeline: Mapped[str] = mapped_column(Text, default="[]")
    linked_event_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    linked_case_id: Mapped[Optional[str]] = mapped_column(String(24), nullable=True, index=True)
    owner_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def chain_of_events(self) -> list[dict[str, object]]:
        return json.loads(self.timeline or "[]")

    def resources(self) -> list[str]:
        return json.loads(self.affected_resources or "[]")

    def response_plan(self) -> list[str]:
        return json.loads(self.recommended_response or "[]")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    security_event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: __import__("uuid").uuid4().hex)
    category: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(12), index=True)
    title: Mapped[str] = mapped_column(String(200))
    plain_explanation: Mapped[str] = mapped_column(Text)
    what_happened: Mapped[str] = mapped_column(Text)
    why_it_matters: Mapped[str] = mapped_column(Text)
    what_was_affected: Mapped[str] = mapped_column(Text, default="")
    recommended_action: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    subject_id: Mapped[Optional[str]] = mapped_column(String(56), nullable=True, index=True)
    document_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)
    promoted_to_incident: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="{}")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditRecord(Base):
    """Append-only, hash-chained privileged-action log. Separate from the ledger
    so an operator who compromises the ledger still cannot forge the
    administrative history."""

    __tablename__ = "audit_records"

    audit_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(32), index=True)
    actor_role: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[Optional[str]] = mapped_column(String(56), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), default="SUCCESS")
    detail: Mapped[str] = mapped_column(Text, default="{}")
    record_hash: Mapped[str] = mapped_column(String(64), index=True)
    prev_record_hash: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    #: Query-first copies of fields the detail payload also carries. Old rows
    #: leave these NULL, which keeps their recorded hash intact; the hash of a
    #: new row covers whichever of these is populated.
    device_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    document_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    document_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)
    policy_version: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)


class SystemState(Base):
    __tablename__ = "system_state"

    state_id: Mapped[str] = mapped_column(String(8), primary_key=True, default="GLOBAL")
    lockdown_active: Mapped[bool] = mapped_column(Boolean, default=False)
    lockdown_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lockdown_activated_by: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    lockdown_activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    air_gap_violation: Mapped[bool] = mapped_column(Boolean, default=False)
    air_gap_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    #: Set by the attack lab and the demo to prove the platform keeps working
    #: with no peers reachable.
    network_partitioned: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnomalyObservation(Base):
    """Rule-based anomaly counters. Explainable rules first; the schema leaves
    room for a later statistical model without changing any caller."""

    __tablename__ = "anomaly_observations"

    observation_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    rule: Mapped[str] = mapped_column(String(48), index=True)
    subject_id: Mapped[Optional[str]] = mapped_column(String(56), nullable=True, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    window_seconds: Mapped[int] = mapped_column(Integer)
    observed_value: Mapped[int] = mapped_column(Integer)
    threshold: Mapped[int] = mapped_column(Integer)
    triggered: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    explanation: Mapped[str] = mapped_column(Text)
    baseline: Mapped[str] = mapped_column(Text, default="{}")
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Revocation(Base):
    """Append-only register of every withdrawal of authority. Deleting a row
    here is exactly what the design forbids."""

    __tablename__ = "revocations"

    revocation_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(24), index=True)
    subject_id: Mapped[str] = mapped_column(String(56), index=True)
    scope: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    revoked_by: Mapped[str] = mapped_column(String(32), index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    cascaded_to: Mapped[str] = mapped_column(Text, default="[]")
    history_preserved: Mapped[bool] = mapped_column(Boolean, default=True)
    policy_version: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)


class BackupRecord(Base):
    __tablename__ = "backup_records"

    backup_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    path: Mapped[str] = mapped_column(Text)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    file_count: Mapped[int] = mapped_column(Integer)
    size_bytes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="CREATED", index=True)
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
