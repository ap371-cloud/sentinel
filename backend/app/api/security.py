from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Role, Severity
from ..core.exceptions import NotFound
from ..core.timeutil import utcnow
from ..models.identity import Recipient
from ..models.security import Incident, SecurityEvent
from ..security import anomaly_detection, attack_lab, incident_engine, lockdown
from ..services import ai_service, approval_service, audit_service, command_service
from .deps import current_recipient, db, permitted, readable

router = APIRouter(tags=["security", "incidents", "commander", "approvals", "ai", "audit"])


# ---- security events and incidents -----------------------------------------


@router.get("/security-events")
def security_events(
    session: Session = Depends(db),
    _: Recipient = Depends(readable("incident.manage")),
    limit: int = 50,
    minimum_severity: str | None = None,
) -> dict[str, Any]:
    return {
        "events": incident_engine.recent(session, limit=min(limit, 200), minimum_severity=minimum_severity),
        "counts_by_severity": incident_engine.counts_by_severity(session),
        "open_count": incident_engine.open_count(session),
        "severity_levels": list(Severity.ORDER),
    }


class AcknowledgeRequest(BaseModel):
    note: str = Field(min_length=3, max_length=400)


@router.post("/security-events/{event_id}/acknowledge")
def acknowledge(
    event_id: str,
    payload: AcknowledgeRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("incident.manage")),
) -> dict[str, Any]:
    if not incident_engine.acknowledge(session, event_id, officer.recipient_id):
        from ..core.exceptions import NotFound

        raise NotFound(f"No security event {event_id}.")
    audit_service.record(
        session,
        actor_id=officer.recipient_id,
        action="SECURITY_EVENT_ACKNOWLEDGED",
        target_type="SECURITY_EVENT",
        target_id=event_id,
        detail={"note": payload.note},
    )
    return {"security_event_id": event_id, "acknowledged_by": officer.recipient_id, "note": payload.note}


class IncidentRequest(BaseModel):
    security_event_id: str
    title: str = Field(min_length=5, max_length=200)
    recommended_response: list[str] = Field(default_factory=list)


@router.post("/incidents")
def open_incident(
    payload: IncidentRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(permitted("incident.manage")),
) -> dict[str, Any]:
    """Promotes a detected security event into an owned, tracked incident with
    a timeline and a recommended response."""
    event = session.get(SecurityEvent, payload.security_event_id)
    if event is None:
        raise NotFound(f"No security event {payload.security_event_id}.")

    now = utcnow().isoformat(timespec="seconds")
    sequence = int(
        session.execute(select(func.count()).select_from(Incident)).scalar_one()
    ) + 1
    incident = Incident(
        incident_id=f"INC-{utcnow().year}-{sequence:03d}",
        title=payload.title,
        severity=event.severity,
        category=event.category,
        what_happened=event.what_happened,
        why_it_matters=event.why_it_matters,
        evidence=event.detail,
        affected_resources=json.dumps(
            [value for value in (event.document_id, event.subject_id, event.session_id) if value]
        ),
        recommended_response=json.dumps(payload.recommended_response),
        timeline=json.dumps(
            [
                {
                    "at": event.detected_at.isoformat(timespec="seconds"),
                    "stage": "ALERT CREATED",
                    "detail": f"{event.severity} — {event.title}",
                },
                {
                    "at": now,
                    "stage": "EVIDENCE PRESERVED",
                    "detail": "Source records and hashes preserved; no destructive action taken.",
                },
                {"at": now, "stage": "INVESTIGATION REQUIRED", "detail": "Awaiting authorised review."},
            ]
        ),
        linked_event_id=event.security_event_id,
        owner_id=officer.recipient_id,
    )
    session.add(incident)
    event.promoted_to_incident = incident.incident_id
    session.flush()
    return {"incident": describe_incident(incident)}


def describe_incident(incident: Incident) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "category": incident.category,
        "what_happened": incident.what_happened,
        "why_it_matters": incident.why_it_matters,
        "affected_resources": incident.resources(),
        "recommended_response": incident.response_plan(),
        "timeline": incident.chain_of_events(),
        "linked_event_id": incident.linked_event_id,
        "linked_case_id": incident.linked_case_id,
        "owner_id": incident.owner_id,
        "opened_at": incident.opened_at.isoformat(timespec="seconds"),
        "closed_at": incident.closed_at.isoformat(timespec="seconds") if incident.closed_at else None,
    }


@router.get("/incidents")
def incidents(session: Session = Depends(db), _: Recipient = Depends(readable("incident.manage"))) -> dict[str, Any]:
    rows = session.execute(select(Incident).order_by(Incident.opened_at.desc()).limit(100)).scalars()
    return {"incidents": [describe_incident(row) for row in rows]}


# ---- lockdown ---------------------------------------------------------------


class LockdownRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=600)
    approval_id: str | None = None


@router.post("/lockdown")
def engage_lockdown(
    payload: LockdownRequest,
    session: Session = Depends(db),
    commander: Recipient = Depends(permitted("security.lockdown")),
) -> dict[str, Any]:
    """Emergency lockdown.

    Blocks new sensitive operations and requires elevated approval, while every
    existing record stays intact. Lockdown never deletes evidence and never
    creates a hidden bypass: releasing it also requires two people.
    """
    if payload.approval_id:
        approval_service.consume(
            session,
            approval_id=payload.approval_id,
            acting_role=commander.role,
            expected_action="EMERGENCY_ACCESS",
        )
    result = lockdown.activate(session, actor_id=commander.recipient_id, reason=payload.reason)
    audit_service.record(
        session,
        actor_id=commander.recipient_id,
        action="LOCKDOWN_ACTIVATED",
        target_type="SYSTEM",
        target_id="GLOBAL",
        detail={"reason": payload.reason},
    )
    incident_engine.raise_event(
        session,
        "LOCKDOWN",
        title="Emergency lockdown engaged",
        what_happened=f"{commander.recipient_id} engaged emergency lockdown. Reason: {payload.reason}",
        why_it_matters="New sensitive operations are blocked until the situation is reviewed.",
        what_was_affected="all document decryption",
        recommended_action="Review the triggering incident, then release the lockdown with two-person approval.",
        severity="HIGH",
        actor_id=commander.recipient_id,
    )
    return result


@router.post("/unlock")
def release_lockdown(
    payload: LockdownRequest,
    session: Session = Depends(db),
    commander: Recipient = Depends(permitted("security.lockdown")),
) -> dict[str, Any]:
    """Releasing a lockdown requires two authorised identities, so an attacker
    who manages to engage one cannot also quietly release it."""
    approval = approval_service.consume(
        session,
        approval_id=payload.approval_id or "",
        acting_role=commander.role,
    )
    result = lockdown.release(session, actor_id=commander.recipient_id, reason=payload.reason)
    audit_service.record(
        session,
        actor_id=commander.recipient_id,
        action="LOCKDOWN_RELEASED",
        target_type="SYSTEM",
        target_id="GLOBAL",
        detail={"reason": payload.reason, "approval_id": approval.approval_id},
    )
    return result


@router.get("/lockdown")
def lockdown_status(session: Session = Depends(db), _: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return lockdown.describe(session)


# ---- two-person approvals ---------------------------------------------------


class ApprovalRequestBody(BaseModel):
    action: str = Field(min_length=4, max_length=48)
    justification: str = Field(min_length=10, max_length=1000)
    subject_id: str | None = None
    required_approvals: int = Field(default=2, ge=2, le=3)


@router.post("/approvals")
def create_approval(
    payload: ApprovalRequestBody,
    session: Session = Depends(db),
    requester: Recipient = Depends(current_recipient),
) -> dict[str, Any]:
    """One person's word is never enough. The request stays inert until a
    different, separately authenticated identity approves it."""
    return approval_service.request(
        session,
        action=payload.action,
        requested_by=requester.recipient_id,
        justification=payload.justification,
        subject_id=payload.subject_id,
        required_approvals=payload.required_approvals,
    )


class DecisionBody(BaseModel):
    reason: str = Field(min_length=3, max_length=600)


@router.post("/approvals/{approval_id}/approve")
def approve(
    approval_id: str,
    payload: DecisionBody,
    session: Session = Depends(db),
    approver: Recipient = Depends(permitted("approval.decide")),
) -> dict[str, Any]:
    result = approval_service.approve(
        session,
        approval_id=approval_id,
        approver_id=approver.recipient_id,
        approver_role=approver.role,
    )
    result["reason"] = payload.reason
    return result


@router.post("/approvals/{approval_id}/reject")
def reject(
    approval_id: str,
    payload: DecisionBody,
    session: Session = Depends(db),
    approver: Recipient = Depends(permitted("approval.decide")),
) -> dict[str, Any]:
    return approval_service.reject(
        session,
        approval_id=approval_id,
        approver_id=approver.recipient_id,
        approver_role=approver.role,
        reason=payload.reason,
    )


@router.get("/approvals")
def approvals(
    session: Session = Depends(db), _: Recipient = Depends(current_recipient), status: str | None = None
) -> dict[str, Any]:
    return {
        "approvals": approval_service.list_requests(session, status=status),
        "high_risk_actions": approval_service.high_risk_actions(session),
        "approver_roles": list(Role.APPROVERS),
        "plain_explanation": (
            "The identity that raises a request can never be one of the approvers, and an approval is "
            "single-use."
        ),
    }


class BreakGlassRequest(BaseModel):
    document_id: str
    reason: str = Field(min_length=15, max_length=1000)


@router.post("/approvals/break-glass")
def break_glass(
    payload: BreakGlassRequest,
    session: Session = Depends(db),
    requester: Recipient = Depends(current_recipient),
) -> dict[str, Any]:
    """Emergency access that bypasses a normal authorisation rule.

    There is no hidden administrator override: the request needs two approvers,
    the resulting decryption is watermarked and signed like any other, and the
    event is flagged for mandatory post-event review.
    """
    return approval_service.request_break_glass(
        session,
        recipient_id=requester.recipient_id,
        document_id=payload.document_id,
        reason=payload.reason,
    )


# ---- command dashboards -----------------------------------------------------


@router.get("/commander/dashboard")
def commander_dashboard(session: Session = Depends(db), _: Recipient = Depends(readable("commander.dashboard"))) -> dict[str, Any]:
    return command_service.commander_dashboard(session)


@router.get("/commander/system-status")
def system_status(session: Session = Depends(db), _: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return command_service.system_status(session)


@router.get("/commander/posture")
def posture(session: Session = Depends(db), _: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return command_service.security_posture(session)


@router.get("/commander/topology")
def topology(session: Session = Depends(db), _: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return {"components": command_service.system_topology(session)}


@router.get("/commander/roles")
def role_matrix(_: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return command_service.role_matrix()


@router.get("/commander/classifications")
def classifications(_: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return {"levels": command_service.clearance_ladder()}


@router.get("/commander/anomaly-rules")
def anomaly_rules(session: Session = Depends(db), _: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return command_service.anomaly_catalogue(session)


@router.get("/commander/watermark-engine")
def watermark_engine(session: Session = Depends(db), _: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return command_service.watermark_engine_status(session)


@router.get("/audit")
def audit(session: Session = Depends(db), _: Recipient = Depends(readable("audit.read")), limit: int = 60) -> dict[str, Any]:
    """Privileged-action trail. Append-only and hash-chained, so removing an
    entry breaks the chain instead of hiding it."""
    return command_service.audit_trail(session, limit=min(limit, 300))


# ---- local AI (optional) ----------------------------------------------------


@router.get("/ai/health")
def ai_health(_: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    """Never raises. A missing local model is reported, not propagated."""
    return ai_service.health()


class AiBriefRequest(BaseModel):
    limit: int = Field(default=12, ge=1, le=50)


@router.post("/ai/briefing")
def ai_briefing(
    payload: AiBriefRequest,
    session: Session = Depends(db),
    _: Recipient = Depends(readable("commander.dashboard")),
) -> dict[str, Any]:
    """Narrative over already-verified dashboard state.

    The model never participates in an authorisation, signature, ledger or
    forensic decision, and its output is labelled as advisory.
    """
    dashboard = command_service.commander_dashboard(session)
    return {
        "briefing": ai_service.commander_briefing(dashboard),
        "deterministic_state": {
            "system_security_status": dashboard["system_security_status"],
            "posture": dashboard["security_posture"]["score"],
            "ledger_integrity": dashboard["ledger_health"]["headline"],
        },
    }


class AiEventRequest(BaseModel):
    security_event_id: str


@router.post("/ai/explain-event")
def ai_explain_event(
    payload: AiEventRequest,
    session: Session = Depends(db),
    _: Recipient = Depends(permitted("incident.manage")),
) -> dict[str, Any]:
    event = session.get(SecurityEvent, payload.security_event_id)
    if event is None:
        from ..core.exceptions import NotFound

        raise NotFound(f"No security event {payload.security_event_id}.")
    return {
        "explanation": ai_service.summarise_incident(incident_engine.describe(event)),
        "deterministic_verdict": {
            "category": event.category,
            "severity": event.severity,
            "recommended_action": event.recommended_action,
        },
    }


@router.get("/ai/clusters")
def ai_clusters(
    session: Session = Depends(db), _: Recipient = Depends(current_recipient), limit: int = 40
) -> dict[str, Any]:
    """Clustering is deterministic and computed locally; the language model is
    never able to change cluster membership."""
    return ai_service.cluster_events(incident_engine.recent(session, limit=min(limit, 200)))


# ---- attack simulation lab --------------------------------------------------


@router.get("/security-lab/scenarios")
def scenarios(_: Recipient = Depends(current_recipient)) -> dict[str, Any]:
    return {
        "environment": "DEMO SECURITY LAB",
        "scenarios": attack_lab.SCENARIO_CATALOGUE,
        "disclaimer": (
            "Each scenario invokes the real backend path for that attack. Detection results are "
            "whatever the system concluded, not a scripted outcome."
        ),
    }


class SimulateRequest(BaseModel):
    scenario: str


@router.post("/security-lab/simulate")
def simulate(
    payload: SimulateRequest,
    session: Session = Depends(db),
    officer: Recipient = Depends(readable("incident.manage")),
) -> dict[str, Any]:
    return attack_lab.run(payload.scenario, session)


class DemonstrateRequest(BaseModel):
    include_attacks: bool = True


@router.post("/commander/demonstration")
def demonstration(
    payload: DemonstrateRequest,
    session: Session = Depends(db),
    _: Recipient = Depends(permitted("commander.dashboard")),
) -> dict[str, Any]:
    """One call that returns the whole command picture plus, optionally, the
    live results of every defensive simulation."""
    dashboard = command_service.commander_dashboard(session)
    result: dict[str, Any] = {
        "system_security_status": dashboard["system_security_status"],
        "posture": dashboard["security_posture"],
        "ledger": dashboard["ledger_health"],
        "watermark_engine": dashboard["watermark_engine"],
        "kpis": dashboard["kpis"],
        "attribution_statement": dashboard["attribution_statement"],
    }
    if payload.include_attacks:
        outcomes = {}
        for key in ("ledger_tampering", "signature_forgery", "replay_attack", "watermark_corruption"):
            outcomes[key] = attack_lab.run(key, session)
        result["attack_outcomes"] = outcomes
        result["all_attacks_detected"] = all(o["detected"] for o in outcomes.values())
    return result
