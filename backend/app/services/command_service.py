from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import SETTINGS, Clearance, ForensicOutcome, Role, Severity
from ..core.permissions import PERMISSIONS, separation_of_duties_report
from ..core.security import EGRESS
from ..crypto.key_management import VAULT
from ..crypto.pqc import PQC
from ..ledger.chain import NETWORK
from ..models.documents import Document
from ..models.forensic import EvidenceItem, InvestigationCase, LedgerNode
from ..models.identity import Device, KeyMetadata, Recipient
from ..models.security import AnomalyObservation, ApprovalRequest, SecurityEvent
from ..models.sessions import DecryptionSession, Watermark
from ..security import anomaly_detection, incident_engine, lockdown
from . import audit_service, decryption_service


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def system_status(session: Session) -> dict[str, Any]:
    described = lockdown.describe(session)
    ledger = NETWORK.verify()
    return {
        **described,
        "ledger_integrity": ledger["headline"],
        "air_gap": EGRESS.status(),
        "post_quantum": PQC.describe(),
    }


def commander_dashboard(session: Session) -> dict[str, Any]:
    documents_total = int(session.execute(select(func.count()).select_from(Document)).scalar_one())
    recipients = session.execute(
        select(Recipient.status, func.count()).group_by(Recipient.status)
    ).all()
    recipient_counts = {status: count for status, count in recipients}
    active_sessions = int(
        session.execute(
            select(func.count())
            .select_from(DecryptionSession)
            .where(DecryptionSession.status == "COMPLETED")
        ).scalar_one()
    )
    open_events = int(
        session.execute(
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.status == "OPEN")
        ).scalar_one()
    )
    severity_counts = {
        row[0]: row[1]
        for row in session.execute(
            select(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity)
        ).all()
    }
    open_cases = int(
        session.execute(
            select(func.count())
            .select_from(InvestigationCase)
            .where(InvestigationCase.status.in_(("OPEN", "UNDER_INVESTIGATION")))
        ).scalar_one()
    )
    verified_evidence = int(
        session.execute(
            select(func.count())
            .select_from(EvidenceItem)
            .where(EvidenceItem.verification_status == ForensicOutcome.VERIFIED_ASSOCIATION)
        ).scalar_one()
    )
    pending_approvals = int(
        session.execute(
            select(func.count())
            .select_from(ApprovalRequest)
            .where(ApprovalRequest.status == "PENDING")
        ).scalar_one()
    )

    status = lockdown.describe(session)
    ledger_status = NETWORK.verify()
    posture = security_posture(session)

    if status["system_status"] == "EMERGENCY LOCKDOWN":
        headline = "EMERGENCY LOCKDOWN"
    elif "TAMPER DETECTED" in ledger_status["headline"]:
        headline = "WARNING"
    elif severity_counts.get(Severity.CRITICAL, 0) > 0:
        headline = "HIGH RISK"
    elif severity_counts.get(Severity.HIGH, 0) > 0 or status["air_gap_violation"]:
        headline = "WARNING"
    else:
        headline = "NORMAL"

    return {
        "system_security_status": headline,
        "kpis": {
            "documents_protected": documents_total,
            "active_recipients": recipient_counts.get("ACTIVE", 0),
            "revoked_recipients": recipient_counts.get("REVOKED", 0),
            "suspended_recipients": recipient_counts.get("SUSPENDED", 0),
            "active_sessions": active_sessions,
            "registered_devices": int(session.execute(select(func.count()).select_from(Device)).scalar_one()),
            "revoked_devices": int(
                session.execute(
                    select(func.count()).select_from(Device).where(Device.status == "REVOKED")
                ).scalar_one()
            ),
            "security_events_open": open_events,
            "critical_incidents": severity_counts.get(Severity.CRITICAL, 0),
            "high_incidents": severity_counts.get(Severity.HIGH, 0),
            "watermarks_issued": int(
                session.execute(select(func.count()).select_from(Watermark)).scalar_one()
            ),
            "open_investigations": open_cases,
            "verified_evidence": verified_evidence,
            "pending_approvals": pending_approvals,
        },
        "security_posture": posture,
        "ledger_health": {
            "headline": ledger_status["headline"],
            "agreement": ledger_status["agreement"]["status"],
            "nodes": ledger_status["nodes"],
            "quorum_size": ledger_status["quorum_size"],
        },
        "live_security_events": incident_engine.recent(session, limit=12),
        "recent_decryptions": decryption_service.list_sessions(session, limit=10),
        "recent_investigations": [
            {
                "case_id": case.case_id,
                "title": case.title,
                "status": case.status,
                "final_verification_status": case.final_verification_status,
                "created_at": case.created_at.isoformat(timespec="seconds"),
            }
            for case in session.execute(
                select(InvestigationCase).order_by(InvestigationCase.created_at.desc()).limit(5)
            ).scalars()
        ],
        "watermark_engine": watermark_engine_status(session),
        "air_gap": EGRESS.status(),
        "post_quantum": PQC.describe(),
        "key_vault": VAULT.storage_report(),
        "topology": system_topology(session),
        "attribution_statement": (
            "A verified association links a leaked copy to an authorised decryption session. It does "
            "not establish which individual physically released the material."
        ),
    }


def watermark_engine_status(session: Session) -> dict[str, Any]:
    rows = list(session.execute(select(Watermark).order_by(Watermark.watermark_id.desc()).limit(200)).scalars())
    unique_tags = len({row.tag for row in rows})
    psnr_values = [row.psnr_db for row in rows if row.psnr_db is not None]
    ssim_values = [row.ssim for row in rows if row.ssim is not None]
    return {
        "status": "ACTIVE" if rows else "IDLE",
        "watermarks_issued": len(rows),
        "unique_tags": unique_tags,
        "uniqueness_holds": unique_tags == len(rows),
        "mean_psnr_db": round(sum(psnr_values) / len(psnr_values), 2) if psnr_values else None,
        "mean_ssim": round(sum(ssim_values) / len(ssim_values), 4) if ssim_values else None,
        "embedding": "Mid-frequency 8x8 DCT spread spectrum, keyed carriers, repetition redundancy",
        "derivation": "HMAC-SHA256 over recipient, document, document hash, session, nonce and versions",
        "extraction": "Blind keyed correlation; the original document is not required",
        "payload_bits": rows[0].payload_bits if rows else None,
        "carriers_per_bit": rows[0].carriers_per_bit if rows else None,
        "watermark_version": SETTINGS.watermark_version,
    }


def system_topology(session: Session) -> list[dict[str, Any]]:
    ledger = NETWORK.status()
    ai = _ai_topology()
    components = [
        ("COMMANDER TERMINAL", "ONLINE", "Command dashboard and incident review"),
        ("IDENTITY SERVICE", "ONLINE", "Local authentication and cryptographic identities"),
        ("POLICY ENGINE", "ONLINE", "Deterministic RBAC and attribute evaluation"),
        ("DEVICE TRUST", "ONLINE", "Registered device and trust-state checks"),
        ("DOCUMENT SERVICE", "ONLINE", "Versioning, classification and sealing"),
        ("CRYPTO SERVICE", "ONLINE" if PQC.available else "WARNING", "ML-KEM-768 and ML-DSA-65 via pqcrypto"),
        ("WATERMARK ENGINE", "ONLINE", "Session-specific invisible forensic marking"),
        ("FORENSIC ENGINE", "ONLINE", "Blind extraction and evidence-chain verification"),
        ("INCIDENT ENGINE", "ONLINE", "Rule-based detection and recommended response"),
        ("LOCAL AI (OPTIONAL)", ai["status"], ai["detail"]),
    ]
    topology = [
        {"component": name, "status": status, "purpose": purpose}
        for name, status, purpose in components
    ]
    for node in ledger["nodes"]:
        topology.append(
            {
                "component": f"LEDGER {node['node_id']}",
                "status": node["status"],
                "purpose": f"Permissioned ledger replica at height {node['block_height']}",
            }
        )
    return topology


def _ai_topology() -> dict[str, str]:
    from . import ai_service

    health = ai_service.health()
    return {
        "status": "ONLINE" if health["available"] else "OFFLINE",
        "detail": (
            "Ollama summarisation available. Analysis only; never a security decision input."
            if health["available"]
            else "AI SERVICE OFFLINE — deterministic security systems unaffected"
        ),
    }


def security_posture(session: Session) -> dict[str, Any]:
    """A transparent operational indicator.

    This is not a certified rating. Every factor is listed with its measured
    value so an operator can see exactly why the number moved.
    """
    ledger = NETWORK.verify()
    node_health = {v["node_id"]: v["status"] for v in ledger["nodes"]}
    reachable = sum(1 for status in node_health.values() if status == "VERIFIED")

    critical = int(
        session.execute(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.severity == Severity.CRITICAL, SecurityEvent.status == "OPEN")
        ).scalar_one()
    )
    high = int(
        session.execute(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.severity == Severity.HIGH, SecurityEvent.status == "OPEN")
        ).scalar_one()
    )
    revoked_identities = int(
        session.execute(
            select(func.count()).select_from(Recipient).where(Recipient.status == "REVOKED")
        ).scalar_one()
    )
    compromised_devices = int(
        session.execute(
            select(func.count())
            .select_from(Device)
            .where(Device.trust_state.in_(("SUSPICIOUS", "COMPROMISED")))
        ).scalar_one()
    )
    active_keys = int(
        session.execute(
            select(func.count()).select_from(KeyMetadata).where(KeyMetadata.status == "ACTIVE")
        ).scalar_one()
    )
    unusable_keys = int(
        session.execute(
            select(func.count())
            .select_from(KeyMetadata)
            .where(KeyMetadata.status.in_(("REVOKED", "EXPIRED")))
        ).scalar_one()
    )
    unresolved_cases = int(
        session.execute(
            select(func.count())
            .select_from(InvestigationCase)
            .where(InvestigationCase.status.in_(("OPEN", "UNDER_INVESTIGATION", "INCONCLUSIVE")))
        ).scalar_one()
    )
    auth_anomalies = int(
        session.execute(
            select(func.count())
            .select_from(AnomalyObservation)
            .where(AnomalyObservation.triggered.is_(True))
        ).scalar_one()
    )
    pending_sync = NETWORK.status()["pending_sync_total"]

    factors = [
        {
            "factor": "Identity health",
            "value": max(0, 100 - (revoked_identities * 8) - (critical * 10)),
            "detail": f"{revoked_identities} revoked identities, {critical} open critical events",
        },
        {
            "factor": "Device health",
            "value": max(0, 100 - (compromised_devices * 20)),
            "detail": f"{compromised_devices} devices flagged suspicious or compromised",
        },
        {
            "factor": "Key health",
            "value": max(0, 100 - (unusable_keys * 10)),
            "detail": f"{active_keys} active keys, {unusable_keys} withdrawn",
        },
        {
            "factor": "Ledger integrity",
            "value": 100 if reachable == len(node_health) else max(0, 60 * reachable // max(1, len(node_health))),
            "detail": f"{reachable}/{len(node_health)} nodes verified; {ledger['agreement']['status']}",
        },
        {
            "factor": "Node availability",
            "value": int(100 * reachable / max(1, len(node_health))),
            "detail": f"quorum size {NETWORK.quorum_size} of {len(NETWORK.node_ids)}",
        },
        {
            "factor": "Incident load",
            "value": max(0, 100 - (critical * 15) - (high * 7)),
            "detail": f"{critical} critical, {high} high open events",
        },
        {
            "factor": "Authentication anomalies",
            "value": max(0, 100 - (auth_anomalies * 10)),
            "detail": f"{auth_anomalies} anomaly rule triggers recorded",
        },
        {
            "factor": "Investigation backlog",
            "value": max(0, 100 - (unresolved_cases * 12)),
            "detail": f"{unresolved_cases} cases not yet closed",
        },
        {
            "factor": "Offline synchronisation",
            "value": 100 if pending_sync == 0 else max(0, 100 - pending_sync * 15),
            "detail": f"{pending_sync} events pending synchronisation",
        },
    ]
    score = round(sum(f["value"] for f in factors) / len(factors))
    if score >= 90:
        rating = "NORMAL"
    elif score >= 75:
        rating = "ELEVATED"
    elif score >= 60:
        rating = "HIGH RISK"
    else:
        rating = "CRITICAL"
    return {
        "score": score,
        "rating": rating,
        "factors": factors,
        "basis": "Unweighted mean of the measured factors listed above.",
        "disclaimer": (
            "This is a prototype operational indicator computed from observable system state. It is "
            "not a certified military security rating and carries no accreditation."
        ),
    }


def role_matrix() -> dict[str, Any]:
    return {
        "roles": {role: sorted(perms) for role, perms in PERMISSIONS.items()},
        "separation_of_duties": separation_of_duties_report(),
        "read_only_roles": list(Role.READ_ONLY),
        "note": (
            "No role holds administrative power together with evidence, ledger-write or approval "
            "authority, so one compromised account cannot both act and erase the record of acting."
        ),
    }


def clearance_ladder() -> list[dict[str, Any]]:
    return [
        {"level": level.name, "rank": level.value, "label": level.label,
         "note": "Prototype application label; not an official classification standard."}
        for level in Clearance
    ]


def anomaly_catalogue(session: Session) -> dict[str, Any]:
    return {
        "rules": anomaly_detection.rule_catalogue(),
        "recent_observations": anomaly_detection.recent_observations(session),
        "note": "Deterministic, explainable thresholds. No machine learning is involved in detection.",
    }


def audit_trail(
    session: Session,
    limit: int = 60,
    *,
    actor_id: str | None = None,
    action: str | None = None,
    target_id: str | None = None,
    device_id: str | None = None,
    document_id: str | None = None,
    session_id: str | None = None,
    severity: str | None = None,
    policy_version: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    return {
        "chain": audit_service.verify_chain(session),
        "privileged_actions": audit_service.search(
            session,
            limit=limit,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            device_id=device_id,
            document_id=document_id,
            session_id=session_id,
            severity=severity,
            policy_version=policy_version,
            since=since,
            until=until,
        ),
        "categories": list(audit_service.PRIVILEGED_ACTIONS),
        "filters_applied": {
            "actor_id": actor_id,
            "action": action,
            "target_id": target_id,
            "device_id": device_id,
            "document_id": document_id,
            "session_id": session_id,
            "severity": severity,
            "policy_version": policy_version,
            "since": since,
            "until": until,
        },
        "note": (
            "Records are append-only and hash-chained. Updating or deleting any entry breaks the chain "
            "and is detected."
        ),
    }


def key_inventory(session: Session) -> dict[str, Any]:
    rows = session.execute(select(KeyMetadata).order_by(KeyMetadata.key_id)).scalars()
    return {
        "keys": [
            {
                "key_id": row.key_id,
                "owner_id": row.owner_id,
                "purpose": row.purpose,
                "algorithm": row.algorithm,
                "version": row.version,
                "status": row.status,
                "created_at": row.created_at.isoformat(timespec="seconds"),
                "expires_at": row.expires_at.isoformat(timespec="seconds") if row.expires_at else None,
                "private_key_exposed": False,
            }
            for row in rows
        ],
        "storage": VAULT.storage_report(),
        "pqc": PQC.describe(),
        "lifecycle_states": ["CREATED", "ACTIVE", "EXPIRING", "ROTATED", "REVOKED", "ARCHIVED"],
    }
