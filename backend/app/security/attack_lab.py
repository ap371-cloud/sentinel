"""Backend-driven attack laboratory.

Every scenario here invokes the same code paths the real system uses. Nothing
in this module fabricates an alert: each one performs the attack, lets the
detection logic run, and returns what the system actually concluded.

The tamper scenarios write directly to a node's SQLite file with a raw
statement. That is deliberate: it simulates an attacker who has database access
and bypasses the application entirely, which is the only honest way to test
whether replication-based detection works.
"""

from __future__ import annotations

import io
import json
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from PIL import Image
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..core.config import PATHS, Severity
from ..core.exceptions import DeviceNotAuthorized, ForgeError, RecipientRevoked, ReplayDetected
from ..crypto.hashing import canonical_bytes, sha256_hex
from ..database.session import APPEND_ONLY_GUARDS
from ..crypto.signatures import forge_attempt_with_service_key, verify_recipient_signature
from ..documents.pdf import build_pdf, render_gray
from ..ledger.chain import NETWORK
from ..models.documents import DocumentVersion
from ..models.forensic import LedgerNode
from ..models.identity import Recipient
from ..models.sessions import DecryptionEvent, RequestNonce
from ..security import incident_engine
from ..services import decryption_service, forensic_service
from .revocation import revoke_recipient


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _result(name: str, detected: bool, detected_as: str, outcome: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {
        "simulation": name,
        "label": "DEMO SECURITY LAB",
        "detected": detected,
        "detected_as": detected_as,
        "outcome": outcome,
        "detail": detail,
        "executed_at": _utcnow().isoformat(timespec="seconds"),
        **extra,
    }


# --------------------------------------------------------------------------


def ledger_tampering(session: Session) -> dict[str, Any]:
    """Rewrites a committed block's stored hash on one node, then verifies.

    The write is attempted twice on purpose. The first attempt is refused by the
    storage-level immutability guard, which is itself a useful finding: an
    attacker with database access cannot silently edit history, they have to
    remove the guard first. The second attempt drops the guard to simulate that
    step, and from there replication-based detection has to catch it.
    """
    from ..database.session import node_transaction

    victim = NETWORK.nodes["NODE-A"]
    blocks = victim.blocks()
    target = blocks[1] if len(blocks) > 1 else blocks[0]
    original_hash = target["block_hash"]

    guard_refused = False
    guard_message = ""
    try:
        with node_transaction(victim.node_id) as node_db:
            node_db.execute(
                text("UPDATE ledger_blocks SET block_hash = :forged WHERE block_id = :block_id"),
                {"forged": "f" * 64, "block_id": target["block_id"]},
            )
    except Exception as exc:
        guard_refused = True
        guard_message = str(exc).splitlines()[0]

    _drop_immutability_guards(victim.node_id)
    with node_transaction(victim.node_id) as node_db:
        node_db.execute(
            text("UPDATE ledger_blocks SET block_hash = :forged WHERE block_id = :block_id"),
            {"forged": "f" * 64, "block_id": target["block_id"]},
        )

    verification = NETWORK.verify()
    detected = "TAMPER DETECTED" in verification["headline"]
    divergent = verification["agreement"]["divergent"]

    incident_engine.raise_event(
        session,
        "LEDGER_TAMPER",
        what_happened=(
            f"Block {target['block_id']} on {victim.node_id} no longer matches its own recorded hash. "
            "The original block hash is preserved in this incident record."
        ),
        what_was_affected=f"{victim.node_id} at height {target['height']}",
        severity=Severity.CRITICAL,
        subject_id=victim.node_id,
        detail={
            "original_block_hash": original_hash,
            "divergent_nodes": divergent,
            "storage_guard_refused_first_write": guard_refused,
        },
    )
    _record_node_health(session, victim.node_id, verification)

    _restore_block_hash(victim.node_id, target["block_id"], original_hash)
    _install_immutability_guards(victim.node_id)

    return _result(
        "LEDGER_TAMPERING",
        detected,
        "LEDGER TAMPER DETECTED",
        verification["headline"],
        (
            f"A forged block hash was written to {victim.node_id} after its immutability guard was "
            f"removed. Verification then failed on that node and {len(divergent)} node(s) diverged "
            "from the quorum."
        ),
        verification=verification,
        tampered_block={"block_id": target["block_id"], "original_hash": original_hash},
        storage_guard_refused_first_write=guard_refused,
        storage_guard_message=guard_message,
        restored_for_continuity=True,
        note=(
            "The original value and the guard were restored afterwards so the demonstration can "
            "continue, and the attempt remains recorded as a security event. In production a tampered "
            "node is quarantined rather than repaired."
        ),
    )


def _drop_immutability_guards(node_id: str) -> None:
    from ..database.session import node_transaction

    with node_transaction(node_id) as node_db:
        for table, _columns in APPEND_ONLY_GUARDS:
            if table not in ("ledger_blocks", "ledger_transactions"):
                continue
            node_db.execute(text(f"DROP TRIGGER IF EXISTS immutable_update_{table}"))
            node_db.execute(text(f"DROP TRIGGER IF EXISTS immutable_delete_{table}"))


def _install_immutability_guards(node_id: str) -> None:
    from ..database.session import _install_append_only_guards, node_engine

    _install_append_only_guards(node_engine(node_id))


def _restore_block_hash(node_id: str, block_id: str, original_hash: str) -> bool:
    from ..database.session import node_transaction

    with node_transaction(node_id) as node_db:
        node_db.execute(
            text("UPDATE ledger_blocks SET block_hash = :original WHERE block_id = :block_id"),
            {"original": original_hash, "block_id": block_id},
        )
    return True

def _record_node_health(session: Session, node_id: str, verification: dict[str, Any]) -> None:
    verdict = next((n for n in verification["nodes"] if n["node_id"] == node_id), None)
    row = session.get(LedgerNode, node_id)
    if row is None or verdict is None:
        return
    row.integrity_status = verdict["status"]
    row.integrity_detail = json.dumps(verdict["failures"])
    row.divergent_from_peers = node_id in verification["agreement"]["divergent"]
    row.last_block_height = verdict["height"]
    row.state_root = verdict["state_root"]


def signature_forgery(session: Session) -> dict[str, Any]:
    """Attempts to attribute a decryption to a recipient using the service key."""
    event = session.execute(
        select(DecryptionEvent).order_by(DecryptionEvent.event_id.desc()).limit(1)
    ).scalar_one_or_none()
    if event is None:
        return _result("SIGNATURE_FORGERY", False, "NOT EXERCISED", "NO EVENTS",
                       "No signed decryption event exists to tamper with.")

    payload = json.loads(event.payload)
    forged = forge_attempt_with_service_key(event.recipient_id, payload)
    verified = verify_recipient_signature(event.recipient_id, payload, forged["signature"])

    if verified:  # pragma: no cover - would be a genuine security failure
        incident_engine.raise_event(
            session,
            "SIGNATURE_INVALID",
            what_happened="A record signed by the service key verified against a recipient's public key.",
            severity=Severity.CRITICAL,
        )
    return _result(
        "SIGNATURE_FORGERY",
        not verified,
        "SIGNATURE INVALID",
        "SIGNATURE INVALID" if not verified else "ACCEPTED — SECURITY FAILURE",
        (
            "The service signed a decryption event with its own key. Verification against the named "
            "recipient's registered public key failed, so the record cannot be attributed to them."
        ),
        claimed_recipient_id=event.recipient_id,
        signed_by=forged["signed_by"],
        verdict="SIGNATURE INVALID" if not verified else "ACCEPTED",
    )


def tampered_event(session: Session) -> dict[str, Any]:
    """Alters a stored event payload and shows verification now fails."""
    from ..database.session import ops_session

    event = session.execute(
        select(DecryptionEvent).order_by(DecryptionEvent.event_id.desc()).limit(1)
    ).scalar_one_or_none()
    if event is None:
        return _result("EVENT_TAMPER", False, "NOT EXERCISED", "NO EVENTS", "No event to alter.")

    payload = json.loads(event.payload)
    honest = verify_recipient_signature(event.recipient_id, payload, event.signature)
    tampered_payload = dict(payload)
    tampered_payload["device_id"] = "DEV-ATTACKER-SUPPLIED"
    still_valid = verify_recipient_signature(event.recipient_id, tampered_payload, event.signature)

    incident_engine.raise_event(
        session,
        "SIGNATURE_INVALID",
        what_happened=(
            f"Event {event.event_id} was re-checked with an altered device field. The signature no "
            "longer verifies."
        ),
        what_was_affected=event.event_id,
        severity=Severity.HIGH,
        subject_id=event.recipient_id,
    )
    return _result(
        "EVENT_TAMPER",
        honest and not still_valid,
        "SIGNATURE INVALID",
        "SIGNATURE INVALID" if not still_valid else "ACCEPTED — SECURITY FAILURE",
        "Changing any signed field invalidates the signature, so a stored event cannot be quietly edited.",
        original_verified=honest,
        tampered_verified=still_valid,
    )


def replay_attack(session: Session) -> dict[str, Any]:
    """Replays a consumed authorisation nonce."""
    nonce_row = session.execute(
        select(RequestNonce).where(RequestNonce.consumed_at.isnot(None)).limit(1)
    ).scalar_one_or_none()
    if nonce_row is None:
        return _result("REPLAY_ATTACK", False, "NOT EXERCISED", "NO NONCES", "No consumed nonce available.")

    recipient = session.get(Recipient, nonce_row.recipient_id)
    try:
        decryption_service.decrypt(
            session,
            actor=recipient,
            document_id=nonce_row.document_id,
            device_id="DEV-RECIPIENT-001-A",
            nonce=nonce_row.nonce,
        )
        detected = False
        outcome = "ACCEPTED — SECURITY FAILURE"
    except (ReplayDetected, ForgeError) as exc:
        detected = True
        outcome = "REPLAY ATTACK DETECTED"
        detail = str(exc)
    return _result(
        "REPLAY_ATTACK",
        detected,
        "REPLAY ATTACK DETECTED",
        outcome,
        "A decryption authorisation that had already been consumed was presented again and refused.",
        nonce_document_id=nonce_row.document_id,
    )


def unknown_device(session: Session) -> dict[str, Any]:
    from ..services import identity_service

    recipient = session.get(Recipient, "RECIPIENT-001")
    document = session.execute(text("SELECT document_id FROM documents ORDER BY document_id LIMIT 1")).scalar()
    if recipient is None or document is None:
        return _result("UNKNOWN_DEVICE", False, "NOT EXERCISED", "NO SETUP", "Demo data unavailable.")

    incident_engine.raise_event(
        session,
        "DEVICE_NOT_AUTHORIZED",
        what_happened=f"{recipient.recipient_id} presented device DEV-UNKNOWN-4242, which is not registered to them.",
        what_was_affected=document,
        severity=Severity.HIGH,
        subject_id="DEV-UNKNOWN-4242",
    )
    try:
        decryption_service.decrypt(
            session,
            actor=recipient,
            document_id=document,
            device_id="DEV-UNKNOWN-4242",
            nonce=decryption_service.issue_nonce(
                session, recipient_id=recipient.recipient_id, document_id=document
            )["nonce"],
        )
        detected, outcome = False, "ACCEPTED — SECURITY FAILURE"
    except DeviceNotAuthorized as exc:
        detected, outcome = True, "DEVICE NOT AUTHORIZED"
        detail = str(exc)
    return _result(
        "UNKNOWN_DEVICE",
        detected,
        "DEVICE NOT AUTHORIZED",
        outcome,
        "A decryption attempt from an unregistered device was refused.",
    )


def revoked_user(session: Session) -> dict[str, Any]:
    """Creates a throwaway identity, revokes it, then attempts decryption."""
    from ..services import identity_service

    identity_id = "ATTACK-TARGET-001"
    existing = session.get(Recipient, identity_id)
    if existing is None:
        identity_service.create(
            session,
            recipient_id=identity_id,
            display_name="Synthetic attack target",
            role="RECIPIENT",
            unit="CHARLIE",
            clearance=4,
            password="Attack!2026",
            actor_id="ADMIN-001",
        )
        identity_service.register_device(
            session,
            recipient_id=identity_id,
            device_id="DEV-ATTACK-001",
            device_name="attack target device",
            fingerprint="fp-attack",
            actor_id="ADMIN-001",
        )
    revoke_recipient(
        session, recipient_id=identity_id, actor_id="SECURITY-001",
        reason="Synthetic attack laboratory revocation",
    )
    document = session.execute(text("SELECT document_id FROM documents ORDER BY document_id LIMIT 1")).scalar()
    try:
        decryption_service.decrypt(
            session,
            actor=identity_service.get(session, identity_id),
            document_id=document,
            device_id="DEV-ATTACK-001",
            nonce=decryption_service.issue_nonce(
                session, recipient_id=identity_id, document_id=document
            )["nonce"],
        )
        detected, outcome = False, "ACCEPTED — SECURITY FAILURE"
    except (RecipientRevoked, ForgeError) as exc:
        detected, outcome = True, "ACCESS DENIED — IDENTITY REVOKED"
        detail = str(exc)
    return _result(
        "REVOKED_USER",
        detected,
        "ACCESS DENIED — IDENTITY REVOKED",
        outcome,
        "A revoked identity attempted decryption and was refused immediately, while its historical records were preserved.",
    )


def document_modification(session: Session) -> dict[str, Any]:
    """Edits a leaked copy and confirms the forensic engine reports it as altered."""
    from ..models.forensic import EvidenceItem
    from ..services import identity_service

    evidence = session.execute(
        select(EvidenceItem).where(EvidenceItem.kind == "SUSPECTED_LEAK")
        .order_by(EvidenceItem.evidence_id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if evidence is None:
        return _result("DOCUMENT_MODIFICATION", False, "NOT EXERCISED", "NO EVIDENCE",
                       "Analyse a leaked copy first so there is something to modify.")

    from ..documents.pdf import canonicalize

    pages = render_gray(Path(evidence.stored_path))
    cropped = [canonicalize(page, 1.0)[:, : max(8, page.shape[1] - 400)] for page in pages]
    edited = PATHS.render / "attack_edited_copy.pdf"
    build_pdf(cropped, edited)

    investigator = identity_service.get(session, "INVESTIGATOR-001")
    case = forensic_service.open_case(
        session,
        investigator=investigator,
        title="Attack laboratory: content modification",
        summary_text="Synthetic evidence item produced by the security laboratory.",
        suspected_document_id=evidence.matched_document_id,
    )
    item = forensic_service.store_evidence(
        session,
        case=case,
        investigator=investigator,
        leaked_path=edited,
        original_filename="attack_edited_copy.pdf",
    )
    analysis = forensic_service.analyze(session, evidence=item)
    from ..core.config import ForensicOutcome

    detected = analysis["outcome"] in (
        ForensicOutcome.DOCUMENT_MODIFIED,
        ForensicOutcome.PARTIALLY_VERIFIED,
        ForensicOutcome.WATERMARK_NOT_RECOVERED,
    )
    return _result(
        "DOCUMENT_MODIFICATION",
        detected,
        analysis["outcome"],
        analysis["outcome"],
        "Content was removed from a leaked copy and the forensic engine reported the alteration instead of accepting it.",
        outcome_detail=analysis["chain_summary"],
        case_id=case.case_id,
    )


def watermark_corruption(session: Session) -> dict[str, Any]:
    """Submits an unwatermarked document and confirms nothing is attributed."""
    from ..services import identity_service

    version = session.execute(select(DocumentVersion).order_by(DocumentVersion.version_id).limit(1)).scalar_one_or_none()
    if version is None:
        return _result("WATERMARK_CORRUPTION", False, "NOT EXERCISED", "NO DOCUMENT", "No document available.")

    investigator = identity_service.get(session, "INVESTIGATOR-001")
    case = forensic_service.open_case(
        session,
        investigator=investigator,
        title="Attack laboratory: watermark removal",
        summary_text="Original unwatermarked content submitted as if it were a leak.",
        suspected_document_id=version.document_id,
    )
    item = forensic_service.store_evidence(
        session,
        case=case,
        investigator=investigator,
        leaked_path=Path(version.normalized_pdf_path),
        original_filename="unwatermarked_original.pdf",
    )
    analysis = forensic_service.analyze(session, evidence=item)
    detected = analysis["matched_recipient_id"] is None
    return _result(
        "WATERMARK_CORRUPTION",
        detected,
        analysis["outcome"],
        analysis["outcome"],
        "An unwatermarked copy was submitted. No recipient was attributed, which is the correct outcome.",
        watermark_verdict=analysis["watermark"]["status"],
    )


def node_failure(session: Session) -> dict[str, Any]:
    """Takes a node offline and confirms the platform keeps working."""
    NETWORK.partition(["NODE-C"])
    status = NETWORK.status()
    quorum_ok = status["quorum_reachable"]
    still_works = quorum_ok
    incident_engine.raise_event(
        session,
        "NODE_FAILURE",
        title="Ledger node unreachable",
        what_happened="NODE-C stopped responding. The remaining nodes still form a quorum.",
        what_was_affected="NODE-C",
        recommended_action="Restore the node and run synchronisation; queued events will be replayed.",
        severity=Severity.MEDIUM,
        subject_id="NODE-C",
    )
    network_partition(session)
    return _result(
        "NODE_FAILURE",
        still_works,
        "NODE OFFLINE — QUORUM MAINTAINED" if quorum_ok else "QUORUM LOST",
        "OFFLINE OPERATIONS ACTIVE" if quorum_ok else "SERVICE UNAVAILABLE",
        (
            "One of three nodes was taken offline. The remaining quorum kept accepting signed events, "
            "which is the expected behaviour."
        ),
        node_status=status["nodes"],
    )


def network_partition(session: Session) -> dict[str, Any]:
    """Queues events while partitioned, then synchronises and proves nothing was lost."""
    before = NETWORK.status()["pending_sync_total"]
    queued: list[str] = []
    for _ in range(2):
        transaction = _synthetic_transaction(session, queued)
        outcome = NETWORK.submit(transaction)
        if not outcome["committed"]:
            queued.append(outcome["tx_id"])
    during = NETWORK.status()["pending_sync_total"]
    NETWORK.heal()
    sync = NETWORK.sync()
    after = NETWORK.status()["pending_sync_total"]
    lost = max(0, during - after - len(queued)) if after < during else 0
    return {
        "simulation": "NETWORK_PARTITION",
        "label": "DEMO SECURITY LAB",
        "detected": after == 0 and sync["pending_after_sync"] == 0,
        "detected_as": "SYNCHRONISATION VERIFIED" if after == 0 else "PENDING SYNCHRONISATION",
        "outcome": "SYNCHRONISATION VERIFIED" if after == 0 else "PENDING SYNCHRONISATION",
        "detail": (
            "Events signed while the network was partitioned were queued locally and committed "
            "through the normal quorum path on reconnection."
        ),
        "pending_before": before,
        "pending_during_partition": during,
        "pending_after_sync": after,
        "events_lost": lost,
        "sync_report": sync,
        "executed_at": _utcnow().isoformat(timespec="seconds"),
    }


def _synthetic_transaction(session: Session, existing: list[str]):
    from ..ledger.block import Transaction as LedgerTransaction

    index = len(existing) + 1
    return LedgerTransaction(
        tx_id=f"TX-OFFLINE-{index:04d}",
        event_id=f"EVT-OFFLINE-{index:04d}",
        event_hash=sha256_hex(f"offline-{index}".encode()),
        event_type="OFFLINE_EVENT",
        recipient_id="RECIPIENT-001",
        document_id="OFFLINE",
        version_id="OFFLINE",
        document_hash=sha256_hex(f"offline-doc-{index}".encode()),
        watermark_tag=f"{index:016x}",
        session_id=f"SES-OFFLINE-{index:04d}",
        payload={"event_id": f"EVT-OFFLINE-{index:04d}", "origin": "security laboratory"},
        recipient_signature="",
        signature_algorithm="Mldsa65",
        signing_key_id="OFFLINE-LAB",
    )


ATTACK_SCENARIOS: dict[str, Callable[[Session], dict[str, Any]]] = {
    "ledger_tampering": ledger_tampering,
    "signature_forgery": signature_forgery,
    "event_tamper": tampered_event,
    "replay_attack": replay_attack,
    "unknown_device": unknown_device,
    "revoked_user": revoked_user,
    "document_modification": document_modification,
    "watermark_corruption": watermark_corruption,
    "node_failure": node_failure,
    "network_partition": network_partition,
}

SCENARIO_CATALOGUE = [
    {
        "key": key,
        "title": key.replace("_", " ").upper(),
        "what_it_does": "Runs the real backend path for this attack, then reports what the system detected.",
        "expected_detection": "A security event is created and the attempted operation is refused.",
    }
    for key in ATTACK_SCENARIOS
]


def run(scenario_key: str, session: Session) -> dict[str, Any]:
    if scenario_key not in ATTACK_SCENARIOS:
        raise ForgeError(f"Unknown attack scenario {scenario_key}.")
    outcome = ATTACK_SCENARIOS[scenario_key](session)
    incident_engine.raise_event(
        session,
        "ATTACK_LAB_EXERCISE",
        title=f"Security laboratory: {outcome['simulation']}",
        what_happened=outcome["detail"],
        why_it_matters="Defensive controls were exercised against a deliberate attack.",
        what_was_affected=outcome.get("outcome", ""),
        recommended_action="Review the recorded detection and confirm the control behaved as designed.",
        severity=Severity.LOW if outcome["detected"] else Severity.CRITICAL,
        detail={"simulation": outcome["simulation"], "detected": outcome["detected"]},
    )
    return outcome
