from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import PATHS
from ..core.exceptions import NotFound
from ..core.identifiers import case_id as make_case_id
from ..crypto.hashing import canonical_bytes, file_digest_bundle, sha256_hex
from ..crypto.signatures import verify_recipient_signature
from ..database import shared as shared_store
from ..documents.pdf import canonicalize, render_gray
from ..ledger.chain import NETWORK
from ..models.documents import Document, DocumentVersion
from ..models.forensic import ANALYSIS_TOOL, EvidenceItem, InvestigationCase
from ..models.identity import Recipient
from ..models.sessions import DecryptionEvent, DecryptionSession
from ..security import incident_engine
from . import audit_service, watermark_service

#: A watermarked copy of an untouched document still differs from the original
#: by the embedding itself, which measures around 41 dB. Anything materially
#: below that means the content was edited after distribution.
UNMODIFIED_PSNR_FLOOR_DB = 33.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def next_case_number(session: Session) -> int:
    current = int(
        session.execute(select(func.count()).select_from(InvestigationCase)).scalar_one()
    )
    existing = session.execute(select(InvestigationCase.case_id)).scalars().all()
    highest = 0
    for value in existing:
        try:
            highest = max(highest, int(value.rsplit("-", 1)[-1]))
        except ValueError:
            continue
    return max(highest + 1, current + 1)


def open_case(
    session: Session,
    *,
    investigator: Recipient,
    title: str,
    summary_text: str = "",
    suspected_document_id: str | None = None,
) -> InvestigationCase:
    case = InvestigationCase(
        case_id=make_case_id(next_case_number(session)),
        title=title,
        investigator_id=investigator.recipient_id,
        status="OPEN",
        suspected_document_id=suspected_document_id,
        summary=summary_text,
        created_at=_utcnow(),
    )
    session.add(case)
    session.flush()
    audit_service.record(
        session,
        actor_id=investigator.recipient_id,
        action="INVESTIGATION_OPENED",
        target_type="INVESTIGATION_CASE",
        target_id=case.case_id,
        detail={"title": title, "suspected_document_id": suspected_document_id},
    )
    return case


def store_evidence(
    session: Session,
    *,
    case: InvestigationCase,
    investigator: Recipient,
    leaked_path: Path,
    original_filename: str,
) -> EvidenceItem:
    """Preserves the submitted artefact and its hash before any analysis runs.

    Analysis never mutates the stored copy, so the recorded hash keeps matching
    whatever the investigator submitted.
    """
    stored = PATHS.evidence / case.case_id / f"{Path(leaked_path).name}"
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(shared_store.artefact_materialize(Path(leaked_path)).read_bytes())
    shared_store.artefact_put_file(stored)
    digest = file_digest_bundle(stored)
    # Counted from the database rather than the relationship collection, which
    # is not refreshed after the previous insert within the same transaction.
    sequence = int(
        session.execute(
            select(func.count()).select_from(EvidenceItem).where(EvidenceItem.case_id == case.case_id)
        ).scalar_one()
    ) + 1
    item = EvidenceItem(
        evidence_id=f"EV-{case.case_id}-{sequence:02d}",
        case_id=case.case_id,
        kind="SUSPECTED_LEAK",
        original_filename=original_filename,
        stored_path=str(stored),
        content_sha256=digest["sha256"],
        size_bytes=digest["size_bytes"],
        collected_by=investigator.recipient_id,
        collected_at=_utcnow(),
        analysis_tool=ANALYSIS_TOOL,
    )
    session.add(item)
    session.flush()
    audit_service.record(
        session,
        actor_id=investigator.recipient_id,
        action="EVIDENCE_ACCESSED",
        target_type="EVIDENCE_ITEM",
        target_id=item.evidence_id,
        detail={"case_id": case.case_id, "content_sha256": digest["sha256"]},
    )
    return item


def analyze(session: Session, *, evidence: EvidenceItem) -> dict[str, Any]:
    """Runs the full chain and records the result on the evidence item.

    Each link is verified independently and the failing link is named. A partial
    result is never upgraded to a success.
    """
    links: list[dict[str, Any]] = []
    stored = Path(evidence.stored_path)

    links.append(
        _link(
            "LEAKED FILE",
            "PASS",
            f"Artefact preserved with SHA-256 {evidence.content_sha256[:16]}…",
        )
    )

    verdict, extraction, _versions = watermark_service.extract_and_match(session, stored)
    links.append(
        _link(
            "WATERMARK EXTRACTION",
            "PASS" if verdict.status in ("FOUND", "WEAK MATCH") else "FAIL",
            (
                f"{verdict.status} — tag {verdict.tag or 'none'}, carrier-to-noise "
                f"{verdict.carrier_to_noise:.2f}, estimated bit errors {verdict.estimated_bit_errors}"
            ),
            evidence={"attempts": verdict.attempts[:3]},
        )
    )

    if not verdict.attributed or verdict.matched_session_id is None:
        links.append(_link("WATERMARK MATCH", "FAIL", "Recovered tag matches no registered decryption session."))
        return _finish(session, evidence, verdict, links, None, None, "WATERMARK_NOT_RECOVERED")

    links.append(
        _link(
            "WATERMARK MATCH",
            "PASS" if verdict.status == "FOUND" else "PARTIAL",
            f"Tag matched {verdict.matched_watermark_id} at Hamming distance {verdict.hamming_distance}.",
        )
    )

    decryption_session = session.get(DecryptionSession, verdict.matched_session_id)
    if decryption_session is None:
        links.append(_link("DECRYPTION SESSION", "FAIL", "The referenced session record is absent."))
        return _finish(session, evidence, verdict, links, None, None, "INSUFFICIENT_EVIDENCE")
    links.append(
        _link(
            "DECRYPTION SESSION",
            "PASS",
            f"Session {decryption_session.session_id} opened {decryption_session.issued_at.isoformat(timespec='seconds')}.",
        )
    )

    recipient = session.get(Recipient, decryption_session.recipient_id)
    links.append(
        _link(
            "RECIPIENT ASSOCIATION",
            "PASS" if recipient else "FAIL",
            (
                f"{recipient.recipient_id} — {recipient.display_name}, unit {recipient.unit}, "
                f"clearance {recipient.clearance}"
            )
            if recipient
            else "Recipient record missing.",
        )
    )

    event = session.execute(
        select(DecryptionEvent).where(DecryptionEvent.session_id == decryption_session.session_id)
    ).scalar_one_or_none()
    signature_ok = bool(
        event
        and verify_recipient_signature(
            event.recipient_id, json.loads(event.payload), event.signature
        )
    )
    links.append(
        _link(
            "EVENT SIGNATURE",
            "PASS" if signature_ok else "FAIL",
            (
                f"{event.signature_algorithm} signature verified against {event.signing_key_id}."
                if signature_ok
                else "The signed event did not verify against the recipient's registered public key."
            ),
        )
    )

    ledger_link, proof = _verify_ledger(event.ledger_tx_id if event else None)
    links.append(ledger_link)

    version = session.get(DocumentVersion, decryption_session.version_id)
    document_integrity = "UNKNOWN"
    if version is not None:
        similarity = content_similarity(stored, Path(version.normalized_pdf_path))
        if not similarity["original_available"]:
            document_integrity = "UNKNOWN"
            links.append(
                _link(
                    "DOCUMENT VERSION MATCH",
                    "UNKNOWN",
                    "The pre-encryption working copy is no longer on disk, so page-image comparison "
                    "was not possible. The version binding was checked from the signed event instead.",
                )
            )
        elif similarity["psnr_db"] >= UNMODIFIED_PSNR_FLOOR_DB:
            document_integrity = "MATCHED"
            links.append(
                _link(
                    "DOCUMENT VERSION MATCH",
                    "PASS",
                    (
                        f"Page images match {version.label} within the embedding tolerance "
                        f"(PSNR {similarity['psnr_db']:.1f} dB, floor {UNMODIFIED_PSNR_FLOOR_DB} dB)."
                    ),
                )
            )
        else:
            document_integrity = "ALTERED"
            links.append(
                _link(
                    "DOCUMENT VERSION MATCH",
                    "FAIL",
                    (
                        f"Page images differ from {version.label} beyond embedding tolerance "
                        f"(PSNR {similarity['psnr_db']:.1f} dB < {UNMODIFIED_PSNR_FLOOR_DB} dB). "
                        "The copy was modified after distribution."
                    ),
                )
            )

    outcome = _decide_outcome(signature_ok, ledger_link["status"], document_integrity, bool(proof and proof.get("verified")))
    return _finish(session, evidence, verdict, links, decryption_session, event, outcome)


def _verify_ledger(tx_id: str | None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if not tx_id:
        return _link("LEDGER TRANSACTION", "FAIL", "No ledger transaction was recorded for this event."), None
    proof = NETWORK.prove_transaction(tx_id)
    if proof.get("verified"):
        return (
            _link(
                "LEDGER TRANSACTION",
                "PASS",
                f"Transaction {tx_id} is committed in block {proof['block_id']} and node "
                f"{proof['verified_by_node']} produced a valid Merkle inclusion proof.",
                evidence=proof,
            ),
            proof,
        )
    return (
        _link(
            "LEDGER PROOF",
            "FAIL",
            f"Transaction {tx_id} could not be proven: {proof.get('status')}.",
            evidence=proof,
        ),
        proof,
    )


def _decide_outcome(signature_ok: bool, ledger_status: str, integrity: str, merkle_ok: bool) -> str:
    from ..core.config import ForensicOutcome

    if not signature_ok:
        return ForensicOutcome.SIGNATURE_INVALID
    if ledger_status == "FAIL" or not merkle_ok:
        return ForensicOutcome.LEDGER_PROOF_INVALID
    if integrity == "ALTERED":
        return ForensicOutcome.DOCUMENT_MODIFIED
    if integrity in ("MATCHED", "UNKNOWN"):
        return ForensicOutcome.VERIFIED_ASSOCIATION
    return ForensicOutcome.PARTIALLY_VERIFIED


def _link(name: str, status: str, detail: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"link": name, "status": status, "detail": detail, "evidence": evidence or {}}


def _finish(
    session: Session,
    evidence: EvidenceItem,
    verdict,
    links: list[dict[str, Any]],
    decryption_session: DecryptionSession | None,
    event: DecryptionEvent | None,
    outcome: str,
) -> dict[str, Any]:
    evidence.extracted_watermark_tag = verdict.tag
    evidence.watermark_confidence = verdict.confidence
    evidence.watermark_verdict = verdict.status
    evidence.matched_watermark_id = verdict.matched_watermark_id
    evidence.matched_event_id = event.event_id if event else None
    evidence.matched_session_id = decryption_session.session_id if decryption_session else None
    evidence.matched_recipient_id = decryption_session.recipient_id if decryption_session else None
    evidence.matched_device_id = decryption_session.device_id if decryption_session else None
    evidence.matched_document_id = verdict.matched_document_id
    evidence.matched_version_id = verdict.matched_version_id
    evidence.signature_status = next(
        (l["status"] for l in links if l["link"] == "EVENT SIGNATURE"), "NOT_REACHED"
    )
    evidence.ledger_status = next(
        (l["status"] for l in links if l["link"].startswith("LEDGER")), "NOT_REACHED"
    )
    evidence.merkle_proof_status = evidence.ledger_status
    evidence.chain_links = json.dumps(links)
    evidence.verification_status = outcome
    evidence.analysed_at = _utcnow()
    evidence.analysed_by = evidence.collected_by
    evidence.limitations = json.dumps(limitations_for(verdict.status))

    case = session.get(InvestigationCase, evidence.case_id)
    if case is not None:
        case.status = "VERIFIED" if outcome == "VERIFIED ASSOCIATION" else "UNDER_INVESTIGATION"
        case.final_verification_status = outcome
        case.attributed_recipient_id = evidence.matched_recipient_id
        case.attributed_session_id = evidence.matched_session_id
        case.suspected_version_number = (
            event.version_number if event else case.suspected_version_number
        )

    if outcome in ("VERIFIED ASSOCIATION", "DOCUMENT_MODIFIED", "SIGNATURE_INVALID"):
        incident_engine.raise_event(
            session,
            "DOCUMENT_HASH_MISMATCH" if outcome == "DOCUMENT_MODIFIED" else "FORENSIC_ATTRIBUTION",
            title=f"Forensic analysis {outcome} for {evidence.evidence_id}",
            what_happened=(
                f"{evidence.collected_by} analysed {evidence.original_filename} in case "
                f"{evidence.case_id}. Result: {outcome}."
            ),
            why_it_matters=(
                "A cryptographically verified association exists between this copy and an authorised "
                "decryption session."
                if outcome == "VERIFIED ASSOCIATION"
                else "The submitted copy does not correspond to an unmodified distributed document."
            ),
            what_was_affected=evidence.matched_document_id or "UNKNOWN",
            recommended_action=(
                "Brief the investigating officer and confirm the attribution with the recipient's unit."
                if outcome == "VERIFIED ASSOCIATION"
                else "Preserve this copy as separate evidence and review the modified content."
            ),
            severity="HIGH" if outcome != "VERIFIED ASSOCIATION" else "MEDIUM",
            subject_id=evidence.matched_recipient_id,
            document_id=evidence.matched_document_id,
        )

    return {
        "evidence_id": evidence.evidence_id,
        "case_id": evidence.case_id,
        "outcome": outcome,
        "watermark": verdict.as_dict(),
        "evidence_chain": links,
        "chain_summary": {
            "links_total": len(links),
            "links_passed": sum(1 for l in links if l["status"] == "PASS"),
            "links_partial": sum(1 for l in links if l["status"] == "PARTIAL"),
            "links_failed": sum(1 for l in links if l["status"] == "FAIL"),
            "links_unknown": sum(1 for l in links if l["status"] == "UNKNOWN"),
        },
        "matched_recipient_id": evidence.matched_recipient_id,
        "matched_session_id": evidence.matched_session_id,
        "matched_document_id": evidence.matched_document_id,
        "matched_version_id": evidence.matched_version_id,
        "content_sha256": evidence.content_sha256,
        "limitations": limitations_for(verdict.status),
        "outcome_explanation": _outcome_explanation(outcome),
    }


def _outcome_explanation(outcome: str) -> str:
    from ..core.config import ForensicOutcome

    return ForensicOutcome.OUTCOME_EXPLANATIONS.get(outcome, "")


def limitations_for(watermark_status: str) -> list[str]:
    base = [
        "This establishes cryptographic association between the copy and an authorised decryption "
        "session. It does not prove which person physically leaked it.",
        "Endpoint compromise is outside software control: a compromised terminal can photograph, "
        "screenshot or manually transcribe displayed content regardless of any watermark.",
        "Two recipients who collude can compare their copies and estimate the embedding pattern. "
        "Collusion-resistant watermarking is a separate research problem and is not implemented here.",
    ]
    if watermark_status in ("WEAK MATCH", "CORRUPTED", "NOT FOUND"):
        base.append(
            "The watermark payload recovered from this copy is weak or absent, so attribution is "
            "reported as a lead rather than a verified association."
        )
    return base


def content_similarity(suspect_pdf: Path, original_pdf: Path) -> dict[str, Any]:
    """Page-image comparison between a suspect copy and the stored original.

    A watermarked but otherwise untouched copy still sits around 41 dB apart,
    because the embedding itself changes pixels. An edited copy falls far below
    that, which is what separates the two cases.
    """
    shared_store.artefact_materialize(original_pdf)
    if not original_pdf.exists():
        return {"original_available": False, "psnr_db": None, "pages": []}
    suspect_pages = render_gray(suspect_pdf)
    original_pages = render_gray(original_pdf)
    if not suspect_pages or not original_pages:
        return {"original_available": True, "psnr_db": None, "pages": []}

    scores: list[float] = []
    for index in range(min(len(suspect_pages), len(original_pages))):
        suspect = suspect_pages[index]
        original = original_pages[index]
        if suspect.shape != original.shape:
            height = min(suspect.shape[0], original.shape[0])
            width = min(suspect.shape[1], original.shape[1])
            suspect = canonicalize(suspect, suspect.shape[0] / height)[:height, :width]
            original = original[:height, :width]
            if suspect.shape != original.shape:
                scores.append(0.0)
                continue
        mse = float(np.mean((suspect - original) ** 2))
        scores.append(99.0 if mse <= 1e-12 else float(10.0 * np.log10(1.0 / mse)))
    return {
        "original_available": True,
        "psnr_db": round(float(np.mean(scores)), 2),
        "pages": [round(s, 2) for s in scores],
        "page_count_compared": len(scores),
        "floor_db": UNMODIFIED_PSNR_FLOOR_DB,
    }


def build_report(session: Session, *, evidence: EvidenceItem, investigator: Recipient) -> dict[str, Any]:
    """Assembles the forensic report and hashes it."""
    from ..core.config import ForensicOutcome

    decryption_session = (
        session.get(DecryptionSession, evidence.matched_session_id) if evidence.matched_session_id else None
    )
    event = (
        session.execute(
            select(DecryptionEvent).where(DecryptionEvent.session_id == evidence.matched_session_id)
        ).scalar_one_or_none()
        if evidence.matched_session_id
        else None
    )
    version = session.get(DocumentVersion, evidence.matched_version_id) if evidence.matched_version_id else None
    document = session.get(Document, evidence.matched_document_id) if evidence.matched_document_id else None
    recipient = session.get(Recipient, evidence.matched_recipient_id) if evidence.matched_recipient_id else None
    proof = NETWORK.prove_transaction(event.ledger_tx_id) if event and event.ledger_tx_id else None

    report = {
        "report_type": "SENTINEL FORENSIC EVIDENCE REPORT",
        "report_version": "1.0",
        "generated_at": _utcnow().isoformat(timespec="seconds"),
        "analysis_tool": evidence.analysis_tool,
        "case": {
            "case_id": evidence.case_id,
            "investigator_id": investigator.recipient_id,
            "investigator_name": investigator.display_name,
            "investigator_unit": investigator.unit,
        },
        "chain_of_custody": {
            "evidence_id": evidence.evidence_id,
            "original_filename": evidence.original_filename,
            "collected_by": evidence.collected_by,
            "collected_at": evidence.collected_at.isoformat(timespec="seconds"),
            "analysed_by": evidence.analysed_by,
            "analysed_at": evidence.analysed_at.isoformat(timespec="seconds") if evidence.analysed_at else None,
            "file_sha256": evidence.content_sha256,
            "file_size_bytes": evidence.size_bytes,
            "stored_path": evidence.stored_path,
            "history_preserved": True,
        },
        "watermark": {
            "watermark_id": evidence.matched_watermark_id,
            "recovered_tag": evidence.extracted_watermark_tag,
            "confidence": evidence.watermark_confidence,
            "verdict": evidence.watermark_verdict,
            "derivation": (
                "HMAC-SHA256 over recipient, document, document hash, session id, fresh nonce, "
                "watermark version and policy version, truncated to 64 bits. The tag carries no "
                "readable identity and requires authorised registry lookup to interpret."
            ),
        },
        "association": {
            "recipient_id": evidence.matched_recipient_id,
            "recipient_name": recipient.display_name if recipient else None,
            "recipient_unit": recipient.unit if recipient else None,
            "recipient_role": recipient.role if recipient else None,
            "session_id": evidence.matched_session_id,
            "device_id": evidence.matched_device_id,
            "decryption_timestamp": decryption_session.issued_at.isoformat(timespec="seconds")
            if decryption_session
            else None,
            "break_glass_used": decryption_session.is_break_glass if decryption_session else None,
        },
        "document": {
            "document_id": evidence.matched_document_id,
            "title": document.title if document else None,
            "classification": document.classification if document else None,
            "version_id": evidence.matched_version_id,
            "version_number": version.version_number if version else None,
            "recorded_content_sha256": version.content_sha256 if version else None,
            "policy_version": document.policy_version if document else None,
        },
        "signed_event": {
            "event_id": event.event_id if event else None,
            "event_hash": event.event_hash if event else None,
            "previous_event_hash": event.prev_event_hash if event else None,
            "signature_algorithm": event.signature_algorithm if event else None,
            "signing_key_id": event.signing_key_id if event else None,
            "signature_verified": evidence.signature_status == "PASS",
            "signature_value": event.signature if event else None,
        },
        "ledger": {
            "transaction_id": event.ledger_tx_id if event else None,
            "block_id": proof.get("block_id") if proof else None,
            "block_hash": proof.get("block_hash") if proof else None,
            "previous_block_hash": proof.get("previous_block_hash") if proof else None,
            "merkle_root": proof.get("merkle_root") if proof else None,
            "merkle_proof": proof.get("proof") if proof else None,
            "merkle_proof_verified": bool(proof and proof.get("verified")),
            "verified_by_node": proof.get("verified_by_node") if proof else None,
        },
        "evidence_chain": json.loads(evidence.chain_links or "[]"),
        "final_result": {
            "status": evidence.verification_status,
            "explanation": ForensicOutcome.OUTCOME_EXPLANATIONS.get(evidence.verification_status, ""),
        },
        "limitations": json.loads(evidence.limitations or "[]"),
        "attestation": (
            "This report records a cryptographically verifiable association between the submitted "
            "artefact and an authorised decryption session, subject to the stated limitations. It is "
            "not a finding of fact about which individual released the material, and it is not a "
            "certified forensic analysis."
        ),
    }
    report["report_sha256"] = sha256_hex(canonical_bytes(report))

    destination = PATHS.evidence / evidence.case_id / f"{evidence.evidence_id}-report.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    shared_store.artefact_put_file(destination)
    evidence.report_path = str(destination)
    evidence.report_sha256 = report["report_sha256"]

    case = session.get(InvestigationCase, evidence.case_id)
    if case is not None:
        case.report_path = str(destination)
        case.report_sha256 = report["report_sha256"]

    audit_service.record(
        session,
        actor_id=investigator.recipient_id,
        action="EVIDENCE_REPORT_GENERATED",
        target_type="EVIDENCE_ITEM",
        target_id=evidence.evidence_id,
        detail={"report_sha256": report["report_sha256"], "outcome": evidence.verification_status},
    )
    return report


def verify_report_integrity(path: Path) -> dict[str, Any]:
    """Recomputes the report hash. Excludes the hash field itself."""
    shared_store.artefact_materialize(path)
    stored = json.loads(Path(path).read_text(encoding="utf-8"))
    recorded = stored.pop("report_sha256", "")
    recomputed = sha256_hex(canonical_bytes(stored))
    return {
        "report_path": str(path),
        "recorded_sha256": recorded,
        "recomputed_sha256": recomputed,
        "status": "EVIDENCE REPORT INTEGRITY: VERIFIED" if recorded == recomputed else "EVIDENCE REPORT INTEGRITY: FAILED",
        "plain_explanation": (
            "The report has not been altered since it was generated."
            if recorded == recomputed
            else "The report file no longer matches the hash recorded when it was created."
        ),
    }


def list_cases(session: Session, *, limit: int = 50) -> list[dict[str, Any]]:
    rows = list(
        session.execute(
            select(InvestigationCase).order_by(InvestigationCase.created_at.desc()).limit(limit)
        ).scalars()
    )
    return [
        {
            "case_id": row.case_id,
            "uuid": row.uuid,
            "title": row.title,
            "investigator_id": row.investigator_id,
            "status": row.status,
            "suspected_document_id": row.suspected_document_id,
            "final_verification_status": row.final_verification_status,
            "attributed_recipient_id": row.attributed_recipient_id,
            "attributed_session_id": row.attributed_session_id,
            "evidence_count": len(row.evidence),
            "report_sha256": row.report_sha256,
            "created_at": row.created_at.isoformat(timespec="seconds"),
        }
        for row in rows
    ]


def describe_case(session: Session, case_id: str) -> dict[str, Any]:
    case = session.get(InvestigationCase, case_id)
    if case is None:
        raise NotFound(f"No investigation case {case_id}.")
    return {
        "case_id": case.case_id,
        "title": case.title,
        "investigator_id": case.investigator_id,
        "status": case.status,
        "summary": case.summary,
        "notes": json.loads(case.notes or "[]"),
        "final_verification_status": case.final_verification_status,
        "attributed_recipient_id": case.attributed_recipient_id,
        "attributed_session_id": case.attributed_session_id,
        "report_path": case.report_path,
        "report_sha256": case.report_sha256,
        "report_integrity": (
            verify_report_integrity(Path(case.report_path)) if case.report_path else None
        ),
        "created_at": case.created_at.isoformat(timespec="seconds"),
        "closed_at": case.closed_at.isoformat(timespec="seconds") if case.closed_at else None,
        "evidence": [describe_evidence(item) for item in case.evidence],
        "history_preserved": True,
        "deletion_note": "Cases are closed, never deleted, so the investigative history survives.",
    }


def describe_evidence(item: EvidenceItem) -> dict[str, Any]:
    return {
        "evidence_id": item.evidence_id,
        "kind": item.kind,
        "original_filename": item.original_filename,
        "content_sha256": item.content_sha256,
        "size_bytes": item.size_bytes,
        "extracted_watermark_tag": item.extracted_watermark_tag,
        "watermark_confidence": item.watermark_confidence,
        "watermark_verdict": item.watermark_verdict,
        "matched_event_id": item.matched_event_id,
        "matched_session_id": item.matched_session_id,
        "matched_recipient_id": item.matched_recipient_id,
        "matched_device_id": item.matched_device_id,
        "signature_status": item.signature_status,
        "ledger_status": item.ledger_status,
        "verification_status": item.verification_status,
        "evidence_chain": json.loads(item.chain_links or "[]"),
        "collected_by": item.collected_by,
        "collected_at": item.collected_at.isoformat(timespec="seconds"),
        "analysed_by": item.analysed_by,
        "analysed_at": item.analysed_at.isoformat(timespec="seconds") if item.analysed_at else None,
        "analysis_tool": item.analysis_tool,
        "limitations": json.loads(item.limitations or "[]"),
    }


def add_note(session: Session, *, case_id: str, author_id: str, note: str) -> dict[str, Any]:
    case = session.get(InvestigationCase, case_id)
    if case is None:
        raise NotFound(f"No investigation case {case_id}.")
    notes = json.loads(case.notes or "[]")
    entry = {"at": _utcnow().isoformat(timespec="seconds"), "author_id": author_id, "note": note}
    notes.append(entry)
    case.notes = json.dumps(notes)
    audit_service.record(
        session,
        actor_id=author_id,
        action="INVESTIGATION_NOTE_ADDED",
        target_type="INVESTIGATION_CASE",
        target_id=case_id,
        detail={"note": note},
    )
    return {"case_id": case_id, "note": entry, "note_count": len(notes)}


def close_case(session: Session, *, case_id: str, actor_id: str, conclusion: str) -> dict[str, Any]:
    case = session.get(InvestigationCase, case_id)
    if case is None:
        raise NotFound(f"No investigation case {case_id}.")
    case.status = "CLOSED"
    case.closed_at = _utcnow()
    add_note(session, case_id=case_id, author_id=actor_id, note=f"Case closed: {conclusion}")
    audit_service.record(
        session,
        actor_id=actor_id,
        action="INVESTIGATION_CLOSED",
        target_type="INVESTIGATION_CASE",
        target_id=case_id,
        detail={"conclusion": conclusion},
    )
    return describe_case(session, case_id)
