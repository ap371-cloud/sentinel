from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.config import PATHS
from ..core.exceptions import ForgeError, NotFound
from ..models.forensic import EvidenceItem, InvestigationCase
from ..models.identity import Recipient
from ..services import forensic_service, watermark_service
from .deps import db, permitted, readable

router = APIRouter(tags=["forensics", "investigations", "evidence"])

MAX_UPLOAD_BYTES = 64 * 1024 * 1024


class CaseRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(default="", max_length=2000)
    suspected_document_id: str | None = None


class NoteRequest(BaseModel):
    note: str = Field(min_length=2, max_length=2000)


class CloseRequest(BaseModel):
    conclusion: str = Field(min_length=5, max_length=2000)


@router.post("/forensics/analyze")
def analyze(
    case_id: str = Form(...),
    file: UploadFile = File(...),
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("forensics.analyze")),
) -> dict[str, Any]:
    """The forensic entry point.

    Stores the artefact with its hash, then runs blind watermark extraction
    across the candidate document versions and verifies every downstream link:
    session, recipient, signature, ledger transaction, Merkle proof and document
    version. A failure at any link is reported by name; nothing is upgraded to a
    success for the sake of the demonstration.
    """
    case = session.get(InvestigationCase, case_id)
    if case is None:
        raise NotFound(f"No investigation case {case_id}.")

    payload = file.file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        from ..core.exceptions import ForgeError

        raise ForgeError(
            "The submitted file exceeds the 64 MB prototype limit.",
            detail="Split the document or analyse it on a workstation with more headroom.",
        )
    staged = PATHS.render / f"evidence-{uuid.uuid4().hex}.pdf"
    staged.write_bytes(payload)
    try:
        evidence = forensic_service.store_evidence(
            session,
            case=case,
            investigator=investigator,
            leaked_path=staged,
            original_filename=file.filename or "submitted.pdf",
        )
        return {"analysis": forensic_service.analyze(session, evidence=evidence)}
    finally:
        staged.unlink(missing_ok=True)


class ExtractRequest(BaseModel):
    file_path: str = Field(min_length=1)
    document_id: str | None = None


@router.post("/forensics/extract")
def extract(
    payload: ExtractRequest,
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("forensics.analyze")),
) -> dict[str, Any]:
    """Watermark extraction only, without opening an investigation.

    Returns FOUND, WEAK MATCH, CORRUPTED or NOT FOUND with a measured
    confidence. A failure here is a legitimate outcome.
    """
    suspect = Path(payload.file_path)
    if not suspect.exists():
        raise NotFound(f"No file at {payload.file_path}.")
    verdict, result, versions = watermark_service.extract_and_match(
        session, suspect, document_id=payload.document_id
    )
    return {
        "verdict": verdict.as_dict(),
        "extraction": result.summary(),
        "candidate_versions": [v.version_id for v in versions],
    }


@router.post("/forensics/verify")
def verify(
    case_id: str = Form(...),
    evidence_id: str = Form(...),
    session: Session = Depends(db),
    _: Recipient = Depends(permitted("forensics.analyze")),
) -> dict[str, Any]:
    """Re-runs verification of stored evidence without touching the artefact."""
    evidence = session.get(EvidenceItem, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise NotFound(f"No evidence {evidence_id} in case {case_id}.")
    return {"analysis": forensic_service.analyze(session, evidence=evidence)}


@router.post("/forensics/evidence/{evidence_id}/report")
def report(
    evidence_id: str,
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("forensics.analyze")),
) -> dict[str, Any]:
    """Builds and hashes the formal evidence report."""
    evidence = session.get(EvidenceItem, evidence_id)
    if evidence is None:
        raise NotFound(f"No evidence {evidence_id}.")
    built = forensic_service.build_report(session, evidence=evidence, investigator=investigator)
    return {
        "report": built,
        "integrity": forensic_service.verify_report_integrity(Path(evidence.report_path)),
    }


@router.get("/forensics/evidence/{evidence_id}/report/integrity")
def report_integrity(
    evidence_id: str, session: Session = Depends(db), _: Recipient = Depends(readable("evidence.read"))
) -> dict[str, Any]:
    evidence = session.get(EvidenceItem, evidence_id)
    if evidence is None or not evidence.report_path:
        raise NotFound(f"No report for evidence {evidence_id}.")
    return forensic_service.verify_report_integrity(Path(evidence.report_path))


@router.get("/investigations")
def list_investigations(
    session: Session = Depends(db), _: Recipient = Depends(readable("evidence.read"))
) -> dict[str, Any]:
    return {"cases": forensic_service.list_cases(session)}


@router.post("/investigations")
def open_case(
    payload: CaseRequest,
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("investigation.manage")),
) -> dict[str, Any]:
    case = forensic_service.open_case(
        session,
        investigator=investigator,
        title=payload.title,
        summary_text=payload.summary,
        suspected_document_id=payload.suspected_document_id,
    )
    return {"case": forensic_service.describe_case(session, case.case_id)}


@router.get("/investigations/{case_id}")
def case_detail(
    case_id: str, session: Session = Depends(db), _: Recipient = Depends(readable("evidence.read"))
) -> dict[str, Any]:
    return {"case": forensic_service.describe_case(session, case_id)}


@router.post("/investigations/{case_id}/notes")
def add_note(
    case_id: str,
    payload: NoteRequest,
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("investigation.manage")),
) -> dict[str, Any]:
    return forensic_service.add_note(
        session, case_id=case_id, author_id=investigator.recipient_id, note=payload.note
    )


@router.post("/investigations/{case_id}/close")
def close_case(
    case_id: str,
    payload: CloseRequest,
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("investigation.manage")),
) -> dict[str, Any]:
    """Cases are closed, never deleted, so the investigative history survives."""
    return forensic_service.close_case(
        session, case_id=case_id, actor_id=investigator.recipient_id, conclusion=payload.conclusion
    )


class ExportRequest(BaseModel):
    case_id: str
    approval_id: str


@router.post("/evidence/export")
def export_evidence(
    payload: ExportRequest,
    session: Session = Depends(db),
    investigator: Recipient = Depends(permitted("evidence.export")),
) -> dict[str, Any]:
    """Exporting evidence outside the system is a two-person controlled action."""
    from ..services import approval_service

    approval_service.consume(
        session,
        approval_id=payload.approval_id,
        acting_role=investigator.role,
        expected_action="EVIDENCE_EXPORT",
    )
    case = forensic_service.describe_case(session, payload.case_id)
    return {
        "case_id": case["case_id"],
        "evidence": [item["evidence_id"] for item in case["evidence"]],
        "report_sha256": case.get("report_sha256"),
        "plain_explanation": (
            "Evidence export requires two separately authenticated identities and is recorded in the "
            "audit trail."
        ),
    }


@router.get("/watermarks/robustness")
def robustness(
    session: Session = Depends(db), _: Recipient = Depends(readable("evidence.read"))
) -> dict[str, Any]:
    """Runs the measured robustness probe so the published claim is backed by
    numbers from this deployment rather than from documentation."""
    from sqlalchemy import select

    from ..models.documents import DocumentVersion

    version = session.execute(
        select(DocumentVersion).order_by(DocumentVersion.version_id).limit(1)
    ).scalar_one_or_none()
    if version is None:
        raise NotFound("No document available to run the robustness probe.")
    return watermark_service.robustness_report(Path(version.normalized_pdf_path))
