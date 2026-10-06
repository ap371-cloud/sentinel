from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import PATHS, SETTINGS
from ..crypto.hashing import canonical_bytes, sha256_hex
from ..crypto.key_management import VAULT
from ..database import shared as shared_store
from ..models.documents import Document, DocumentVersion
from ..models.sessions import Watermark
from .audit_service import record as audit_record
from ..watermark.embedder import embed
from ..watermark.extractor import extract
from ..watermark.generator import PAYLOAD_BITS, derive_tag, derivation_inputs
from ..watermark.validation import RegistryCandidate, Verdict, judge
from ..watermark import visible as visible_wm


def issue_tag(
    *,
    recipient_id: str,
    document_id: str,
    document_hash: str,
    session_id: str,
    nonce: str,
) -> tuple[str, dict[str, Any]]:
    """Derives the tag for one decryption session.

    Inputs are hashed into an HMAC, so the tag carries no readable recipient
    identity. Two sessions for the same recipient and document produce
    different tags because the session id and the fresh nonce differ.
    """
    inputs = derivation_inputs(
        recipient_id=recipient_id,
        document_id=document_id,
        document_hash=document_hash,
        session_id=session_id,
        nonce=nonce,
        watermark_version=SETTINGS.watermark_version,
        policy_version=SETTINGS.policy_version,
    )
    return derive_tag(VAULT.watermark_root(), inputs), inputs


def inputs_fingerprint(inputs: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(inputs))


def embed_for_session(
    *,
    source_pdf: Path,
    output_pdf: Path,
    recipient_id: str,
    document: Document,
    version: DocumentVersion,
    session_id: str,
    nonce: str,
    tag: str,
) -> dict[str, Any]:
    result = embed(
        source_pdf,
        output_pdf,
        root_secret=VAULT.watermark_root(),
        document_id=document.document_id,
        document_hash=version.content_sha256,
        version_id=version.version_id,
        tag_hex=tag,
    )
    visible = visible_wm.stamp(
        output_pdf, document=document, recipient_id=recipient_id, session_id=session_id
    )
    shared_store.artefact_put_file(output_pdf)
    return {
        "output_path": str(output_pdf),
        "psnr_db": round(result.psnr_db, 2),
        "ssim": round(result.ssim_score, 4),
        "contrast_scale": round(result.contrast_scale, 4),
        "carriers_per_bit": result.carriers_per_bit,
        "payload_bits": result.payload_bits,
        "strength": SETTINGS.watermark_strength,
        "visible": visible,
    }


def register(
    session: Session,
    *,
    session_row,
    document: Document,
    version: DocumentVersion,
    tag: str,
    inputs: dict[str, Any],
    quality: dict[str, Any],
) -> Watermark:
    """Adds the tag to the registry.

    The registry row is a convenience index. The authoritative copy of this fact
    lives in the signed ledger event, so deleting a row here cannot erase the
    attribution — it only makes the lookup slower.
    """
    row = Watermark(
        watermark_id=f"WM-{session_row.session_id}",
        session_id=session_row.session_id,
        recipient_id=session_row.recipient_id,
        document_id=document.document_id,
        version_id=version.version_id,
        document_hash=version.content_sha256,
        derivation_inputs_hash=inputs_fingerprint(inputs),
        tag=tag,
        payload_bits=PAYLOAD_BITS,
        carriers_per_bit=quality["carriers_per_bit"],
        watermark_version=SETTINGS.watermark_version,
        policy_version=SETTINGS.policy_version,
        embedding_strength=quality["strength"],
        psnr_db=quality["psnr_db"],
        ssim=quality["ssim"],
        output_path=quality["output_path"],
    )
    session.add(row)
    return row


def registry_candidates(
    session: Session, *, document_id: str | None = None, version_id: str | None = None
) -> list[RegistryCandidate]:
    statement = select(Watermark)
    if document_id:
        statement = statement.where(Watermark.document_id == document_id)
    if version_id:
        statement = statement.where(Watermark.version_id == version_id)
    return [
        RegistryCandidate(
            watermark_id=row.watermark_id,
            tag=row.tag,
            session_id=row.session_id,
            recipient_id=row.recipient_id,
            document_id=row.document_id,
            version_id=row.version_id,
            carriers_per_bit=row.carriers_per_bit,
        )
        for row in session.execute(statement).scalars()
    ]


def extract_and_match(
    session: Session,
    suspect_pdf: Path,
    *,
    document_id: str | None = None,
    version_id: str | None = None,
) -> tuple[Verdict, ExtractionResult, list[DocumentVersion]]:
    """Blind extraction across candidate document versions.

    The watermark lives in the page image, and its carriers are keyed to the
    document identity rather than to the leaked file's own hash. That is what
    allows recovery from a copy whose bytes were edited, re-saved or rescaled,
    and it is why no part of this function needs the original document.
    """
    candidates = registry_candidates(session, document_id=document_id, version_id=version_id)
    versions = _candidate_versions(session, candidates)

    best_verdict: Verdict | None = None
    best_result = None
    for version in versions:
        result = extract(
            suspect_pdf,
            root_secret=VAULT.watermark_root(),
            document_id=version.document_id,
            document_hash=version.content_sha256,
            version_id=version.version_id,
            carriers_per_bit=candidates[0].carriers_per_bit if candidates else SETTINGS.carriers_per_bit,
        )
        scoped = [
            c for c in candidates if c.version_id == version.version_id
        ] or candidates
        verdict = judge(result, scoped)
        if best_verdict is None or verdict.confidence > best_verdict.confidence:
            best_verdict, best_result = verdict, result

    if best_verdict is None:
        best_result = extract(
            suspect_pdf,
            root_secret=VAULT.watermark_root(),
            document_id=document_id or "UNKNOWN",
            document_hash="0" * 64,
            version_id=version_id or "UNKNOWN",
        )
        best_verdict = judge(best_result, candidates)
    return best_verdict, best_result, versions


def _candidate_versions(session: Session, candidates: list[RegistryCandidate]) -> list[DocumentVersion]:
    seen: dict[str, DocumentVersion] = {}
    for candidate in candidates:
        if candidate.version_id in seen:
            continue
        row = session.get(DocumentVersion, candidate.version_id)
        if row is not None:
            seen[row.version_id] = row
    return list(seen.values())


def robustness_report(sample_source: Path, *, strength: float = SETTINGS.watermark_strength) -> dict[str, Any]:
    """Re-runs the embedding against common leak processing so the published
    robustness claim is measured rather than asserted."""
    import io

    import numpy as np
    from PIL import Image

    from ..documents.pdf import build_pdf, canonicalize, render_gray

    outcomes: list[dict[str, Any]] = []
    reference = render_gray(sample_source)[0]
    probe_tag = derive_tag(
        VAULT.watermark_root(),
        derivation_inputs(
            recipient_id="ROBUSTNESS-PROBE",
            document_id="ROBUSTNESS-PROBE",
            document_hash=sha256_hex(reference.tobytes()),
            session_id="ROBUSTNESS-PROBE",
            nonce="0" * 32,
            watermark_version=SETTINGS.watermark_version,
            policy_version=SETTINGS.policy_version,
        ),
    )
    marked_path = PATHS.render / "robustness_probe.pdf"
    embed(
        sample_source,
        marked_path,
        root_secret=VAULT.watermark_root(),
        document_id="ROBUSTNESS-PROBE",
        document_hash=sha256_hex(reference.tobytes()),
        version_id="ROBUSTNESS-PROBE",
        tag_hex=probe_tag,
        strength=strength,
    )
    marked_pages = render_gray(marked_path)

    def measure(label: str, pages: list[np.ndarray], scales: tuple[float, ...]) -> None:
        target = PATHS.render / f"robustness_{label}.pdf"
        build_pdf(pages, target)
        found = extract(
            target,
            root_secret=VAULT.watermark_root(),
            document_id="ROBUSTNESS-PROBE",
            document_hash=sha256_hex(reference.tobytes()),
            version_id="ROBUSTNESS-PROBE",
            scales=scales,
        ).best
        outcomes.append(
            {
                "transformation": label,
                "recovered": bool(found and found.recovered_tag == probe_tag),
                "carrier_to_noise_ratio": round(found.correlation, 2) if found else 0.0,
                "estimated_bit_errors": found.estimated_bit_errors if found else None,
            }
        )

    measure("clean", marked_pages, (1.0,))
    measure("pdf_resave", render_gray(build_and_reexport(marked_pages, PATHS.render / "robustness_resave.pdf")), (1.0,))

    jpeg_pages = []
    for page in marked_pages:
        image = Image.fromarray((np.clip(page, 0, 1) * 255).astype(np.uint8), mode="L")
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=70)
        buffer.seek(0)
        jpeg_pages.append(np.asarray(Image.open(buffer), dtype=np.float32) / 255.0)
    measure("jpeg_quality_70", jpeg_pages, (1.0,))
    measure("downscaled_50_percent", [page[::2, ::2] for page in marked_pages], (0.5, 1.0, 2.0))
    measure(
        "upscaled_150_percent",
        [np.repeat(np.repeat(page, 2, axis=0), 2, axis=1) for page in marked_pages],
        (2.0, 1.5, 1.0),
    )
    measure("canonicalised_reimport", [canonicalize(page, 1.0) for page in marked_pages], (1.0,))

    recovered = sum(1 for o in outcomes if o["recovered"])
    return {
        "transformations_tested": len(outcomes),
        "transformations_recovered": recovered,
        "results": outcomes,
        "tested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "known_limitations": [
            "A photograph taken at an angle, a heavy crop, or re-generation by an image model is "
            "not expected to survive and will report NOT FOUND.",
            "This is an invisible mark for forensic attribution. It does not prevent copying, "
            "photographing or screen capture, and it is not a data-loss-prevention control.",
        ],
    }


def build_and_reexport(pages, destination: Path) -> Path:
    from ..documents.pdf import build_pdf

    build_pdf(pages, destination)
    return destination
