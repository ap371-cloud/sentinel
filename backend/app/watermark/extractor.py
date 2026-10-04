from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from ..core.config import SETTINGS
from ..documents.pdf import canonicalize, render_gray
from .embedder import MID_FREQUENCY, _carrier_plan, to_coefficients
from .error_correction import SoftDecision, combine, estimate_bit_errors
from .generator import PAYLOAD_BITS, decode_payload


@dataclass
class ExtractionAttempt:
    scale: float
    page: int
    correlation: float
    noise_sigma: float
    agreed_fraction: float
    recovered_tag: str
    check_passed: bool
    estimated_bit_errors: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "raster_scale": self.scale,
            "page": self.page,
            "carrier_to_noise_ratio": round(self.correlation, 3),
            "noise_sigma": round(self.noise_sigma, 6),
            "carrier_agreement": round(self.agreed_fraction, 4),
            "recovered_tag": self.recovered_tag,
            "integrity_check_passed": self.check_passed,
            "estimated_bit_errors": self.estimated_bit_errors,
        }


@dataclass
class ExtractionResult:
    attempts: list[ExtractionAttempt]
    best: ExtractionAttempt | None
    payload_bits: int
    carriers_per_bit: int
    method: str = "BLIND — keyed spread-spectrum correlation; the original document is not an input"

    def summary(self) -> dict[str, Any]:
        return {
            "payload_bits": self.payload_bits,
            "carriers_per_bit": self.carriers_per_bit,
            "extraction_method": self.method,
            "attempted_raster_scales": list(SETTINGS.extraction_scales),
            "best_attempt": self.best.as_dict() if self.best else None,
            "attempts": [a.as_dict() for a in self.attempts],
        }


def _scores_for_page(
    grid: np.ndarray,
    *,
    root_secret: bytes,
    document_id: str,
    document_hash: str,
    version_id: str,
    page_index: int,
    carriers_per_bit: int,
) -> np.ndarray:
    coeffs = to_coefficients(grid)
    block_h, block_w = coeffs.shape[0], coeffs.shape[1]
    layout, signs, _polarised, used_carriers = _carrier_plan(
        root_secret,
        document_id=document_id,
        document_hash=document_hash,
        version_id=version_id,
        page=page_index,
        block_count=block_h * block_w,
        carriers_per_bit=carriers_per_bit,
        payload=np.zeros(PAYLOAD_BITS, dtype=np.int8),
    )
    flat = coeffs.reshape(-1, 8, 8)
    projections = np.zeros((PAYLOAD_BITS, used_carriers), dtype=np.float32)
    for slot, (row, col) in enumerate(MID_FREQUENCY):
        sampled = flat[layout.ravel(), row, col].reshape(PAYLOAD_BITS, used_carriers)
        projections += sampled * signs[:, :, slot]
    return projections / len(MID_FREQUENCY)


def _page_has_room(grid: np.ndarray, carriers_per_bit: int) -> bool:
    return (grid.shape[0] // 8) * (grid.shape[1] // 8) >= PAYLOAD_BITS * 8


def extract(
    pdf_path: Path,
    *,
    root_secret: bytes,
    document_id: str,
    document_hash: str,
    version_id: str,
    carriers_per_bit: int = SETTINGS.carriers_per_bit,
    scales: tuple[float, ...] = SETTINGS.extraction_scales,
) -> ExtractionResult:
    """Blind recovery.

    The original document is deliberately not an input. An investigator supplies
    a suspected leaked file plus a candidate document version from the public
    registry; the keyed carrier pattern is rebuilt from the registry values, so
    a copy that has been re-saved, recompressed or rescaled still shows a
    correlation peak, and a file whose bytes were edited still yields nothing
    because the carriers live in the page image rather than in the metadata.
    """
    rendered = render_gray(pdf_path)
    attempts: list[ExtractionAttempt] = []

    for scale in scales:
        for page_index, page in enumerate(rendered):
            grid = canonicalize(page, scale)
            if not _page_has_room(grid, carriers_per_bit):
                continue
            scores = _scores_for_page(
                grid,
                root_secret=root_secret,
                document_id=document_id,
                document_hash=document_hash,
                version_id=version_id,
                page_index=page_index,
                carriers_per_bit=carriers_per_bit,
            )
            decision: SoftDecision = combine(scores)
            recovered, _ones, check_ok = decode_payload(decision.decided)

            attempts.append(
                ExtractionAttempt(
                    scale=scale,
                    page=page_index,
                    correlation=decision.carrier_to_noise,
                    noise_sigma=decision.noise_sigma_mean,
                    agreed_fraction=decision.agreed_fraction,
                    recovered_tag=recovered,
                    check_passed=check_ok,
                    estimated_bit_errors=estimate_bit_errors(decision),
                )
            )

    best = max(
        attempts,
        key=lambda a: (a.agreed_fraction, a.correlation, -a.estimated_bit_errors),
        default=None,
    )
    return ExtractionResult(
        attempts=attempts,
        best=best,
        payload_bits=PAYLOAD_BITS,
        carriers_per_bit=carriers_per_bit,
    )
