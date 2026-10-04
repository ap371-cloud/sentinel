from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..core.config import SETTINGS
from .extractor import ExtractionResult
from .generator import hamming

FOUND = "FOUND"
WEAK_MATCH = "WEAK MATCH"
CORRUPTED = "CORRUPTED"
NOT_FOUND = "NOT FOUND"

STATUS_EXPLANATIONS = {
    FOUND: (
        "A registered watermark was recovered with a bit-exact tag, an intact integrity check and a "
        "carrier-to-noise ratio above the confident-recovery threshold."
    ),
    WEAK_MATCH: (
        "The recovered tag is close to a registered watermark but not identical, or the signal is "
        "marginal. Treat this as a lead requiring corroboration, never as proof on its own."
    ),
    CORRUPTED: (
        "Watermark structure was detected and the payload passed its integrity check, but the tag "
        "does not correspond to any registered decryption session."
    ),
    NOT_FOUND: (
        "No usable watermark carrier energy was found. The copy may have been re-photographed at an "
        "angle, heavily cropped, printed and scanned, or had the watermark deliberately removed."
    ),
}


@dataclass
class Verdict:
    status: str
    tag: str | None
    confidence: float
    explanation: str
    carrier_to_noise: float
    estimated_bit_errors: int
    integrity_check_passed: bool
    matched_watermark_id: str | None = None
    matched_session_id: str | None = None
    matched_recipient_id: str | None = None
    matched_document_id: str | None = None
    matched_version_id: str | None = None
    hamming_distance: int | None = None
    considered_candidates: int = 0
    matched_carriers_per_bit: int | None = None
    attempts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def attributed(self) -> bool:
        return self.status in (FOUND, WEAK_MATCH) and self.matched_session_id is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "recovered_tag": self.tag,
            "confidence": self.confidence,
            "carrier_to_noise_ratio": round(self.carrier_to_noise, 3),
            "estimated_bit_errors": self.estimated_bit_errors,
            "integrity_check_passed": self.integrity_check_passed,
            "matched_watermark_id": self.matched_watermark_id,
            "matched_session_id": self.matched_session_id,
            "matched_recipient_id": self.matched_recipient_id,
            "matched_document_id": self.matched_document_id,
            "matched_version_id": self.matched_version_id,
            "hamming_distance": self.hamming_distance,
            "candidates_considered": self.considered_candidates,
            "matched_carriers_per_bit": self.matched_carriers_per_bit,
            "attributable": self.attributed,
            "plain_explanation": self.explanation,
            "attempts": self.attempts,
        }


@dataclass(frozen=True)
class RegistryCandidate:
    watermark_id: str
    tag: str
    session_id: str
    recipient_id: str
    document_id: str
    version_id: str
    carriers_per_bit: int


def judge(
    result: ExtractionResult,
    candidates: Iterable[RegistryCandidate],
    *,
    found_threshold: float = SETTINGS.found_threshold,
    weak_threshold: float = SETTINGS.weak_threshold,
    hamming_limit: int = SETTINGS.match_hamming_limit,
) -> Verdict:
    """Turns a correlation result into an honest verdict.

    A confident attribution is only ever reported when a registered tag matches
    exactly, the payload's integrity check survived, and the carriers carry
    measurably more energy than the page noise floor. Nothing is rounded up to a
    success for the sake of a demonstration.
    """
    best = result.best
    candidate_list = list(candidates)
    if best is None:
        return Verdict(
            status=NOT_FOUND,
            tag=None,
            confidence=0.0,
            explanation=STATUS_EXPLANATIONS[NOT_FOUND],
            carrier_to_noise=0.0,
            estimated_bit_errors=-1,
            integrity_check_passed=False,
            considered_candidates=len(candidate_list),
            attempts=[a.as_dict() for a in result.attempts],
        )

    cnr = best.correlation
    signal_quality = min(1.0, cnr / max(found_threshold * 2.0, 1e-6))

    closest: RegistryCandidate | None = None
    distance = 65
    for candidate in candidate_list:
        candidate_distance = hamming(best.recovered_tag, candidate.tag)
        if candidate_distance < distance:
            distance, closest = candidate_distance, candidate

    exact = closest is not None and distance == 0
    if exact and best.check_passed and cnr >= found_threshold:
        # Deliberately capped below 1.0. A recovered watermark is strong
        # evidence, never certainty: the copy could still have been altered in a
        # way that leaves the mark intact, and no extraction result should read
        # as an unqualified guarantee.
        status = FOUND
        confidence = round(min(0.99, 0.7 + 0.29 * signal_quality), 4)
    elif closest is not None and distance <= hamming_limit and cnr >= weak_threshold:
        status = WEAK_MATCH
        confidence = round(min(0.75, 0.5 * (1.0 - distance / 16.0) + 0.25 * signal_quality), 4)
    elif best.check_passed and cnr >= weak_threshold:
        status = CORRUPTED
        confidence = round(0.3 * signal_quality, 4)
    else:
        status = NOT_FOUND
        confidence = round(0.1 * signal_quality, 4)

    attributable = status in (FOUND, WEAK_MATCH) and closest is not None
    return Verdict(
        status=status,
        tag=best.recovered_tag,
        confidence=confidence,
        explanation=STATUS_EXPLANATIONS[status],
        carrier_to_noise=cnr,
        estimated_bit_errors=best.estimated_bit_errors,
        integrity_check_passed=best.check_passed,
        matched_watermark_id=closest.watermark_id if attributable else None,
        matched_session_id=closest.session_id if attributable else None,
        matched_recipient_id=closest.recipient_id if attributable else None,
        matched_document_id=closest.document_id if closest else None,
        matched_version_id=closest.version_id if closest else None,
        hamming_distance=distance if distance < 65 else None,
        considered_candidates=len(candidate_list),
        matched_carriers_per_bit=closest.carriers_per_bit if attributable else None,
        attempts=[a.as_dict() for a in result.attempts],
    )
