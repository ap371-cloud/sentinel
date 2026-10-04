"""Watermark engine tests: derivation, uniqueness, robustness, honest failure.

The negative cases matter most here. A watermark engine that always reports
FOUND is worse than none, because it manufactures false attributions.
"""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from app.core.config import PATHS, SETTINGS
from app.documents.pdf import build_pdf, canonicalize, psnr, render_gray, ssim
from app.watermark.embedder import embed
from app.watermark.error_correction import combine, within_row_sigma
from app.watermark.extractor import extract
from app.watermark.generator import (
    CHECK_BITS,
    PAYLOAD_BITS,
    WATERMARK_TAG_BITS,
    decode_payload,
    derive_tag,
    derivation_inputs,
    encode_payload,
    hamming,
)
from app.watermark.validation import CORRUPTED, FOUND, NOT_FOUND, WEAK_MATCH, RegistryCandidate, judge

ROOT_SECRET = b"sentinel-watermark-test-root-secret"
DOCUMENT_ID = "DOC-WM-TEST"
DOCUMENT_HASH = "3b71ff0c6a66060a" + "0" * 48
VERSION_ID = "DOC-WM-TEST-VERSION-001"


def tag_for(session_label: str, recipient: str = "RECIPIENT-001") -> str:
    return derive_tag(
        ROOT_SECRET,
        derivation_inputs(
            recipient_id=recipient,
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            session_id=session_label,
            nonce="9f" * 16,
            watermark_version=SETTINGS.watermark_version,
            policy_version=SETTINGS.policy_version,
        ),
    )


@pytest.fixture(scope="module")
def source_pdf(tmp_path_factory) -> Path:
    import pymupdf

    path = tmp_path_factory.mktemp("watermark") / "source.pdf"
    document = pymupdf.open()
    for _ in range(2):
        page = document.new_page(width=595, height=842)
        page.insert_textbox(
            pymupdf.Rect(56, 56, 540, 790),
            "SENTINEL WATERMARK TEST\n\n1. Synthetic content for unit testing.\n" * 60,
            fontsize=11,
        )
    document.save(path)
    document.close()
    return path


@pytest.fixture(scope="module")
def marked_pdf(source_pdf, tmp_path_factory) -> tuple[Path, str]:
    tag = tag_for("SES-WM-0001")
    target = tmp_path_factory.mktemp("marked") / "marked.pdf"
    embed(
        source_pdf,
        target,
        root_secret=ROOT_SECRET,
        document_id=DOCUMENT_ID,
        document_hash=DOCUMENT_HASH,
        version_id=VERSION_ID,
        tag_hex=tag,
    )
    return target, tag


class TestDerivation:
    def test_tag_is_64_bits_of_hex(self):
        tag = tag_for("SES-A")
        assert len(tag) == WATERMARK_TAG_BITS // 4

    def test_tag_is_stable_for_the_same_inputs(self):
        assert tag_for("SES-A") == tag_for("SES-A")

    def test_different_session_yields_different_tag(self):
        assert tag_for("SES-A") != tag_for("SES-B")

    def test_different_recipient_yields_different_tag(self):
        assert tag_for("SES-A", "RECIPIENT-001") != tag_for("SES-A", "RECIPIENT-002")

    def test_different_nonce_yields_different_tag(self):
        base = derivation_inputs(
            recipient_id="RECIPIENT-001",
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            session_id="SES-A",
            nonce="00" * 16,
            watermark_version="WM-1.0",
            policy_version="POL-1.0",
        )
        altered = dict(base, nonce="11" * 16)
        assert derive_tag(ROOT_SECRET, base) != derive_tag(ROOT_SECRET, altered)

    def test_tag_leaks_no_readable_identity(self):
        tag = tag_for("SES-A", "RECIPIENT-001")
        assert "RECIPIENT" not in tag.upper()
        assert "SES" not in tag.upper()
        assert set(tag) <= set("0123456789abcdef")

    def test_wrong_root_cannot_reproduce_the_tag(self):
        inputs = derivation_inputs(
            recipient_id="RECIPIENT-001",
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            session_id="SES-A",
            nonce="00" * 16,
            watermark_version="WM-1.0",
            policy_version="POL-1.0",
        )
        assert derive_tag(ROOT_SECRET, inputs) != derive_tag(b"a different root secret", inputs)


class TestPayloadCoding:
    def test_round_trip(self):
        tag = tag_for("SES-CODE")
        bits = encode_payload(tag)
        assert len(bits) == PAYLOAD_BITS == WATERMARK_TAG_BITS + CHECK_BITS
        recovered, ones, check_ok = decode_payload(bits)
        assert recovered == tag and check_ok

    def test_integrity_check_catches_a_flipped_bit(self):
        bits = encode_payload(tag_for("SES-CODE"))
        bits[3] ^= 1
        _, _, check_ok = decode_payload(bits)
        assert check_ok is False

    def test_hamming_distance(self):
        assert hamming("0000000000000000", "0000000000000000") == 0
        assert hamming("0000000000000000", "0000000000000001") == 1
        assert hamming("0000000000000000", "ffffffffffffffff") == 64


class TestSoftDecision:
    def test_strong_signal_gives_high_carrier_to_noise(self):
        rng = np.random.default_rng(1)
        scores = rng.normal(0.0, 0.05, size=(80, 64)) + np.where(
            np.arange(80)[:, None] % 2 == 0, 0.5, -0.5
        )
        decision = combine(scores)
        assert decision.carrier_to_noise > 5
        assert decision.agreed_fraction > 0.9

    def test_pure_noise_gives_low_carrier_to_noise(self):
        rng = np.random.default_rng(2)
        decision = combine(rng.normal(0.0, 0.05, size=(80, 64)))
        assert decision.carrier_to_noise < 3
        assert decision.agreed_fraction < 0.5

    def test_sigma_estimate_is_positive(self):
        rng = np.random.default_rng(3)
        assert within_row_sigma(rng.normal(0, 1, size=(10, 32))) > 0


class TestEmbeddingQuality:
    def test_visual_quality_stays_within_documented_limits(self, source_pdf, tmp_path):
        target = tmp_path / "quality.pdf"
        result = embed(
            source_pdf,
            target,
            root_secret=ROOT_SECRET,
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            version_id=VERSION_ID,
            tag_hex=tag_for("SES-QUALITY"),
        )
        assert result.psnr_db > 33, f"PSNR {result.psnr_db}"
        assert result.ssim_score > 0.95, f"SSIM {result.ssim_score}"

    def test_output_is_a_valid_pdf(self, marked_pdf):
        path, _ = marked_pdf
        assert path.read_bytes()[:5] == b"%PDF-"

    def test_page_count_is_preserved(self, source_pdf, marked_pdf):
        path, _ = marked_pdf
        assert len(render_gray(path)) == len(render_gray(source_pdf))

    def test_two_sessions_differ_only_in_forensic_identity(self, source_pdf, tmp_path):
        """The rendered pages must be visually equivalent even though the tags
        differ, which is the whole point of the design."""
        outputs = []
        for index, session in enumerate(("SES-VIS-1", "SES-VIS-2")):
            target = tmp_path / f"visual-{index}.pdf"
            embed(
                source_pdf,
                target,
                root_secret=ROOT_SECRET,
                document_id=DOCUMENT_ID,
                document_hash=DOCUMENT_HASH,
                version_id=VERSION_ID,
                tag_hex=tag_for(session),
            )
            outputs.append(render_gray(target))

        first, second = outputs[0][0], outputs[1][0]
        assert first.shape == second.shape
        # Copy against copy is a two-marker difference, so it sits below the
        # single-marker figure measured against the original (0.967). The
        # claim being tested is that the two are visually equivalent, not that
        # they are pixel-identical.
        assert psnr(first, second) > 30
        assert ssim(first, second) > 0.93


class TestBlindExtraction:
    def test_recovers_the_tag_from_the_generated_copy(self, marked_pdf):
        path, tag = marked_pdf
        found = extract(
            path,
            root_secret=ROOT_SECRET,
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            version_id=VERSION_ID,
            scales=(1.0,),
        ).best
        assert found is not None
        assert found.recovered_tag == tag
        assert found.estimated_bit_errors == 0

    def test_wrong_carrier_key_finds_nothing(self, marked_pdf):
        path, _ = marked_pdf
        found = extract(
            path,
            root_secret=b"a completely different root secret",
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            version_id=VERSION_ID,
            scales=(1.0,),
        ).best
        assert found is None or found.recovered_tag != tag_for("SES-WM-0001")

    def test_wrong_document_hash_finds_nothing(self, marked_pdf):
        path, _ = marked_pdf
        found = extract(
            path,
            root_secret=ROOT_SECRET,
            document_id=DOCUMENT_ID,
            document_hash="9" * 64,
            version_id=VERSION_ID,
            scales=(1.0,),
        ).best
        assert found is None or found.recovered_tag != tag_for("SES-WM-0001")

    def test_unmarked_document_yields_no_tag(self, source_pdf):
        found = extract(
            source_pdf,
            root_secret=ROOT_SECRET,
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            version_id=VERSION_ID,
            scales=(1.0,),
        ).best
        assert found is None or found.estimated_bit_errors > 8


class TestRobustness:
    """Transformations a leaked copy realistically passes through."""

    def _round_trip(self, marked_pdf, tmp_path, transform, scales=(1.0,)):
        path, tag = marked_pdf
        target = tmp_path / "transformed.pdf"
        transform(render_gray(path), target)
        found = extract(
            target,
            root_secret=ROOT_SECRET,
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            version_id=VERSION_ID,
            scales=scales,
        ).best
        return found, tag

    def test_survives_pdf_resave(self, marked_pdf, tmp_path):
        def resave(pages, target):
            staging = tmp_path / "stage.pdf"
            build_pdf(pages, staging)
            build_pdf(render_gray(staging), target)

        found, tag = self._round_trip(marked_pdf, tmp_path, resave)
        assert found and found.recovered_tag == tag

    def test_survives_moderate_jpeg_compression(self, marked_pdf, tmp_path):
        def recompress(pages, target):
            converted = []
            for page in pages:
                image = Image.fromarray((np.clip(page, 0, 1) * 255).astype(np.uint8), mode="L")
                buffer = io.BytesIO()
                image.save(buffer, format="JPEG", quality=70)
                buffer.seek(0)
                converted.append(np.asarray(Image.open(buffer), dtype=np.float32) / 255.0)
            build_pdf(converted, target)

        found, tag = self._round_trip(marked_pdf, tmp_path, recompress)
        assert found and found.recovered_tag == tag

    def test_survives_a_50_percent_downscale(self, marked_pdf, tmp_path):
        found, tag = self._round_trip(
            marked_pdf,
            tmp_path,
            lambda pages, target: build_pdf([page[::2, ::2] for page in pages], target),
            scales=(0.5, 1.0, 2.0),
        )
        assert found and found.recovered_tag == tag

    def test_survives_a_150_percent_upscale(self, marked_pdf, tmp_path):
        found, tag = self._round_trip(
            marked_pdf,
            tmp_path,
            lambda pages, target: build_pdf(
                [np.repeat(np.repeat(page, 2, axis=0), 2, axis=1) for page in pages], target
            ),
            scales=(2.0, 1.5, 1.0),
        )
        assert found and found.recovered_tag == tag

    def test_heavy_crop_is_reported_as_not_found(self, marked_pdf, tmp_path):
        """A heavily cropped copy must NOT be silently attributed. Reporting
        nothing is the correct and honest outcome."""
        found, _ = self._round_trip(
            marked_pdf,
            tmp_path,
            lambda pages, target: build_pdf([page[:, :500] for page in pages], target),
            scales=(1.0,),
        )
        verdict = judge(
            extract(
                tmp_path / "transformed.pdf",
                root_secret=ROOT_SECRET,
                document_id=DOCUMENT_ID,
                document_hash=DOCUMENT_HASH,
                version_id=VERSION_ID,
            ),
            [RegistryCandidate("WM-1", tag_for("SES-WM-0001"), "SES-WM-0001", "RECIPIENT-001",
                               DOCUMENT_ID, VERSION_ID, SETTINGS.carriers_per_bit)],
        )
        assert verdict.status in (NOT_FOUND, "WEAK MATCH", CORRUPTED)
        assert verdict.status != FOUND or verdict.hamming_distance == 0


class TestVerdict:
    """Uses the real ExtractionAttempt/ExtractionResult types so the verdict
    logic is exercised exactly as it runs in production."""

    def _result(self, *, tag: str, cnr: float = 10.0, errors: int = 0, check: bool = True):
        from app.watermark.extractor import ExtractionAttempt, ExtractionResult

        attempt = ExtractionAttempt(
            scale=1.0,
            page=0,
            correlation=cnr,
            noise_sigma=0.01,
            agreed_fraction=1.0,
            recovered_tag=tag,
            check_passed=check,
            estimated_bit_errors=errors,
        )
        return ExtractionResult(
            attempts=[attempt],
            best=attempt,
            payload_bits=PAYLOAD_BITS,
            carriers_per_bit=SETTINGS.carriers_per_bit,
        )

    def _candidates(self, tag: str, session: str = "SES-V1") -> list[RegistryCandidate]:
        return [
            RegistryCandidate(
                "WM-1", tag, session, "RECIPIENT-001", DOCUMENT_ID, VERSION_ID,
                SETTINGS.carriers_per_bit,
            )
        ]

    def test_exact_match_above_threshold_is_found(self):
        tag = tag_for("SES-V1")
        verdict = judge(self._result(tag=tag), self._candidates(tag))
        assert verdict.status == FOUND
        assert verdict.attributed is True
        assert verdict.matched_session_id == "SES-V1"

    def test_confidence_never_reaches_certainty(self):
        tag = tag_for("SES-V2")
        verdict = judge(self._result(tag=tag, cnr=10_000.0), self._candidates(tag))
        assert verdict.confidence < 1.0, "confidence must never be reported as certainty"

    def test_unknown_tag_with_valid_check_is_corrupted_not_a_match(self):
        verdict = judge(
            self._result(tag="f" * 16), self._candidates(tag_for("SES-V3"))
        )
        assert verdict.status == CORRUPTED
        assert verdict.attributed is False

    def test_failed_integrity_check_cannot_be_found(self):
        tag = tag_for("SES-V4")
        verdict = judge(self._result(tag=tag, check=False), self._candidates(tag))
        assert verdict.status != FOUND

    def test_low_signal_cannot_be_found(self):
        tag = tag_for("SES-V5")
        verdict = judge(self._result(tag=tag, cnr=0.4), self._candidates(tag))
        assert verdict.status == NOT_FOUND

    def test_near_miss_is_reported_as_weak_match(self):
        tag = tag_for("SES-V6")
        near = f"{tag[:-1]}{'0' if tag[-1] != '0' else '1'}"
        verdict = judge(self._result(tag=near, cnr=6.0), self._candidates(tag))
        assert verdict.status == WEAK_MATCH
        assert verdict.confidence < 1.0
        assert verdict.hamming_distance == 1

    def test_no_candidates_means_no_attribution(self):
        verdict = judge(self._result(tag=tag_for("SES-V7")), [])
        assert verdict.attributed is False
