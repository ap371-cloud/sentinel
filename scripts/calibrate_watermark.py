"""Calibrates watermark strength and carrier count against measured image
quality and measured extraction signal-to-noise.

Run this before changing SETTINGS.watermark_strength or SETTINGS.carriers_per_bit:

    python scripts/calibrate_watermark.py
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import numpy as np  # noqa: E402
import pymupdf  # noqa: E402
from PIL import Image  # noqa: E402

from app.core.config import PATHS  # noqa: E402
from app.documents.pdf import build_pdf, canonicalize, psnr, render_gray, ssim  # noqa: E402
from app.watermark.embedder import embed  # noqa: E402
from app.watermark.extractor import extract  # noqa: E402
from app.watermark.generator import derive_tag, derivation_inputs  # noqa: E402

ROOT_SECRET = b"calibration-root-secret-0123456789"
DOCUMENT_ID, DOCUMENT_HASH, VERSION_ID = "DOC-CAL", "a" * 64, "VER-CAL"

GRID = [(0.02, 256), (0.02, 512), (0.03, 384), (0.03, 512), (0.04, 512), (0.05, 512)]
TRANSFORMATIONS = ("clean", "pdf_resave", "jpeg_quality_70", "downscaled_50", "upscaled_150")


def sample_document(path: Path) -> None:
    document = pymupdf.open()
    for page_index in range(2):
        page = document.new_page(width=595, height=842)
        body = (
            "SYNTHETIC CALIBRATION DOCUMENT\n\n"
            "1. Element posture is confirmed at 0600 and reported through the chain.\n"
            "2. Two officers from each company attend the briefing.\n"
            "3. Equipment draw is signed against the quartermaster record.\n\n"
        ) * 7
        page.insert_textbox(pymupdf.Rect(56, 56, 540, 790), body, fontsize=11)
    document.save(path)
    document.close()


def tag_for(session_label: str) -> str:
    return derive_tag(
        ROOT_SECRET,
        derivation_inputs(
            recipient_id="REC-001",
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            session_id=session_label,
            nonce="0" * 32,
            watermark_version="WM-1.0",
            policy_version="POL-1.0",
        ),
    )


def transform(pages, label: str, destination: Path):
    if label == "jpeg_quality_70":
        out = []
        for page in pages:
            image = Image.fromarray((np.clip(page, 0, 1) * 255).astype(np.uint8), mode="L")
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=70)
            buffer.seek(0)
            out.append(np.asarray(Image.open(buffer), dtype=np.float32) / 255.0)
        pages = out
    elif label == "downscaled_50":
        pages = [page[::2, ::2] for page in pages]
    elif label == "upscaled_150":
        pages = [np.repeat(np.repeat(page, 2, axis=0), 2, axis=1) for page in pages]
    elif label == "pdf_resave":
        staging = destination.with_suffix(".stage.pdf")
        build_pdf(pages, staging)
        pages = render_gray(staging)
    build_pdf(pages, destination)
    return pages


SCALE_HINTS = {
    "clean": (1.0,),
    "pdf_resave": (1.0,),
    "jpeg_quality_70": (1.0,),
    "downscaled_50": (0.5, 1.0, 2.0),
    "upscaled_150": (2.0, 1.5, 1.0),
}


def measure(source: Path, strength: float, carriers: int) -> dict:
    tag = tag_for(f"CAR-{carriers}")
    marked = PATHS.render / f"cal_{strength}_{carriers}.pdf"
    quality = embed(
        source,
        marked,
        root_secret=ROOT_SECRET,
        document_id=DOCUMENT_ID,
        document_hash=DOCUMENT_HASH,
        version_id=VERSION_ID,
        tag_hex=tag,
        strength=strength,
        carriers_per_bit=carriers,
    )
    clean = render_gray(marked)
    baseline = render_gray(source)
    results = {}
    for label in TRANSFORMATIONS:
        target = PATHS.render / f"cal_{strength}_{carriers}_{label}.pdf"
        transform(clean, label, target)
        found = extract(
            target,
            root_secret=ROOT_SECRET,
            document_id=DOCUMENT_ID,
            document_hash=DOCUMENT_HASH,
            version_id=VERSION_ID,
            carriers_per_bit=carriers,
            scales=SCALE_HINTS[label],
        ).best
        results[label] = {
            "recovered": bool(found and found.recovered_tag == tag),
            "carrier_to_noise": round(found.correlation, 2) if found else 0.0,
            "bit_errors": found.estimated_bit_errors if found else None,
        }
    return {
        "strength": strength,
        "carriers_per_bit": carriers,
        "psnr_db": round(quality.psnr_db, 2),
        "ssim": round(quality.ssim_score, 4),
        "contrast_scale": round(quality.contrast_scale, 4),
        "raster_roundtrip_psnr_db": round(
            float(np.mean([psnr(a, b) for a, b in zip(baseline, clean)])), 2
        ),
        "raster_roundtrip_ssim": round(
            float(np.mean([ssim(a, b) for a, b in zip(baseline, clean)])), 4
        ),
        "transformations": results,
        "recovered_count": sum(1 for r in results.values() if r["recovered"]),
    }


def main() -> None:
    source = PATHS.render / "calibration_source.pdf"
    sample_document(source)
    print(
        f"{'strength':>8} {'carriers':>8} {'PSNR':>7} {'SSIM':>7} {'rasterPSNR':>10} {'rasterSSIM':>10} "
        f"{'minCNR':>7} {'recovered':>10}"
    )
    rows = []
    for strength, carriers in GRID:
        row = measure(source, strength, carriers)
        rows.append(row)
        worst_cnr = min(r["carrier_to_noise"] for r in row["transformations"].values())
        print(
            f"{row['strength']:>8.3f} {row['carriers_per_bit']:>8} {row['psnr_db']:>7.2f} {row['ssim']:>7.4f} "
            f"{row['raster_roundtrip_psnr_db']:>10.2f} {row['raster_roundtrip_ssim']:>10.4f} "
            f"{worst_cnr:>7.2f} {row['recovered_count']:>6}/{len(TRANSFORMATIONS)}"
        )

    print("\nper-transformation detail:")
    for row in rows:
        detail = "  ".join(
            f"{label}={'OK' if r['recovered'] else 'MISS'}({r['carrier_to_noise']:.1f})"
            for label, r in row["transformations"].items()
        )
        print(f"  strength={row['strength']:<5} carriers={row['carriers_per_bit']:<5} {detail}")

    (PATHS.render / "calibration.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nwritten to {PATHS.render / 'calibration.json'}")


if __name__ == "__main__":
    main()
