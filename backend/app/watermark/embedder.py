from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..core.config import SETTINGS
from ..documents.pdf import build_pdf, psnr, render_gray, ssim
from .generator import PAYLOAD_BITS, carrier_seed, encode_payload

BLOCK = 8

#: Mid-frequency 8x8 DCT positions. Low frequencies carry visible structure and
#: survive cropping poorly; the top-right corner is discarded by JPEG and
#: downscaling. This band is the compromise that keeps the mark both invisible
#: and durable.
MID_FREQUENCY = ((1, 2), (2, 1), (1, 3), (3, 1))


def dct_matrix(size: int = BLOCK) -> np.ndarray:
    matrix = np.zeros((size, size), dtype=np.float32)
    for u in range(size):
        scale = np.sqrt(1.0 / size) if u == 0 else np.sqrt(2.0 / size)
        for x in range(size):
            matrix[u, x] = scale * np.cos(np.pi * (2 * x + 1) * u / (2 * size))
    return matrix


_DCT = dct_matrix()


def to_coefficients(grid: np.ndarray) -> np.ndarray:
    height, width = grid.shape
    blocks = grid.reshape(height // BLOCK, BLOCK, width // BLOCK, BLOCK).transpose(0, 2, 1, 3)
    return _DCT @ blocks @ _DCT.T


def from_coefficients(coeffs: np.ndarray, shape: tuple[int, int]) -> np.ndarray:
    blocks = _DCT.T @ coeffs @ _DCT
    block_h, block_w = blocks.shape[0], blocks.shape[1]
    return blocks.transpose(0, 2, 1, 3).reshape(block_h * BLOCK, block_w * BLOCK)[: shape[0], : shape[1]]


def _carrier_plan(
    root_secret: bytes,
    *,
    document_id: str,
    document_hash: str,
    version_id: str,
    page: int,
    block_count: int,
    carriers_per_bit: int,
    payload: np.ndarray,
):
    """Deterministic block selection, sign pattern and bit encoding.

    Identical on the embedding and extraction side and derived only from
    document identity, which is what makes recovery blind. The bit value rides
    on the sign of the correlation, so a bit of 0 is embedded as a negative
    excursion rather than as an absent one.
    """
    seed = carrier_seed(
        root_secret, document_id=document_id, document_hash=document_hash, version_id=version_id, page=page
    )
    rng = np.random.default_rng(seed)
    usable = block_count
    if usable < PAYLOAD_BITS:
        raise ValueError(
            f"Page offers only {usable} usable blocks, fewer than the {PAYLOAD_BITS} the payload needs. "
            "Increase the rendering resolution or shorten the document."
        )
    # A small or low-resolution page cannot host the full redundancy budget.
    # Reducing carriers keeps the mark recoverable instead of failing outright,
    # and the value actually used is recorded on the watermark.
    carriers_per_bit = max(8, min(carriers_per_bit, usable // PAYLOAD_BITS))
    needed = PAYLOAD_BITS * carriers_per_bit
    order = rng.permutation(usable)[:needed]
    signs = rng.choice(
        np.array([-1.0, 1.0], dtype=np.float32), size=(PAYLOAD_BITS, carriers_per_bit, len(MID_FREQUENCY))
    )
    bit_polarity = (2.0 * payload.astype(np.float32) - 1.0)[:, None, None]
    return (
        order.reshape(PAYLOAD_BITS, carriers_per_bit),
        signs,
        signs * bit_polarity,
        carriers_per_bit,
    )


@dataclass
class EmbeddingResult:
    pages: list[np.ndarray]
    psnr_db: float
    ssim_score: float
    carriers_per_bit: int
    payload_bits: int
    contrast_scale: float


def fit_range(page: np.ndarray) -> tuple[np.ndarray, float]:
    """Keeps the marked page inside 0..255 without destroying the mark.

    Text pages have saturated black glyphs on saturated white paper, so any
    added excursion clips. Clipping is not a small effect: measured on a
    two-page operational order it removed 45% of the watermark energy. Pulling
    the page very slightly towards mid-grey removes the clipping and costs only
    the small contrast factor applied here.
    """
    overshoot = max(0.0, float(page.max()) - 1.0, -float(page.min()))
    if overshoot <= 0.0:
        return page, 1.0
    scale = max(0.0, 1.0 - overshoot)
    return 0.5 + (page - 0.5) * scale, scale


def embed(
    pdf_path: Path,
    output_path: Path,
    *,
    root_secret: bytes,
    document_id: str,
    document_hash: str,
    version_id: str,
    tag_hex: str,
    strength: float = SETTINGS.watermark_strength,
    carriers_per_bit: int = SETTINGS.carriers_per_bit,
) -> EmbeddingResult:
    """Adds the keyed mark to every page of the document.

    Strength is expressed directly in 8x8 DCT coefficient units because that is
    the only scale where "how strong" is meaningful for this embedding.
    """
    payload = encode_payload(tag_hex)
    pages = render_gray(pdf_path)
    original = [page.copy() for page in pages]
    embedded: list[np.ndarray] = []
    scales: list[float] = []
    carriers_used: list[int] = []

    for index, page in enumerate(pages):
        coeffs = to_coefficients(page)
        block_h, block_w = coeffs.shape[0], coeffs.shape[1]
        layout, _signs, deltas, used_carriers = _carrier_plan(
            root_secret,
            document_id=document_id,
            document_hash=document_hash,
            version_id=version_id,
            page=index,
            block_count=block_h * block_w,
            carriers_per_bit=carriers_per_bit,
            payload=payload,
        )
        flat = coeffs.reshape(-1, BLOCK, BLOCK)
        block_indices = layout.ravel()
        scaled = deltas * np.float32(strength)
        for slot, (row, col) in enumerate(MID_FREQUENCY):
            flat[block_indices, row, col] += scaled[:, :, slot].ravel()
        marked, scale = fit_range(from_coefficients(flat.reshape(block_h, block_w, BLOCK, BLOCK), page.shape))
        embedded.append(marked)
        scales.append(scale)
        carriers_used.append(used_carriers)

    build_pdf(embedded, output_path)
    return EmbeddingResult(
        pages=embedded,
        psnr_db=_mean_metric(original, embedded, psnr),
        ssim_score=_mean_metric(original, embedded, ssim),
        carriers_per_bit=min(carriers_used),
        payload_bits=PAYLOAD_BITS,
        contrast_scale=float(np.mean(scales)),
    )


def _mean_metric(before: list[np.ndarray], after: list[np.ndarray], metric) -> float:
    values = [metric(a, b) for a, b in zip(before, after)]
    return float(np.mean(values))


