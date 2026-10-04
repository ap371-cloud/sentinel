from __future__ import annotations

from pathlib import Path
from typing import Any

import pymupdf as fitz
import numpy as np

from ..core.config import SETTINGS

TEXT_PAGE_WIDTH = 595
TEXT_PAGE_HEIGHT = 842


def normalize_to_pdf(source: Path, destination: Path) -> dict[str, Any]:
    """Everything becomes a PDF before sealing.

    The prototype rasterises content during watermark embedding, which means an
    uploaded text file loses selectable text in its watermarked output. That is
    a deliberate trade-off of pixel-domain watermarking and is recorded in
    docs/watermarking.md; production uses a controlled viewer instead of a
    re-rendered file.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix.lower() == ".pdf":
        with fitz.open(source) as doc:
            doc.save(destination, garbage=3, deflate=True)
            page_count = doc.page_count
    else:
        text = source.read_text(encoding="utf-8", errors="replace")
        document = fitz.open()
        for chunk in _paginate(text):
            page = document.new_page(width=TEXT_PAGE_WIDTH, height=TEXT_PAGE_HEIGHT)
            page.insert_textbox(fitz.Rect(56, 56, TEXT_PAGE_WIDTH - 56, TEXT_PAGE_HEIGHT - 56), chunk, fontsize=11)
        document.save(destination, garbage=3, deflate=True)
        page_count = document.page_count
        document.close()
    return {"path": str(destination), "page_count": page_count}


def _paginate(text: str, chars_per_page: int = 2600) -> list[str]:
    lines = text.splitlines()
    pages: list[str] = []
    buffer: list[str] = []
    size = 0
    for line in lines:
        buffer.append(line)
        size += len(line) + 1
        if size >= chars_per_page:
            pages.append("\n".join(buffer))
            buffer, size = [], 0
    if buffer:
        pages.append("\n".join(buffer))
    return pages or [""]


def render_gray(pdf_path: Path, dpi: int = SETTINGS.watermark_dpi) -> list[np.ndarray]:
    """Rasterises every page to 2-D grayscale float32 in [0, 1]. Using a single
    fixed geometry on both sides is what lets the extractor rebuild the same
    8x8 block grid the embedder used."""
    pages: list[np.ndarray] = []
    zoom = dpi / 72.0
    matrix = fitz.Matrix(zoom, zoom)
    with fitz.open(pdf_path) as document:
        for page in document:
            pixmap = page.get_pixmap(matrix=matrix, colorspace=fitz.csGRAY, alpha=False)
            buffer = np.frombuffer(pixmap.samples, dtype=np.uint8)
            side = pixmap.height - (pixmap.height % 8)
            width = pixmap.width - (pixmap.width % 8)
            grid = buffer[: side * pixmap.width].reshape(side, pixmap.width)[:, :width]
            pages.append(grid.astype(np.float32) / 255.0)
    return pages


def build_pdf(images: list[np.ndarray], destination: Path, *, dpi: int = SETTINGS.watermark_dpi) -> None:
    """Writes rasterised pages back into a PDF of the same physical size, so a
    recipient's copy looks like the document they were sent."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    points_per_pixel = 72.0 / dpi
    document = fitz.open()
    for grid in images:
        clipped = np.clip(grid * 255.0, 0, 255).astype(np.uint8)
        height, width = clipped.shape
        rect = fitz.Rect(0, 0, width * points_per_pixel, height * points_per_pixel)
        pixmap = fitz.Pixmap(fitz.csGRAY, width, height, clipped.tobytes(), False)
        page = document.new_page(width=rect.width, height=rect.height)
        page.insert_image(rect, pixmap=pixmap)
    document.save(destination, garbage=3, deflate=True)
    document.close()


def canonicalize(grid: np.ndarray, scale: float) -> np.ndarray:
    """Maps a captured raster back onto the geometry the embedder used.

    ``scale`` is the ratio between the captured image and the original render
    resolution, so a 1.5x capture is decimated and a half-size capture is
    resampled up. Without this the 8x8 block grid no longer lines up with the
    carriers and extraction silently fails, which is exactly the case a
    screenshot or a scanned page produces.
    """
    if abs(scale - 1.0) < 1e-9:
        return grid
    height, width = grid.shape
    target_h = max(8, int(height / scale) // 8 * 8)
    target_w = max(8, int(width / scale) // 8 * 8)
    rows = np.clip(np.round(np.arange(target_h) * scale).astype(int), 0, height - 1)
    cols = np.linspace(0, width - 1, target_w)
    horizontal = np.empty((height, target_w), dtype=np.float32)
    column_index = np.arange(width, dtype=np.float32)
    for row in range(height):
        horizontal[row] = np.interp(cols, column_index, grid[row])
    return horizontal[rows]


def page_count(pdf_path: Path) -> int:
    with fitz.open(pdf_path) as document:
        return document.page_count


def psnr(original: np.ndarray, watermarked: np.ndarray) -> float:
    mse = float(np.mean((original - watermarked) ** 2))
    if mse <= 1e-12:
        return 99.0
    return float(10.0 * np.log10(1.0 / mse))


def ssim(original: np.ndarray, watermarked: np.ndarray) -> float:
    """Global SSIM with the standard 8x8 sliding window. Reported next to every
    generated copy so 'visually identical' is a measured claim."""
    c1 = (0.01) ** 2
    c2 = (0.03) ** 2
    kernel = _ssim_kernel()
    channels = 1
    mu_x = _filter2(original, kernel)
    mu_y = _filter2(watermarked, kernel)
    mu_xx = mu_x * mu_x
    mu_yy = mu_y * mu_y
    mu_xy = mu_x * mu_y
    sigma_xx = _filter2(original * original, kernel) - mu_xx
    sigma_yy = _filter2(watermarked * watermarked, kernel) - mu_yy
    sigma_xy = _filter2(original * watermarked, kernel) - mu_xy
    numerator = (2 * mu_xy + c1) * (2 * sigma_xy + c2)
    denominator = (mu_xx + mu_yy + c1) * (sigma_xx + sigma_yy + c2)
    return float(np.mean(numerator / denominator) * channels)


def _ssim_kernel() -> np.ndarray:
    window = np.ones((8, 8), dtype=np.float32) / 64.0
    return window


def _filter2(image: np.ndarray, kernel: np.ndarray) -> np.ndarray:
    from numpy.lib.stride_tricks import sliding_window_view

    view = sliding_window_view(image, kernel.shape)
    return np.einsum("ijkl,kl->ij", view, kernel)
