from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pymupdf as fitz

from ..core.config import SETTINGS

DIAGONAL_DEGREES = -45.0
LINE_STEP_PX = 150
FONT_SIZE = 10


def render_line(
    *, classification: str, recipient_id: str, session_id: str, timestamp: str | None = None
) -> str:
    return SETTINGS.visible_watermark_template.format(
        classification=classification,
        recipient_id=recipient_id,
        username=recipient_id,
        session_id=session_id,
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        org=SETTINGS.short_name,
        secret=classification,
    )


def stamp(
    pdf_path: Path, *, document: Any, recipient_id: str, session_id: str
) -> dict[str, Any]:
    """Overlays the deterrent text on every page of an already-watermarked
    copy. Vector text, low opacity — readable to a person inspecting the file,
    deliberately not a security claim of its own."""
    if not document.visible_watermark:
        return {
            "stamped": False,
            "reason": "Document policy has the visible layer disabled.",
        }
    line = render_line(
        classification=document.classification,
        recipient_id=recipient_id,
        session_id=session_id,
    )
    rotation = fitz.Matrix(DIAGONAL_DEGREES)
    with fitz.open(pdf_path) as copy:
        for page in copy:
            width, height = page.rect.width, page.rect.height
            for y in range(int(height) // LINE_STEP_PX + 1):
                origin = fitz.Point(40.0, float(y * LINE_STEP_PX + 80))
                page.insert_text(
                    origin,
                    line,
                    fontsize=FONT_SIZE,
                    color=(0.25, 0.25, 0.3),
                    fill_opacity=SETTINGS.visible_watermark_opacity,
                    morph=(origin, rotation),
                )
        staging = pdf_path.with_name(f".{pdf_path.name}.visible-tmp")
        copy.save(staging, garbage=3, deflate=True)
    staging.replace(pdf_path)
    return {
        "stamped": True,
        "template": SETTINGS.visible_watermark_template,
        "opacity": SETTINGS.visible_watermark_opacity,
        "angle_degrees": DIAGONAL_DEGREES,
        "plain_explanation": (
            "A faint diagonal marking names the recipient and session on every page. "
            "It deters casual sharing; the invisible watermark is what proves attribution."
        ),
    }
