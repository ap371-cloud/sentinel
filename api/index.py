"""Vercel entry point: exposes the SENTINEL ASGI app from the backend package.

The serverless filesystem is read-only outside /tmp, so all mutable state
(SQLite, sealed documents, key vault, ledger journals) is redirected there and
re-created on each cold start. For a working model this is acceptable; real
persistence uses the same code against a normal server with
SENTINEL_DATA_ROOT pointed at a durable volume.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

os.environ.setdefault("SENTINEL_DATA_ROOT", "/tmp/sentinel-data")
os.environ.setdefault("SENTINEL_AIR_GAPPED", "0")

from app.main import app  # noqa: E402,F401  (Vercel imports `app`)
