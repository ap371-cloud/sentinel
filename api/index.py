"""Vercel entry point: exposes the SENTINEL ASGI app from the backend package.

The serverless filesystem is read-only outside /tmp, so all mutable state
(SQLite, sealed documents, key vault, ledger journals) is redirected there and
re-created on each cold start. With SENTINEL_DATABASE_URL set, the parts that
must agree across instances — record store, key vault, artefacts and
identifier counters — live in PostgreSQL instead, which is what makes the
forensic chain survive request routing to a different warm instance. Without
the variable the local behaviour above still applies, for development.
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
