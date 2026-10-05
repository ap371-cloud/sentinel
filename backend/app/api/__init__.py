from __future__ import annotations

import os

from fastapi import APIRouter, FastAPI

from ..database.session import ops_session
from . import auth, decryption, documents, forensics, ledger, security


def register_routes(app: FastAPI) -> None:
    app.include_router(auth.router)
    app.include_router(documents.router)
    app.include_router(decryption.router)
    app.include_router(ledger.router)
    app.include_router(forensics.router)
    app.include_router(security.router)

    @app.get("/api/health", tags=["system"])
    def health() -> dict[str, object]:
        from ..core.config import SETTINGS
        from ..crypto.pqc import PQC

        failure = getattr(app.state, "bootstrap_error", None)
        return {
            "status": "DEGRADED" if failure else "UP",
            "service": SETTINGS.short_name,
            "version": "1.0.0",
            "record_store": (
                "postgresql" if os.getenv("SENTINEL_DATABASE_URL") else "sqlite"
            ),
            "startup_error": failure,
            "post_quantum": {
                "signing": PQC.metadata.signing_algorithm,
                "kem": PQC.metadata.kem_algorithm,
                "backend": PQC.metadata.backend_library,
                "production_grade_backend": PQC.metadata.production_grade,
            },
            "disclaimer": (
                "Working local prototype with documented security and production limitations. Not "
                "certified for classified information."
            ),
        }

    @app.get("/api/status", tags=["system"])
    def status() -> dict[str, object]:
        from ..core.security import EGRESS
        from ..ledger.chain import NETWORK
        from ..security import lockdown

        with ops_session() as session:
            state = lockdown.describe(session)
        return {
            "system": state,
            "air_gap": EGRESS.status(),
            "ledger": NETWORK.status(),
            "ui_contract": {
                "statuses": [
                    "NORMAL", "VERIFIED", "WARNING", "HIGH RISK", "CRITICAL",
                    "REVOKED", "TAMPER DETECTED", "INVESTIGATION REQUIRED", "OFFLINE",
                ],
                "forensic_outcomes": [
                    "VERIFIED ASSOCIATION", "PARTIALLY VERIFIED", "DOCUMENT MODIFIED",
                    "WATERMARK NOT RECOVERED", "NO MATCH FOUND", "SIGNATURE INVALID",
                    "LEDGER PROOF INVALID", "INSUFFICIENT EVIDENCE",
                ],
            },
        }
