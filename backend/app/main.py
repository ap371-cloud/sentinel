"""Application entry point.

Start with:

    python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000

The egress guard blocks every non-loopback socket while air-gapped mode is
active, so the API is reachable only from the local command terminal.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import register_routes
from .core.config import PATHS, SETTINGS
from .core.exceptions import ForgeError
from .core.identifiers import sync_counter
from .core.security import EGRESS
from .crypto.signatures import ensure_server_identity
from .database.session import create_node_schema, create_ops_schema, ops_session
from .ledger.chain import NETWORK
from .models.documents import Document, RecipientGrant
from .models.security import AnomalyObservation, ApprovalRequest, AuditRecord
from .models.sessions import DecryptionEvent, DecryptionSession

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
)
logger = logging.getLogger("sentinel")


def bootstrap() -> dict[str, object]:
    """Creates schemas, brings the ledger online and seeds a usable identity.

    Called on start-up rather than at import time so ordering problems surface
    as a clear start-up error instead of an import crash.
    """
    PATHS.ensure()
    EGRESS.install()
    create_ops_schema()
    for node_id in NETWORK.node_ids:
        create_node_schema(node_id)
    NETWORK.ensure_ready()

    from .services import approval_service, seed_service

    with ops_session() as session:
        ensure_server_identity()
        approval_service.active_policy(session)
        _reseed_identifiers(session)
        seeded = seed_service.seed(session)
    logger.info(
        "bootstrap complete — ledger nodes %s online, %d identities, %d documents",
        ",".join(NETWORK.node_ids),
        len(seeded["users_created"]),
        len(seeded["documents_created"]),
    )
    return seeded


def _reseed_identifiers(session: Session) -> None:
    """Advances every in-memory identifier counter past the highest value already in
    the database. Without this a restart reissues DOC-001 / EVT-...0001 and the insert
    fails on the primary key, taking down whichever request happened to arrive first."""
    for prefix, table, column in (
        ("AUD", AuditRecord, "audit_id"),
        ("DOC", Document, "document_id"),
        ("APR", ApprovalRequest, "approval_id"),
        ("ANO", AnomalyObservation, "observation_id"),
        ("SES", DecryptionSession, "session_id"),
        ("EVT", DecryptionEvent, "event_id"),
        ("REQ", DecryptionSession, "request_id"),
        ("GRT", RecipientGrant, "grant_id"),
    ):
        issued = [value for (value,) in session.execute(select(getattr(table, column))) if value]
        if not issued:
            continue
        highest = max(int(value.rsplit("-", 1)[1]) for value in issued if value.rsplit("-", 1)[-1].isdigit())
        sync_counter(prefix, highest)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # A misconfigured record store must not take the whole surface down. When
    # bootstrap raises, the process used to exit and every route answered an
    # opaque 500, which is indistinguishable from a code fault. Keeping the app
    # up lets /api/health name the actual cause.
    app.state.bootstrap_error = None
    try:
        app.state.bootstrap = bootstrap()
    except Exception as exc:
        app.state.bootstrap_error = f"{type(exc).__name__}: {exc}"
        logger.error("bootstrap failed, serving in a degraded state — %s", app.state.bootstrap_error)
    app.state.egress = EGRESS.status()
    yield
    logger.info("sentinel shutting down")


app = FastAPI(
    title=SETTINGS.app_name,
    version="1.0.0",
    description=(
        "Offline secure document distribution with session-specific forensic watermarking, "
        "post-quantum signed events and a tamper-evident permissioned ledger.\n\n"
        "This is a working local prototype with documented security and production limitations. "
        "A verified association links a copy to an authorised decryption session; it does not "
        "establish which individual physically released the material."
    ),
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# The browser talks to this backend across origins when the console is hosted
# separately (e.g. Vercel frontend -> Railway backend). Local dev keeps the
# default loopback origins; set SENTINEL_CORS_ORIGINS to allow your frontend.
_origins = [
    origin.strip()
    for origin in os.getenv(
        "SENTINEL_CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _error(status: int, code: str, message: str, detail: str | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "detail": detail or ""}},
    )


@app.exception_handler(ForgeError)
async def forge_error_handler(request: Request, exc: ForgeError) -> JSONResponse:
    """Security outcomes are reported as structured refusals, never as crashes.

    The plain explanation is written for a commander who does not read
    cryptography; the reason code is there for an investigator or a test.
    """
    return _error(exc.status, exc.code, exc.plain_explanation if exc.status >= 400 else str(exc),
                   exc.detail or str(exc))


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return _error(422, "INVALID_REQUEST", "The request was malformed.", str(exc.errors()[:5]))


@app.exception_handler(StarletteHTTPException)
async def http_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return _error(exc.status_code, f"HTTP_{exc.status_code}", str(exc.detail))


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    # Logged with a category rather than a traceback containing request data, so
    # no secret can reach the log through an unexpected failure.
    logger.error("unhandled failure category=%s path=%s", type(exc).__name__, request.url.path)
    return _error(
        500,
        "INTERNAL_ERROR",
        "The request could not be completed.",
        f"{type(exc).__name__} — see server log for the failure category.",
    )


register_routes(app)
