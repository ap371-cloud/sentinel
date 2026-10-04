"""Shared fixtures.

The whole suite runs against a real temporary deployment: real ML-DSA and
ML-KEM keys, a real SQLite ledger with three nodes, real PDF rendering and real
watermark embedding. Nothing is mocked, because the properties under test are
exactly the properties of those primitives.

Storage is redirected into a temporary directory per test session so a test run
never touches a developer's working data.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

#: Redirected before any application module is imported, because the key vault,
#: path registry and ledger all resolve their locations at import time.
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))
os.environ["SENTINEL_AIR_GAPPED"] = "1"

import app.core.config as config  # noqa: E402

_original_root = config.PROJECT_ROOT
config.PROJECT_ROOT = _TMP_ROOT
config.PATHS = config.Paths(root=_TMP_ROOT).ensure()

import app.database.session as database  # noqa: E402

database.OPS_DB = config.PATHS.data / "forge.db"
database.ops_engine = database._engine_for(database.OPS_DB)
database.OpsSession.configure(bind=database.ops_engine)
database._node_engines.clear()

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import DeviceTrust  # noqa: E402
from app.database.session import (  # noqa: E402
    create_node_schema,
    create_ops_schema,
    ops_session,
)
from app.ledger.chain import NETWORK  # noqa: E402
from app.models.identity import Device  # noqa: E402
from app.security import lockdown  # noqa: E402
from app.services import (  # noqa: E402
    approval_service,
    decryption_service,
    document_service,
    identity_service,
    seed_service,
)


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    # Teardown must never mask the real result. If the schema was never created
    # because collection failed, healing the network would raise here.
    try:
        NETWORK.heal()
    except Exception:
        pass
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def deployment() -> dict:
    """One seeded deployment for the whole session.

    Ledger nodes and identities are expensive to create, and every test needs
    the same synthetic environment.
    """
    config.PATHS.ensure()
    create_ops_schema()
    for node_id in NETWORK.node_ids:
        create_node_schema(node_id)
    NETWORK.ensure_ready()
    with ops_session() as session:
        approval_service.active_policy(session)
        seed_service.seed(session)
    return {"nodes": NETWORK.node_ids}


@pytest.fixture()
def db() -> Session:
    with ops_session() as session:
        yield session


@pytest.fixture(scope="session")
def client(deployment) -> TestClient:
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def brief_id() -> str:
    from app.models.documents import Document

    with ops_session() as session:
        return session.query(Document).filter_by(title="SYNTHETIC SECURE BRIEF 001").one().document_id


@pytest.fixture()
def clean_lockdown():
    yield
    with ops_session() as session:
        if lockdown.is_active(session):
            lockdown.release(session, actor_id="COMMANDER-001", reason="test teardown")


def token_for(client: TestClient, recipient_id: str, password: str, device_id: str | None = None) -> str:
    response = client.post(
        "/auth/login",
        json={"recipient_id": recipient_id, "password": password, "device_id": device_id},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def tokens(client: TestClient) -> dict[str, str]:
    return {
        "commander": token_for(client, "COMMANDER-001", "Commander!2026"),
        "officer": token_for(client, "SECURITY-001", "Security!2026"),
        "admin": token_for(client, "ADMIN-001", "Admin!2026"),
        "recipient_one": token_for(client, "RECIPIENT-001", "Recipient1!2026", "DEV-RECIPIENT-001-A"),
        "recipient_two": token_for(client, "RECIPIENT-002", "Recipient2!2026", "DEV-RECIPIENT-002-A"),
        "investigator": token_for(client, "INVESTIGATOR-001", "Investigator!2026"),
        "auditor": token_for(client, "AUDITOR-001", "Auditor!2026"),
        "ledger": token_for(client, "LEDGER-001", "Ledger!2026"),
    }


def decrypt_once(
    db: Session,
    *,
    recipient_id: str,
    document_id: str,
    device_id: str,
) -> dict:
    actor = identity_service.get(db, recipient_id)
    nonce = decryption_service.issue_nonce(db, recipient_id=recipient_id, document_id=document_id)
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=device_id, nonce=nonce["nonce"]
    )
