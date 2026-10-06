"""Cross-instance shared state for the serverless deployment.

Every warm Vercel instance owns a fresh /tmp, so SQLite, the key vault and the
generated artefacts are invisible to sibling instances. When
SENTINEL_DATABASE_URL is set, the parts that must agree across instances —
vault rows, artefact bytes and identifier counters — are mirrored into
PostgreSQL. With the variable absent every helper here is a no-op and the
prototype keeps its local SQLite/file behaviour unchanged.
"""

from __future__ import annotations

import fnmatch
import hashlib
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    text,
)
from sqlalchemy.exc import SQLAlchemyError

from .session import ops_engine, postgres_url

#: Serialises first-boot work (identity issuance, seeding, ledger genesis)
#: between instances that cold-start together on the same database.
BOOTSTRAP_LOCK_KEY = 77240913

shared_metadata = MetaData()

vault_keys = Table(
    "vault_keys",
    shared_metadata,
    Column("owner_id", String(120), primary_key=True),
    Column("payload", Text, nullable=False),
)

vault_meta = Table(
    "vault_meta",
    shared_metadata,
    Column("meta_key", String(60), primary_key=True),
    Column("payload", Text, nullable=False),
)

artefacts = Table(
    "artefacts",
    shared_metadata,
    Column("path", String(600), primary_key=True),
    Column("content", LargeBinary, nullable=False),
    Column("sha256", String(64)),
    Column("size_bytes", Integer),
    Column("updated_at", DateTime(timezone=True)),
)

id_counters = Table(
    "id_counters",
    shared_metadata,
    Column("prefix", String(20), primary_key=True),
    Column("value", BigInteger, nullable=False),
)


def shared_enabled() -> bool:
    url = postgres_url()
    return bool(url and url.startswith("postgres"))


_ensured = False


def ensure_shared_tables() -> None:
    global _ensured
    if _ensured:
        return
    # Two instances cold-starting together can both pass the checkfirst probe;
    # the loser retries once and then finds the tables already there.
    for attempt in (0, 1):
        try:
            shared_metadata.create_all(ops_engine, checkfirst=True)
            _ensured = True
            return
        except SQLAlchemyError:
            if attempt:
                raise
            time.sleep(0.4)


def _query(statement: str, params: dict | None = None):
    ensure_shared_tables()
    with ops_engine.begin() as connection:
        return list(connection.execute(text(statement), params or {}))


# ---- key vault -------------------------------------------------------------


def vault_read_owners() -> dict[str, str]:
    return {row[0]: row[1] for row in _query("SELECT owner_id, payload FROM vault_keys")}


def vault_write_owner(owner_id: str, payload: str) -> None:
    _query(
        "INSERT INTO vault_keys (owner_id, payload) VALUES (:owner_id, :payload) "
        "ON CONFLICT (owner_id) DO UPDATE SET payload = EXCLUDED.payload",
        {"owner_id": owner_id, "payload": payload},
    )


def vault_read_meta(meta_key: str) -> str | None:
    rows = _query("SELECT payload FROM vault_meta WHERE meta_key = :k", {"k": meta_key})
    return rows[0][0] if rows else None


def vault_write_meta(meta_key: str, payload: str, *, only_if_absent: bool = False) -> bool:
    """Returns False when the row already existed and only_if_absent was set."""
    if only_if_absent:
        rows = _query(
            "INSERT INTO vault_meta (meta_key, payload) VALUES (:k, :p) "
            "ON CONFLICT (meta_key) DO NOTHING RETURNING meta_key",
            {"k": meta_key, "p": payload},
        )
        return bool(rows)
    _query(
        "INSERT INTO vault_meta (meta_key, payload) VALUES (:k, :p) "
        "ON CONFLICT (meta_key) DO UPDATE SET payload = EXCLUDED.payload",
        {"k": meta_key, "p": payload},
    )
    return True


def vault_keys_exist() -> bool:
    return bool(_query("SELECT owner_id FROM vault_keys LIMIT 1"))


def master_secret_read() -> bytes | None:
    stored = vault_read_meta("master_secret")
    return bytes.fromhex(stored) if stored else None


def master_secret_write(secret: bytes) -> None:
    vault_write_meta("master_secret", secret.hex())


# ---- artefacts -------------------------------------------------------------


def artefact_put(path: Path | str, data: bytes) -> None:
    if not shared_enabled():
        return
    _query(
        "INSERT INTO artefacts (path, content, sha256, size_bytes, updated_at) "
        "VALUES (:p, :c, :s, :n, :t) ON CONFLICT (path) DO UPDATE SET "
        "content = EXCLUDED.content, sha256 = EXCLUDED.sha256, "
        "size_bytes = EXCLUDED.size_bytes, updated_at = EXCLUDED.updated_at",
        {
            "p": str(path),
            "c": data,
            "s": hashlib.sha256(data).hexdigest(),
            "n": len(data),
            "t": datetime.now(timezone.utc),
        },
    )


def artefact_put_file(path: Path) -> None:
    if not shared_enabled() or not path.exists():
        return
    artefact_put(path, path.read_bytes())


def artefact_get(path: Path | str) -> bytes | None:
    if not shared_enabled():
        return None
    rows = _query("SELECT content FROM artefacts WHERE path = :p", {"p": str(path)})
    return bytes(rows[0][0]) if rows else None


def artefact_delete(path: Path | str) -> bool:
    if not shared_enabled():
        return False
    rows = _query("DELETE FROM artefacts WHERE path = :p RETURNING path", {"p": str(path)})
    return bool(rows)


def artefact_glob(pattern: str) -> list[str]:
    if not shared_enabled():
        return []
    return sorted(
        row[0] for row in _query("SELECT path FROM artefacts") if fnmatch.fnmatch(row[0], pattern)
    )


def artefact_materialize(path: Path) -> Path:
    """Makes the file present on this instance by pulling the shared copy.

    Local reads stay untouched: if the file already exists here, no query runs
    and the behaviour is byte-for-byte the old one."""
    if not shared_enabled() or path.exists():
        return path
    data = artefact_get(path)
    if data is None:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.incoming")
    staging.write_bytes(data)
    staging.replace(path)
    return path


# ---- identifier counters ---------------------------------------------------


def counter_next(prefix: str) -> int:
    ensure_shared_tables()
    with ops_engine.begin() as connection:
        return int(
            connection.execute(
                text(
                    "INSERT INTO id_counters (prefix, value) VALUES (:p, 1) "
                    "ON CONFLICT (prefix) DO UPDATE SET value = id_counters.value + 1 "
                    "RETURNING value"
                ),
                {"p": prefix},
            ).scalar_one()
        )


def counter_sync(prefix: str, observed: int) -> None:
    _query(
        "INSERT INTO id_counters (prefix, value) VALUES (:p, :v) "
        "ON CONFLICT (prefix) DO UPDATE SET value = "
        "CASE WHEN id_counters.value < EXCLUDED.value THEN EXCLUDED.value "
        "ELSE id_counters.value END",
        {"p": prefix, "v": observed},
    )


# ---- bootstrap ------------------------------------------------------------


def hold_bootstrap_lock(session) -> None:
    """Keeps one instance from seeding while another is still mid-seed.

    Held until the caller's session commits, so the whole first-boot block —
    identity issuance, document creation and ledger genesis — runs once at a
    time against a shared database."""
    if shared_enabled():
        session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": BOOTSTRAP_LOCK_KEY}
        )
