from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..core.config import PATHS, SETTINGS

OPS_DB = PATHS.data / "forge.db"

#: Set this to a PostgreSQL URI to move the record store off the local disk.
#: Absent it, every path below keeps using SQLite exactly as before.
DATABASE_URL_ENV = "SENTINEL_DATABASE_URL"


def postgres_url() -> str | None:
    return os.getenv(DATABASE_URL_ENV) or None


def _engine_for(path: Path) -> Engine:
    url = postgres_url()
    if url:
        # Serverless instances come and go, and each one builds its own pool.
        # A wide per-process pool would burn Supabase's connection budget once
        # Vercel keeps more than one instance warm, so stay deliberately narrow.
        # The ceiling still has to cover a request holding its ORM session while
        # a keystore or artefact helper borrows a second connection.
        return create_engine(url, future=True, pool_pre_ping=True, pool_size=1, max_overflow=4)

    engine = create_engine(
        f"sqlite:///{path.as_posix()}",
        future=True,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _harden(connection, _record):  # pragma: no cover - driver level setup
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.close()

    return engine


def _schema_engine(schema: str) -> Engine:
    """Gives one ledger node its own PostgreSQL schema.

    A separate schema rather than a separate database: Supabase provisions a
    single database, and the node isolation this project relies on is about a
    store an attacker cannot reach through the others, not about the process.
    """
    engine = create_engine(
        postgres_url(),
        future=True,
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=2,
        connect_args={"options": f"-csearch_path={schema},public"},
    )
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    return engine


ops_engine = _engine_for(OPS_DB)
OpsSession = sessionmaker(bind=ops_engine, expire_on_commit=False, future=True)

_node_engines: dict[str, Engine] = {}


def node_engine(node_id: str) -> Engine:
    """Every ledger node owns a physically separate database file. That
    separation is what lets the system detect a single-node tamper instead of
    trusting one shared store."""
    if node_id not in _node_engines:
        if postgres_url():
            _node_engines[node_id] = _schema_engine(f"node_{node_id.replace('-', '_').lower()}")
            return _node_engines[node_id]

        folder = PATHS.ledger / node_id.replace("-", "_").lower()
        folder.mkdir(parents=True, exist_ok=True)
        _node_engines[node_id] = _engine_for(folder / "ledger.db")
    return _node_engines[node_id]


def node_session(node_id: str) -> Session:
    return Session(node_engine(node_id), expire_on_commit=False, future=True)


def create_ops_schema() -> None:
    from ..models import Base  # noqa: F401  (registers every mapper)

    Base.metadata.create_all(ops_engine)
    _ensure_added_columns(ops_engine)
    _install_append_only_guards(ops_engine)


#: create_all only creates missing tables; it never alters an existing one, so
#: a column added to a model has to be lifted onto old databases separately.
#: (sqlite: / postgres: ADD COLUMN both accept a constant default.)
ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("documents", "rights", "TEXT NOT NULL DEFAULT '{}'"),
    ("documents", "offline_max_hours", "INTEGER NOT NULL DEFAULT 0"),
    ("documents", "visible_watermark", "BOOLEAN NOT NULL DEFAULT TRUE"),
    ("documents", "allowed_locations", "TEXT NOT NULL DEFAULT '[]'"),
    ("policies", "policy_hash", "VARCHAR(64)"),
    ("approval_requests", "policy_version", "VARCHAR(24)"),
    ("revocations", "policy_version", "VARCHAR(24)"),
    ("audit_records", "device_id", "VARCHAR(64)"),
    ("audit_records", "document_id", "VARCHAR(64)"),
    ("audit_records", "document_hash", "VARCHAR(64)"),
    ("audit_records", "session_id", "VARCHAR(40)"),
    ("audit_records", "policy_version", "VARCHAR(24)"),
    ("audit_records", "reason", "TEXT"),
    ("audit_records", "severity", "VARCHAR(16)"),
)


def ensure_column(engine: Engine, table: str, column: str, ddl: str) -> None:
    with engine.connect() as connection:
        if engine.dialect.name == "postgresql":
            present = (
                connection.execute(
                    text(
                        "SELECT 1 FROM information_schema.columns "
                        "WHERE table_name = :table AND column_name = :column"
                    ),
                    {"table": table, "column": column},
                ).first()
                is not None
            )
        else:
            present = any(
                row[1] == column
                for row in connection.execute(text(f'PRAGMA table_info("{table}")')).fetchall()
            )
        if not present:
            connection.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}'))


def _ensure_added_columns(engine: Engine) -> None:
    for table, column, ddl in ADDED_COLUMNS:
        ensure_column(engine, table, column, ddl)


def create_node_schema(node_id: str) -> None:
    from ..models.ledger import LedgerBase

    LedgerBase.metadata.create_all(node_engine(node_id))
    _install_append_only_guards(node_engine(node_id))


#: Append-only tables, and for each one the columns that must never change.
#:
#: Scoping matters: an evidence row legitimately gains analysis columns once,
#: and a signed event legitimately gains its ledger link. What must never change
#: is the signed or custody-bearing content, so the guards target those columns
#: specifically rather than the whole row.
APPEND_ONLY_GUARDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ledger_blocks", ("block_id", "height", "previous_block_hash", "merkle_root", "block_hash",
                      "timestamp", "proposer_id", "state_root")),
    ("ledger_transactions", ("tx_id", "event_id", "event_hash", "payload", "recipient_signature",
                             "tx_hash", "merkle_index")),
    ("audit_records", ("audit_id", "actor_id", "action", "record_hash", "prev_record_hash", "occurred_at")),
    ("decryption_events", ("event_id", "event_hash", "prev_event_hash", "payload", "signature",
                           "watermark_tag", "document_hash", "recipient_id", "occurred_at")),
    ("evidence_items", ("evidence_id", "case_id", "stored_path", "content_sha256", "collected_by",
                        "collected_at", "analysis_tool")),
    ("watermarks", ("watermark_id", "tag", "derivation_inputs_hash", "document_hash", "session_id")),
    ("security_events", ("security_event_id", "detected_at", "category", "severity", "what_happened")),
    ("revocations", ("revocation_id", "subject_type", "subject_id", "scope", "reason",
                     "revoked_by", "revoked_at")),
    ("offline_grants", ("offline_grant_id", "document_id", "recipient_id", "device_id",
                        "granted_at", "policy_version")),
)


def _install_append_only_guards(engine: Engine) -> None:
    """Turns changes to security-bearing columns into hard storage failures.

    Application code already refuses those operations; these guards exist so a
    process using the same database file directly still cannot quietly rewrite
    signed history.
    """
    with engine.connect() as connection:
        present = set(engine.dialect.get_table_names(connection))
    for table, columns in APPEND_ONLY_GUARDS:
        if table not in present:
            continue
        column_list = ", ".join(columns)
        if engine.dialect.name == "postgresql":
            statements = _postgres_guard_statements(table, column_list)
        else:
            statements = (
                f"CREATE TRIGGER IF NOT EXISTS immutable_update_{table} BEFORE UPDATE OF {column_list} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table}: these columns are immutable'); END",
                f"CREATE TRIGGER IF NOT EXISTS immutable_delete_{table} BEFORE DELETE ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only: DELETE denied'); END",
            )
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


#: PostgreSQL has no RAISE(ABORT); an exception with a restrict violation code is
#: the equivalent, and the per-table triggers are dropped and recreated by the
#: attack lab, which is why the function is CREATE OR REPLACE.
_POSTGRES_GUARD_FN = """
CREATE OR REPLACE FUNCTION sentinel_append_only_guard() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % denied', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
"""


def _postgres_guard_statements(table: str, column_list: str) -> tuple[str, ...]:
    # PostgreSQL has no CREATE TRIGGER IF NOT EXISTS, and bootstrap runs on every
    # cold start, so the triggers are dropped before they are recreated.
    return (
        _POSTGRES_GUARD_FN,
        f"DROP TRIGGER IF EXISTS immutable_update_{table} ON {table}",
        f"DROP TRIGGER IF EXISTS immutable_delete_{table} ON {table}",
        f"CREATE TRIGGER immutable_update_{table} BEFORE UPDATE OF {column_list} ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION sentinel_append_only_guard()",
        f"CREATE TRIGGER immutable_delete_{table} BEFORE DELETE ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION sentinel_append_only_guard()",
    )


@contextmanager
def node_transaction(node_id: str) -> Iterator[Session]:
    """SQLAlchemy's ``with Session()`` only closes on exit; it does not commit.
    Every writer in this project goes through one of the two context managers
    below so a successful return always means the change is durable."""
    session = node_session(node_id)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def ops_session() -> Iterator[Session]:
    session = OpsSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def quorum() -> int:
    return SETTINGS.quorum_size
