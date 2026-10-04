from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..core.config import PATHS, SETTINGS

OPS_DB = PATHS.data / "forge.db"


def _engine_for(path: Path) -> Engine:
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


ops_engine = _engine_for(OPS_DB)
OpsSession = sessionmaker(bind=ops_engine, expire_on_commit=False, future=True)

_node_engines: dict[str, Engine] = {}


def node_engine(node_id: str) -> Engine:
    """Every ledger node owns a physically separate database file. That
    separation is what lets the system detect a single-node tamper instead of
    trusting one shared store."""
    if node_id not in _node_engines:
        folder = PATHS.ledger / node_id.replace("-", "_").lower()
        folder.mkdir(parents=True, exist_ok=True)
        _node_engines[node_id] = _engine_for(folder / "ledger.db")
    return _node_engines[node_id]


def node_session(node_id: str) -> Session:
    return Session(node_engine(node_id), expire_on_commit=False, future=True)


def create_ops_schema() -> None:
    from ..models import Base  # noqa: F401  (registers every mapper)

    Base.metadata.create_all(ops_engine)
    _install_append_only_guards(ops_engine)


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
        statements = (
            f"CREATE TRIGGER IF NOT EXISTS immutable_update_{table} BEFORE UPDATE OF {column_list} ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{table}: these columns are immutable'); END",
            f"CREATE TRIGGER IF NOT EXISTS immutable_delete_{table} BEFORE DELETE ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{table} is append-only: DELETE denied'); END",
        )
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


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
