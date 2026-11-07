"""SQLite connection and initialization helpers for a single-user local app."""
from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Iterator


DEFAULT_DB_PATH = Path.home() / ".vulnflow" / "vulnflow.sqlite3"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DEFAULT_DB_PATH).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def initialize(db_path: str | Path | None = None) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        _migrate_legacy_finding_states(conn)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA user_version = 2")
    finally:
        conn.close()


def _migrate_legacy_finding_states(conn: sqlite3.Connection) -> None:
    """Upgrade the earlier MVP state CHECK constraint while preserving all rows."""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'").fetchone()
    sql = (row[0] or "") if row else ""
    legacy_states = ("'open'", "'triaged'", "'accepted'", "'remediated'", "'false_positive'")
    # Key off the complete prior five-state CHECK set. Merely seeing `open`
    # must never cause a fresh or partially migrated schema to be rebuilt.
    if not all(state in sql for state in legacy_states):
        return
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("""CREATE TABLE findings_v2 (
            id TEXT PRIMARY KEY,
            dedup_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info','unknown')),
            state TEXT NOT NULL DEFAULT 'reported' CHECK (state IN ('reported','investigating','planned','patching','verifying','resolved','rejected')),
            target TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
            synthetic INTEGER NOT NULL DEFAULT 0 CHECK (synthetic IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("""INSERT INTO findings_v2(id,dedup_key,title,severity,state,target,rule_id,version,synthetic,created_at,updated_at)
            SELECT id,dedup_key,title,severity,
            CASE state WHEN 'open' THEN 'reported' WHEN 'triaged' THEN 'investigating'
                WHEN 'accepted' THEN 'planned' WHEN 'remediated' THEN 'resolved'
                WHEN 'false_positive' THEN 'rejected' ELSE 'reported' END,
            target,rule_id,version,synthetic,created_at,updated_at FROM findings""")
        conn.execute("DROP INDEX IF EXISTS idx_findings_state")
        conn.execute("DROP TABLE findings")
        conn.execute("ALTER TABLE findings_v2 RENAME TO findings")
        conn.execute("CREATE INDEX idx_findings_state ON findings(state)")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


def initialize_database(db_path: str | Path | None = None) -> None:
    """Stable service name used by API startup and callers with temporary DBs."""
    initialize(db_path)


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Use a savepoint if already in a caller transaction, else BEGIN IMMEDIATE."""
    nested = conn.in_transaction
    name = "vf_nested_tx"
    conn.execute(f"SAVEPOINT {name}" if nested else "BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute(f"ROLLBACK TO {name}" if nested else "ROLLBACK")
        if nested:
            conn.execute(f"RELEASE {name}")
        raise
    else:
        conn.execute(f"RELEASE {name}" if nested else "COMMIT")
