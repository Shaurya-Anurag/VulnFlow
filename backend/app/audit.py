"""Append-only audit helpers. SQLite file owners remain able to rewrite history."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from .models import AuditEvent
from .db import connect, initialize_database

_SENSITIVE = {"password", "token", "secret", "authorization", "cookie"}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower() in _SENSITIVE else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return value[:4096]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def append_event(conn: sqlite3.Connection, actor: str, event_type: str, entity_type: str,
                 entity_id: str, payload: dict[str, Any], correlation_id: str | None = None) -> AuditEvent:
    previous = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous[0] if previous else ""
    occurred = datetime.now(timezone.utc).isoformat()
    safe_payload = _redact(payload)
    payload_json = _canonical(safe_payload)
    correlation = (correlation_id or "")[:128]
    material = _canonical([actor[:128], event_type[:128], entity_type[:128], entity_id[:128], occurred,
                           correlation, payload_json, previous_hash])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    cur = conn.execute("""INSERT INTO audit_events(actor,event_type,entity_type,entity_id,occurred_at,
        correlation_id,payload_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?)""",
        (actor[:128], event_type[:128], entity_type[:128], entity_id[:128], occurred, correlation,
         payload_json, previous_hash, digest))
    return AuditEvent(cur.lastrowid, actor[:128], event_type[:128], entity_type[:128], entity_id[:128],
                      occurred, correlation, safe_payload, previous_hash, digest)


def list_events(conn: sqlite3.Connection, entity_type: str | None = None,
                entity_id: str | None = None, limit: int = 100) -> list[AuditEvent]:
    limit = min(max(int(limit), 1), 1000)
    clauses, args = [], []
    if entity_type is not None:
        clauses.append("entity_type=?"); args.append(entity_type)
    if entity_id is not None:
        clauses.append("entity_id=?"); args.append(entity_id)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(f"SELECT * FROM audit_events{where} ORDER BY id DESC LIMIT ?", (*args, limit))
    return [AuditEvent(r["id"], r["actor"], r["event_type"], r["entity_type"], r["entity_id"],
                       r["occurred_at"], r["correlation_id"], json.loads(r["payload_json"]),
                       r["previous_hash"], r["event_hash"]) for r in rows]


def record_activity(actor: str, action: str, target: str, outcome: str, details: dict[str, Any],
                    db_path: str | Path | None = None) -> AuditEvent:
    initialize_database(db_path); conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        event = append_event(conn, actor, action, "activity", target,
                             {"outcome": outcome, "details": details})
        conn.execute("COMMIT")
        return event
    except Exception:
        if conn.in_transaction: conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def list_activity(limit: int = 100, db_path: str | Path | None = None) -> list[AuditEvent]:
    initialize_database(db_path); conn = connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM audit_events WHERE entity_type='activity' ORDER BY id DESC LIMIT ?",
                            (min(max(int(limit), 1), 1000),))
        return [AuditEvent(r["id"], r["actor"], r["event_type"], r["entity_type"], r["entity_id"],
                           r["occurred_at"], r["correlation_id"], json.loads(r["payload_json"]),
                           r["previous_hash"], r["event_hash"]) for r in rows]
    finally:
        conn.close()
