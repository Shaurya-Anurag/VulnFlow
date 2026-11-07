"""Finding lifecycle and workflow-only approvals; this module executes no actions."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .audit import append_event
from .db import connect, initialize_database, transaction
from .models import ApprovalError, ApprovalRequest, Finding, WorkflowConflict

TRANSITIONS = {
    # Retry/reopen paths are explicit: investigation may return to reported,
    # planning may return to investigation, patching may be retried, and a
    # resolved/rejected item can be reopened into investigation/reporting.
    "reported": {"investigating", "rejected"},
    "investigating": {"reported", "planned", "rejected"},
    "planned": {"investigating", "patching", "rejected"},
    "patching": {"investigating", "verifying", "rejected"},
    "verifying": {"patching", "resolved", "rejected"},
    "resolved": {"investigating"},
    "rejected": {"reported"},
}
APPROVABLE_ACTIONS = {"propose_remediation", "change_finding_state", "export_evidence"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding(row: sqlite3.Row) -> Finding:
    return Finding(row["id"], row["dedup_key"], row["title"], row["severity"], row["state"], row["target"],
                   row["rule_id"], row["version"], bool(row["synthetic"]), row["created_at"], row["updated_at"])


def transition_finding(conn: sqlite3.Connection, finding_id: str, new_state: str, actor: str,
                       reason: str, expected_version: int) -> Finding:
    if not isinstance(reason, str) or len(reason) > 4096:
        raise WorkflowConflict("reason must be text no longer than 4096 characters")
    with transaction(conn):
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row is None: raise WorkflowConflict("finding does not exist")
        if row["version"] != expected_version: raise WorkflowConflict("finding was changed; refresh and retry")
        if new_state not in TRANSITIONS.get(row["state"], set()):
            raise WorkflowConflict(f"transition from {row['state']} to {new_state} is not allowed")
        updated = _now()
        cur = conn.execute("UPDATE findings SET state=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                           (new_state, updated, finding_id, expected_version))
        if cur.rowcount != 1: raise WorkflowConflict("finding was changed; refresh and retry")
        append_event(conn, actor, "finding.transition", "finding", finding_id,
                     {"from": row["state"], "to": new_state, "reason": reason[:4096],
                      "previous_version": expected_version, "version": expected_version + 1})
        fresh = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    return _finding(fresh)


def _canonical_parameters(parameters: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(parameters, dict): raise ApprovalError("approval parameters must be an object")
    try:
        encoded = json.dumps(parameters, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ApprovalError("approval parameters must be JSON-compatible") from exc
    if len(encoded) > 65536: raise ApprovalError("approval parameters exceed limit")
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _approval(row: sqlite3.Row) -> ApprovalRequest:
    return ApprovalRequest(row["id"], row["finding_id"], row["action"], row["target"],
                           json.loads(row["parameters_json"]), row["parameter_sha256"], row["requester"],
                           row["approver"], row["state"], row["created_at"], row["expires_at"],
                           row["decided_at"], row["version"])


def create_approval(conn: sqlite3.Connection, finding_id: str, action: str, target: str,
                    parameters: dict[str, Any], requester: str, expires_at: str) -> ApprovalRequest:
    if action not in APPROVABLE_ACTIONS: raise ApprovalError("action is not in the approval allowlist")
    if len(target) > 2048 or not target: raise ApprovalError("target is required and must be bounded")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ApprovalError("expires_at must be an ISO-8601 timestamp") from exc
    now = datetime.now(timezone.utc)
    if expiry.tzinfo is None or expiry <= now or expiry > now.replace(year=min(now.year + 1, 9999)):
        raise ApprovalError("expiry must be future and within one year")
    params_json, digest = _canonical_parameters(parameters)
    approval_id = str(uuid.uuid4())
    with transaction(conn):
        if conn.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone() is None:
            raise ApprovalError("finding does not exist")
        # Idempotency: a finding can have only one live pending request for a
        # given action. BEGIN IMMEDIATE (via transaction()) serializes concurrent
        # writers so simultaneous retries cannot both create an approval.
        existing = conn.execute(
            """SELECT * FROM approvals
               WHERE finding_id=? AND action=? AND state='pending' AND expires_at>?
               ORDER BY created_at DESC,id LIMIT 1""",
            (finding_id, action, now.isoformat()),
        ).fetchone()
        if existing is not None:
            return _approval(existing)
        conn.execute("""INSERT INTO approvals(id,finding_id,action,target,parameters_json,parameter_sha256,
            requester,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,'pending',?,?)""",
            (approval_id, finding_id, action, target, params_json, digest, requester[:128], now.isoformat(), expiry.astimezone(timezone.utc).isoformat()))
        append_event(conn, requester, "approval.created", "approval", approval_id,
                     {"finding_id": finding_id, "action": action, "target": target, "parameter_sha256": digest,
                      "expires_at": expiry.astimezone(timezone.utc).isoformat()})
        row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    return _approval(row)


def decide_approval(conn: sqlite3.Connection, approval_id: str, decision: str, approver: str,
                    expected_parameter_hash: str, now: datetime | None = None,
                    reason: str = "") -> ApprovalRequest:
    if decision not in {"approved", "rejected"}: raise ApprovalError("decision must be approved or rejected")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None: raise ApprovalError("decision time must include a timezone")
    with transaction(conn):
        row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if row is None: raise ApprovalError("approval does not exist")
        if row["state"] != "pending": raise ApprovalError("approval is no longer pending")
        if row["requester"] == approver: raise ApprovalError("requester cannot approve their own request")
        if row["parameter_sha256"] != expected_parameter_hash: raise ApprovalError("approval parameters changed; create a new request")
        expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if now.astimezone(timezone.utc) >= expiry:
            conn.execute("UPDATE approvals SET state='expired',version=version+1 WHERE id=? AND state='pending'", (approval_id,))
            append_event(conn, approver, "approval.expired", "approval", approval_id,
                         {"parameter_sha256": row["parameter_sha256"], "reason": reason[:4096]})
        else:
            decided = now.astimezone(timezone.utc).isoformat()
            cur = conn.execute("UPDATE approvals SET state=?,approver=?,decided_at=?,version=version+1 WHERE id=? AND state='pending'",
                               (decision, approver[:128], decided, approval_id))
            if cur.rowcount != 1: raise ApprovalError("approval was already decided")
            append_event(conn, approver, "approval." + decision, "approval", approval_id,
                         {"parameter_sha256": row["parameter_sha256"], "requester": row["requester"],
                          "reason": reason[:4096]})
        result = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    return _approval(result)


def transition_finding_service(finding_id: str, new_status: str, actor: str, reason: str,
                               expected_version: int, db_path: str | Path | None = None) -> Finding:
    """Path-based service adapter for API callers; update and audit are atomic."""
    initialize_database(db_path); conn = connect(db_path)
    try:
        return transition_finding(conn, finding_id, new_status, actor, reason, expected_version)
    finally:
        conn.close()


def create_approval_service(action: str, target: str, parameters: dict[str, Any], requester: str,
                            db_path: str | Path | None = None) -> ApprovalRequest:
    """Create a workflow-only approval; parameters must bind a finding_id."""
    finding_id = parameters.get("finding_id") if isinstance(parameters, dict) else None
    expires_at = parameters.get("expires_at") if isinstance(parameters, dict) else None
    if not isinstance(finding_id, str) or not finding_id:
        raise ApprovalError("parameters must include finding_id")
    if not isinstance(expires_at, str):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    initialize_database(db_path); conn = connect(db_path)
    try:
        return create_approval(conn, finding_id, action, target, parameters, requester, expires_at)
    finally:
        conn.close()


def decide_approval_service(approval_id: str, decision: str, approver: str, reason: str,
                            db_path: str | Path | None = None) -> ApprovalRequest:
    """Resolve the stored parameter hash and atomically persist decision + audit."""
    initialize_database(db_path); conn = connect(db_path)
    try:
        row = conn.execute("SELECT parameter_sha256 FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if row is None: raise ApprovalError("approval does not exist")
        return decide_approval(conn, approval_id, decision, approver, row["parameter_sha256"], reason=reason)
    finally:
        conn.close()


def list_approvals(limit: int = 100, db_path: str | Path | None = None) -> list[ApprovalRequest]:
    initialize_database(db_path); conn = connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM approvals ORDER BY created_at DESC,id LIMIT ?",
                            (min(max(int(limit), 1), 500),))
        return [_approval(row) for row in rows]
    finally:
        conn.close()
