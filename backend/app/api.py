"""HTTP routes for the local VulnFlow workspace."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request

from .audit import list_events
from .db import connect, transaction
from .importers import parse_import, persist_import
from .models import ApprovalError, ImportValidationError, WorkflowConflict
from .workflow import create_approval, decide_approval, transition_finding

router = APIRouter(prefix="/api")
MAX_REQUEST_BYTES = 10 * 1024 * 1024


def _db_path(request: Request) -> str:
    return str(request.app.state.db_path)


@contextmanager
def _connection(request: Request) -> Iterator[sqlite3.Connection]:
    conn = connect(_db_path(request))
    try:
        yield conn
    finally:
        conn.close()


def _valid_id(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=404, detail="Record not found") from None


def _row_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return dict(row)


def _finding(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    result = _row_dict(row)
    finding_id = result["id"]
    observations = conn.execute(
        """SELECT o.id,o.import_id,o.tool_name,o.tool_version,o.run_id,o.rule_id,o.fingerprint,o.raw_json,
                  o.raw_location,o.normalized_location,o.observed_at,
                  i.source_name,i.source_sha256,i.imported_at,i.importer_version
           FROM observations o JOIN imports i ON i.id=o.import_id
           WHERE o.finding_id=? ORDER BY i.imported_at DESC,o.result_index""",
        (finding_id,),
    ).fetchall()
    observation_items = []
    evidence_items = []
    description = ""
    for observation in observations:
        item = _row_dict(observation)
        raw = json.loads(item.pop("raw_json") or "{}")
        if not description:
            message = raw.get("message")
            if isinstance(message, dict):
                description = str(message.get("text") or message.get("markdown") or "")[:16_384]
            elif isinstance(message, str):
                description = message[:16_384]
            description = description or str(raw.get("description") or "")[:16_384]
        item["raw_location"] = json.loads(item["raw_location"] or "{}")
        item["normalized_location"] = json.loads(item["normalized_location"] or "{}")
        item["source_hash"] = item["source_sha256"]
        observation_items.append(item)
        for evidence in conn.execute(
            "SELECT id,kind,locator,excerpt,content_sha256 FROM evidence WHERE observation_id=? ORDER BY id",
            (item["id"],),
        ):
            evidence_item = _row_dict(evidence)
            evidence_item["uri"] = evidence_item.pop("locator")
            evidence_item["source_hash"] = evidence_item.pop("content_sha256")
            evidence_items.append(evidence_item)
    result["status"] = result.pop("state", "reported")
    result["resource"] = result.get("target", "")
    result["fingerprint"] = result.get("dedup_key", "")
    result["description"] = description
    result["observations"] = observation_items
    result["evidence"] = evidence_items
    return result


async def _read_body(request: Request) -> bytes:
    raw_length = request.headers.get("content-length")
    if raw_length:
        try:
            if int(raw_length) > MAX_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="Request exceeds the 10 MiB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Request exceeds the 10 MiB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key[:80]}")
        result[key] = value
    return result


def _decode_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_json_pairs,
                          parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("Invalid JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise HTTPException(status_code=400, detail="Request must contain valid UTF-8 JSON without duplicate keys") from None


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-single-user"}


@router.get("/dashboard")
def dashboard(request: Request) -> dict[str, Any]:
    with _connection(request) as conn:
        total = conn.execute("SELECT COUNT(*) FROM findings WHERE synthetic=0").fetchone()[0]
        synthetic = conn.execute("SELECT COUNT(*) FROM findings WHERE synthetic=1").fetchone()[0]
        active_count = conn.execute("SELECT COUNT(*) FROM findings WHERE synthetic=0 AND state IN ('reported','investigating','planned','patching','verifying')").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM approvals WHERE state='pending'").fetchone()[0]
        by_severity = {row["severity"]: row["n"] for row in conn.execute(
            "SELECT severity,COUNT(*) AS n FROM findings WHERE synthetic=0 GROUP BY severity")}
        by_status = {row["state"]: row["n"] for row in conn.execute(
            "SELECT state,COUNT(*) AS n FROM findings WHERE synthetic=0 GROUP BY state")}
        event_count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    return {"total": total + synthetic, "real_total": total, "synthetic_total": synthetic,
            "active": active_count, "pending_approvals": pending, "activities": event_count,
            "by_severity": by_severity, "by_status": by_status}


@router.get("/findings")
def findings(request: Request, status: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    with _connection(request) as conn:
        if status:
            rows = conn.execute("SELECT * FROM findings WHERE state=? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                                (status, limit, offset)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM findings ORDER BY synthetic ASC,updated_at DESC LIMIT ? OFFSET ?",
                                (limit, offset)).fetchall()
        return [_finding(conn, row) for row in rows]


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: str, request: Request) -> dict[str, Any]:
    finding_id = _valid_id(finding_id)
    with _connection(request) as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return _finding(conn, row)


@router.post("/imports")
async def create_import(request: Request) -> dict[str, Any]:
    envelope = _decode_json(await _read_body(request))
    if not isinstance(envelope, dict) or set(envelope) != {"format", "source_name", "document"}:
        raise HTTPException(status_code=422, detail="Expected format, source_name, and document fields")
    format_name = envelope.get("format")
    source_name = envelope.get("source_name")
    document = envelope.get("document")
    if format_name not in {"sarif", "json"}:
        raise HTTPException(status_code=422, detail="format must be sarif or json")
    if not isinstance(source_name, str) or not source_name.strip() or len(source_name) > 256:
        raise HTTPException(status_code=422, detail="source_name must be 1 to 256 characters")
    if not isinstance(document, dict):
        raise HTTPException(status_code=422, detail="document must be a JSON object")
    encoded = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        parsed = parse_import(encoded, source_name)
        if format_name == "sarif" and parsed.format != "sarif-2.1.0":
            raise ImportValidationError("format does not match SARIF document")
        if format_name == "json" and parsed.format != "vulnflow-json-1":
            raise ImportValidationError("format does not match VulnFlow JSON v1 document")
        with _connection(request) as conn:
            result = persist_import(conn, parsed, actor="local-operator")
        return {"import_id": result.import_id, "imported": result.created_findings,
                "observations": result.observations, "deduplicated": max(result.observations - result.created_findings, 0),
                "duplicate_import": result.duplicate_import}
    except ImportValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except sqlite3.Error:
        raise HTTPException(status_code=409, detail="Import could not be committed; no partial data was retained") from None


@router.post("/findings/{finding_id}/transition")
def update_finding(finding_id: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    finding_id = _valid_id(finding_id)
    status = payload.get("status")
    reason = payload.get("reason", "")
    actor = payload.get("actor", "local-operator")
    version = payload.get("expected_version")
    if not isinstance(status, str) or not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
        raise HTTPException(status_code=422, detail="status and a reason of 1 to 1024 characters are required")
    if not isinstance(actor, str) or len(actor) > 128 or not isinstance(version, int):
        raise HTTPException(status_code=422, detail="actor or expected_version is invalid")
    try:
        with _connection(request) as conn:
            updated = transition_finding(conn, finding_id, status, actor, reason.strip(), version)
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            return _finding(conn, row)
    except WorkflowConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.get("/approvals")
def approvals(request: Request, limit: int = 50) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 200)
    with _connection(request) as conn:
        rows = conn.execute("SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        output = []
        for row in rows:
            item = _row_dict(row)
            item["parameters"] = json.loads(item.pop("parameters_json"))
            item["status"] = item.pop("state")
            item["parameter_hash"] = item.pop("parameter_sha256")
            output.append(item)
        return output


@router.post("/approvals")
def request_approval(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    finding_id = payload.get("target")
    action = payload.get("action")
    parameters = payload.get("parameters")
    requester = payload.get("requester", "vulnflow-remediation")
    if not isinstance(finding_id, str) or not isinstance(action, str) or not isinstance(parameters, dict):
        raise HTTPException(status_code=422, detail="target, action, and object parameters are required")
    if len(action) > 128 or not isinstance(requester, str) or len(requester) > 128:
        raise HTTPException(status_code=422, detail="action or requester exceeds the allowed length")
    finding_id = _valid_id(finding_id)
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    try:
        with _connection(request) as conn:
            approval = create_approval(conn, finding_id, action, finding_id, parameters, requester, expires)
            return _approval_dict(approval)
    except (ApprovalError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _approval_dict(value: Any) -> dict[str, Any]:
    result = dict(value) if isinstance(value, dict) else value.__dict__.copy()
    if "state" in result:
        result["status"] = result.pop("state")
    if "parameter_sha256" in result:
        result["parameter_hash"] = result.pop("parameter_sha256")
    return result


@router.post("/approvals/{approval_id}/decision")
def approval_decision(approval_id: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    approval_id = _valid_id(approval_id)
    decision = payload.get("decision")
    approver = payload.get("approver", "local-operator")
    reason = payload.get("reason", "")
    if decision not in {"approved", "rejected"} or not isinstance(approver, str) or not approver.strip():
        raise HTTPException(status_code=422, detail="decision and approver are required")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
        raise HTTPException(status_code=422, detail="a decision reason of 1 to 1024 characters is required")
    try:
        with _connection(request) as conn:
            row = conn.execute("SELECT parameter_sha256 FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Approval not found")
            approval = decide_approval(conn, approval_id, decision, approver.strip(),
                                       row["parameter_sha256"], reason=reason.strip())
            return _approval_dict(approval)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@router.get("/activity")
def activity(request: Request, limit: int = 50) -> list[dict[str, Any]]:
    with _connection(request) as conn:
        events = list_events(conn, limit=min(max(limit, 1), 200))
    return [{"id": str(event.id), "actor": event.actor, "action": event.event_type,
             "target": f"{event.entity_type}:{event.entity_id}", "outcome": "recorded",
             "details": event.payload, "created_at": event.occurred_at} for event in events]


@router.post("/activity")
def record_agent_activity(request: Request, payload: dict[str, Any]) -> dict[str, str]:
    actor, action, target = payload.get("actor"), payload.get("action"), payload.get("target")
    outcome, details = payload.get("outcome", "recorded"), payload.get("details", {})
    if not all(isinstance(value, str) and value.strip() for value in (actor, action, target, outcome)):
        raise HTTPException(status_code=422, detail="actor, action, target, and outcome are required")
    if len(actor) > 128 or len(action) > 128 or len(target) > 512 or not isinstance(details, dict):
        raise HTTPException(status_code=422, detail="activity fields are invalid or too long")
    from .audit import append_event
    with _connection(request) as conn:
        with transaction(conn):
            event = append_event(conn, actor, f"agent_activity:{action}", "activity", target,
                                 {"outcome": outcome[:128], "details": details})
    return {"id": str(event.id), "status": "recorded"}
