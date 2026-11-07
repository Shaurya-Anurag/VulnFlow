"""Bounded, inert import of SARIF 2.1.0 and VulnFlow JSON v1."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import append_event
from .db import connect, initialize_database, transaction
from .models import DEFAULT_LIMITS, ImportLimits, ImportRequest, ImportResult, ImportValidationError, NormalizedObservation

IMPORTER_VERSION = "1"
_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ImportValidationError(f"duplicate JSON key: {key[:80]}")
        out[key] = value
    return out


def _depth(value: Any, max_depth: int, max_string: int, depth: int = 0) -> None:
    if depth > max_depth:
        raise ImportValidationError("document nesting exceeds configured limit")
    if isinstance(value, dict):
        for k, v in value.items():
            if len(k) > 256:
                raise ImportValidationError("object key exceeds configured limit")
            _depth(v, max_depth, max_string, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _depth(v, max_depth, max_string, depth + 1)
    elif isinstance(value, str):
        if len(value) > max_string:
            raise ImportValidationError("string exceeds parser safety limit")


def _string(value: Any, name: str, limits: ImportLimits, default: str = "") -> str:
    if value is None:
        value = default
    if not isinstance(value, str):
        raise ImportValidationError(f"{name} must be a string")
    if len(value) > limits.max_string:
        raise ImportValidationError(f"{name} exceeds configured limit")
    return value


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    raw = str(result.get("level", "warning")).lower()
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    raw = str(props.get("severity", raw)).lower()
    if raw in {"error", "critical"}: return "critical" if raw == "critical" else "high"
    if raw in {"warning", "medium", "moderate"}: return "medium"
    if raw in {"note", "low"}: return "low"
    if raw in {"none", "info", "informational"}: return "info"
    return "unknown"


def _make_observation(index: int, result: dict[str, Any], tool_name: str, tool_version: str,
                      run_id: str, limits: ImportLimits, format_name: str) -> NormalizedObservation:
    rule_id = _string(result.get("ruleId", result.get("rule_id")), "rule id", limits, "unknown") or "unknown"
    if format_name == "sarif-2.1.0":
        message_obj = result.get("message") if isinstance(result.get("message"), dict) else {}
        title = _string(message_obj.get("text", message_obj.get("markdown")), "message", limits, rule_id) or rule_id
        locations = result.get("locations", [])
        if not isinstance(locations, list):
            raise ImportValidationError("locations must be an array", index)
        rawloc: dict[str, Any] = locations[0] if locations and isinstance(locations[0], dict) else {}
        physical = rawloc.get("physicalLocation", {}) if isinstance(rawloc, dict) else {}
        artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
        region = physical.get("region", {}) if isinstance(physical, dict) else {}
        uri = _string(artifact.get("uri", "") if isinstance(artifact, dict) else "", "artifact URI", limits)
        line = region.get("startLine") if isinstance(region, dict) else None
        target = uri or "unknown"
        normloc = {"uri": uri.replace("\\", "/"), "line": line if isinstance(line, int) and line > 0 else None}
        fingerprints = result.get("partialFingerprints", {})
        fingerprint = ""
        if isinstance(fingerprints, dict) and fingerprints:
            fingerprint = _string(next(iter(fingerprints.values())), "fingerprint", limits)
        props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
        evidence: list[dict[str, str]] = []
        for loc in locations:
            if not isinstance(loc, dict): continue
            pl = loc.get("physicalLocation", {})
            region_obj = pl.get("region", {}) if isinstance(pl, dict) else {}
            snippet = region_obj.get("snippet", {}) if isinstance(region_obj, dict) else {}
            text = snippet.get("text", "") if isinstance(snippet, dict) else ""
            if text:
                text = _string(text, "evidence", limits)
                if len(text) > limits.max_evidence: raise ImportValidationError("evidence exceeds configured limit", index)
                evidence.append({"kind": "snippet", "locator": uri, "excerpt": text})
        severity = _severity(result, {})
    else:
        title = _string(result.get("title", result.get("message", rule_id)), "title", limits) or rule_id
        target = _string(result.get("target", result.get("path", "unknown")), "target", limits) or "unknown"
        rawloc = result.get("location", {})
        if not isinstance(rawloc, dict): raise ImportValidationError("location must be an object", index)
        normloc = {"uri": _string(rawloc.get("uri", target), "location URI", limits).replace("\\", "/"),
                   "line": rawloc.get("line") if isinstance(rawloc.get("line"), int) and rawloc.get("line") > 0 else None}
        fingerprint = _string(result.get("fingerprint", ""), "fingerprint", limits)
        raw_sev = _string(result.get("severity", "unknown"), "severity", limits).lower()
        severity = raw_sev if raw_sev in _SEVERITIES else "unknown"
        evidence = []
        ev = result.get("evidence", [])
        if not isinstance(ev, list): raise ImportValidationError("evidence must be an array", index)
        for item in ev:
            if isinstance(item, str): item = {"excerpt": item}
            if not isinstance(item, dict): raise ImportValidationError("evidence entry must be an object", index)
            excerpt = _string(item.get("excerpt", ""), "evidence", limits)
            if len(excerpt) > limits.max_evidence: raise ImportValidationError("evidence exceeds configured limit", index)
            evidence.append({"kind": _string(item.get("kind", "text"), "evidence kind", limits),
                             "locator": _string(item.get("locator", ""), "evidence locator", limits), "excerpt": excerpt})
    return NormalizedObservation(index, title, severity, target, rule_id, tool_name, tool_version, run_id,
                                 fingerprint, result, rawloc, normloc, evidence,
                                 datetime.now(timezone.utc).isoformat())


def parse_import(data: bytes, filename: str, limits: ImportLimits = DEFAULT_LIMITS) -> ImportRequest:
    if not isinstance(data, bytes): raise ImportValidationError("import body must be bytes")
    if len(data) > limits.max_bytes: raise ImportValidationError("import exceeds byte limit")
    try:
        raw = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_pairs,
                         parse_constant=lambda _v: (_ for _ in ()).throw(ImportValidationError("non-finite number is not allowed")))
    except ImportValidationError: raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ImportValidationError("invalid UTF-8 JSON document") from exc
    if not isinstance(raw, dict): raise ImportValidationError("top-level JSON value must be an object")
    _depth(raw, limits.max_depth, limits.max_string)
    if "runs" in raw and "version" in raw:
        if raw.get("version") != "2.1.0": raise ImportValidationError("only SARIF 2.1.0 is supported")
        runs = raw.get("runs")
        if not isinstance(runs, list) or not runs: raise ImportValidationError("SARIF runs must be a non-empty array")
        out: list[NormalizedObservation] = []
        tool_name = "unknown"; tool_version = ""; index = 0
        for run_index, run in enumerate(runs):
            if not isinstance(run, dict): raise ImportValidationError("SARIF run must be an object")
            tool = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
            if not isinstance(tool, dict): raise ImportValidationError("SARIF tool.driver must be an object")
            tool_name = _string(tool.get("name"), "tool name", limits, "unknown")
            tool_version = _string(tool.get("version"), "tool version", limits)
            results = run.get("results", [])
            if not isinstance(results, list): raise ImportValidationError("SARIF results must be an array")
            if len(out) + len(results) > limits.max_results: raise ImportValidationError("result count exceeds configured limit")
            for result in results:
                if not isinstance(result, dict): raise ImportValidationError("SARIF result must be an object", index)
                out.append(_make_observation(index, result, tool_name, tool_version, str(run_index), limits, "sarif-2.1.0")); index += 1
        fmt = "sarif-2.1.0"
    elif raw.get("schema_version") == "1":
        if set(raw) - {"schema_version", "tool", "results", "run_id"}:
            raise ImportValidationError("unsupported VulnFlow JSON v1 top-level fields")
        tool = raw.get("tool", {})
        if not isinstance(tool, dict): raise ImportValidationError("tool must be an object")
        if set(tool) - {"name", "version"}: raise ImportValidationError("unsupported tool fields")
        tool_name = _string(tool.get("name"), "tool name", limits, "unknown")
        tool_version = _string(tool.get("version"), "tool version", limits)
        run_id = _string(raw.get("run_id", ""), "run id", limits)
        results = raw.get("results")
        if not isinstance(results, list): raise ImportValidationError("results must be an array")
        if len(results) > limits.max_results: raise ImportValidationError("result count exceeds configured limit")
        out = []
        for index, result in enumerate(results):
            if not isinstance(result, dict): raise ImportValidationError("result must be an object", index)
            if set(result) - {"rule_id", "ruleId", "title", "message", "severity", "target", "path", "location", "fingerprint", "evidence"}:
                raise ImportValidationError("unsupported VulnFlow result fields", index)
            out.append(_make_observation(index, result, tool_name, tool_version, run_id, limits, "vulnflow-json-1"))
        fmt = "vulnflow-json-1"
    else:
        raise ImportValidationError("expected SARIF 2.1.0 or VulnFlow JSON schema_version 1")
    return ImportRequest(fmt, filename[:256] or "import.json", hashlib.sha256(data).hexdigest(), IMPORTER_VERSION,
                        tool_name, tool_version, str(out[0].run_id if out else ""), out, raw)


def normalize_import(request: ImportRequest) -> list[NormalizedObservation]:
    return request.observations


def _target_key(value: str) -> str:
    # Paths remain opaque metadata; this does not access the filesystem or resolve URIs.
    return value.strip().replace("\\", "/") or "unknown"


def persist_import(conn: sqlite3.Connection, request: ImportRequest,
                   observations: list[NormalizedObservation] | None = None, actor: str = "user") -> ImportResult:
    observations = observations if observations is not None else request.observations
    import_id = str(uuid.uuid4()); created = 0
    with transaction(conn):
        existing = conn.execute("SELECT id,result_count FROM imports WHERE format=? AND source_sha256=?",
                                (request.format, request.source_sha256)).fetchone()
        if existing:
            return ImportResult(existing["id"], 0, existing["result_count"], True)
        conn.execute("INSERT INTO imports(id,format,source_name,source_sha256,importer_version,imported_at,actor,result_count) VALUES(?,?,?,?,?,?,?,?)",
                     (import_id, request.format, request.source_name, request.source_sha256, request.importer_version,
                      datetime.now(timezone.utc).isoformat(), actor[:128], len(observations)))
        for obs in observations:
            target = _target_key(obs.target)
            location = json.dumps(obs.normalized_location, sort_keys=True, separators=(",", ":"))
            identity = obs.fingerprint or location
            dedup = hashlib.sha256("\0".join((target, obs.rule_id, identity)).encode("utf-8")).hexdigest()
            row = conn.execute("SELECT id FROM findings WHERE dedup_key=?", (dedup,)).fetchone()
            if row:
                finding_id = row["id"]
            else:
                finding_id = str(uuid.uuid4()); created += 1
                now = datetime.now(timezone.utc).isoformat()
                conn.execute("INSERT INTO findings(id,dedup_key,title,severity,target,rule_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                             (finding_id, dedup, obs.title, obs.severity, target, obs.rule_id, now, now))
            observation_id = str(uuid.uuid4())
            conn.execute("""INSERT INTO observations(id,import_id,finding_id,result_index,tool_name,tool_version,run_id,
                rule_id,fingerprint,raw_json,raw_location,normalized_location,observed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (observation_id, import_id, finding_id, obs.result_index, obs.tool_name, obs.tool_version, obs.run_id,
                 obs.rule_id, obs.fingerprint, json.dumps(obs.raw, ensure_ascii=False, sort_keys=True),
                 json.dumps(obs.raw_location, ensure_ascii=False, sort_keys=True), location, obs.observed_at))
            for evidence in obs.evidence:
                excerpt = evidence.get("excerpt", "")[:32768]
                conn.execute("INSERT INTO evidence(id,observation_id,kind,locator,excerpt,content_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                             (str(uuid.uuid4()), observation_id, evidence.get("kind", "text")[:128],
                              evidence.get("locator", "")[:4096], excerpt,
                              hashlib.sha256(excerpt.encode("utf-8")).hexdigest(), obs.observed_at))
        append_event(conn, actor, "import.created", "import", import_id,
                     {"format": request.format, "sha256": request.source_sha256,
                      "observation_count": len(observations), "created_findings": created})
    return ImportResult(import_id, created, len(observations), False)


def import_report(document: bytes | str | dict[str, Any], format: str, source_name: str,
                  db_path: str | Path | None = None) -> ImportResult:
    """Parse and persist one report. `format` is `sarif` or VulnFlow `json`."""
    if isinstance(document, dict):
        data = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    elif isinstance(document, str):
        data = document.encode("utf-8")
    elif isinstance(document, bytes):
        data = document
    else:
        raise ImportValidationError("document must be UTF-8 JSON text, bytes, or an object")
    normalized_format = format.lower().strip()
    request = parse_import(data, source_name)
    if normalized_format not in {"sarif", "sarif-2.1.0", "json", "vulnflow-json-1"}:
        raise ImportValidationError("format must be sarif or json")
    if normalized_format.startswith("sarif") and request.format != "sarif-2.1.0":
        raise ImportValidationError("document is not SARIF 2.1.0")
    if normalized_format in {"json", "vulnflow-json-1"} and request.format != "vulnflow-json-1":
        raise ImportValidationError("document is not VulnFlow JSON v1")
    initialize_database(db_path)
    conn = connect(db_path)
    try:
        return persist_import(conn, request, normalize_import(request))
    finally:
        conn.close()


def dashboard_summary(db_path: str | Path | None = None) -> dict[str, Any]:
    initialize_database(db_path)
    conn = connect(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) FROM findings WHERE synthetic=0").fetchone()[0]
        by_state = {row[0]: row[1] for row in conn.execute(
            "SELECT state,COUNT(*) FROM findings WHERE synthetic=0 GROUP BY state")}
        by_severity = {row[0]: row[1] for row in conn.execute(
            "SELECT severity,COUNT(*) FROM findings WHERE synthetic=0 GROUP BY severity")}
        pending = conn.execute("SELECT COUNT(*) FROM approvals WHERE state='pending'").fetchone()[0]
        imports = conn.execute("SELECT COUNT(*) FROM imports WHERE synthetic=0").fetchone()[0]
        return {"total_findings": total, "by_status": by_state, "by_severity": by_severity,
                "pending_approvals": pending, "imports": imports}
    finally:
        conn.close()


def list_findings(status: str | None = None, limit: int = 100, offset: int = 0,
                  db_path: str | Path | None = None) -> list[dict[str, Any]]:
    initialize_database(db_path)
    conn = connect(db_path)
    try:
        limit = min(max(int(limit), 1), 500); offset = max(int(offset), 0)
        where = " WHERE state=?" if status else ""
        args: tuple[Any, ...] = (status, limit, offset) if status else (limit, offset,)
        rows = conn.execute("SELECT * FROM findings" + where + " ORDER BY updated_at DESC,id LIMIT ? OFFSET ?", args)
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_finding(finding_id: str, db_path: str | Path | None = None) -> dict[str, Any] | None:
    initialize_database(db_path)
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if row is None: return None
        result = dict(row)
        observations = conn.execute("""SELECT o.*,i.source_name,i.source_sha256,i.format AS import_format,
            i.imported_at,i.importer_version FROM observations o JOIN imports i ON i.id=o.import_id
            WHERE o.finding_id=? ORDER BY o.observed_at,o.id""", (finding_id,)).fetchall()
        result["observations"] = []
        for observation in observations:
            item = dict(observation)
            item["raw"] = json.loads(item.pop("raw_json"))
            item["raw_location"] = json.loads(item["raw_location"])
            item["normalized_location"] = json.loads(item["normalized_location"])
            item["evidence"] = [dict(e) for e in conn.execute("SELECT kind,locator,excerpt,content_sha256,created_at FROM evidence WHERE observation_id=?", (item["id"],))]
            result["observations"].append(item)
        return result
    finally:
        conn.close()
