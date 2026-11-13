PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS imports (
    id TEXT PRIMARY KEY,
    format TEXT NOT NULL CHECK (format IN ('sarif-2.1.0', 'vulnflow-json-1')),
    source_name TEXT NOT NULL,
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    importer_version TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    result_count INTEGER NOT NULL DEFAULT 0 CHECK (result_count >= 0),
    synthetic INTEGER NOT NULL DEFAULT 0 CHECK (synthetic IN (0, 1)),
    UNIQUE(format, source_sha256)
);

CREATE TABLE IF NOT EXISTS findings (
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
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL REFERENCES imports(id) ON DELETE RESTRICT,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    result_index INTEGER NOT NULL CHECK (result_index >= 0),
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    raw_location TEXT NOT NULL DEFAULT '{}',
    normalized_location TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    UNIQUE(import_id, result_index)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL,
    locator TEXT NOT NULL DEFAULT '',
    excerpt TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    parameter_sha256 TEXT NOT NULL CHECK (length(parameter_sha256) = 64),
    requester TEXT NOT NULL,
    approver TEXT,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','rejected','expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    correlation_id TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64)
);

CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_observations_finding ON observations(finding_id);
CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals(state);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_events(entity_type, entity_id, id);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;


-- Immutable snapshots of Verityx assessments, linked to canonical findings.
CREATE TABLE IF NOT EXISTS verityx_assessments (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
    verityx_analysis_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('current','potentially_stale','contradicted','insufficient_evidence')),
    method TEXT NOT NULL,
    summary TEXT NOT NULL,
    assessment_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verityx_assessments_finding
ON verityx_assessments(finding_id, created_at DESC);
