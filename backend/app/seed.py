"""Clearly synthetic, deterministic demo records. Never represents real findings."""
from __future__ import annotations

import hashlib
import json
import sqlite3

from .audit import append_event
from .db import transaction

SYNTHETIC_LABEL = "SYNTHETIC DEMO — not a real vulnerability report"


def seed_demo(conn: sqlite3.Connection) -> int:
    records = [
        ("00000000-0000-4000-8000-000000000001", "DEMO-RULE-001", "Example input validation review", "medium", "demo://training/sample-app", 1),
        ("00000000-0000-4000-8000-000000000002", "DEMO-RULE-002", "Example dependency inventory review", "low", "demo://training/sample-app", 2),
    ]
    created = 0
    with transaction(conn):
        for finding_id, rule, title, severity, target, line in records:
            dedup = hashlib.sha256(("synthetic\0" + finding_id).encode()).hexdigest()
            if conn.execute("SELECT 1 FROM findings WHERE id=? OR dedup_key=?", (finding_id, dedup)).fetchone():
                continue
            now = "2026-01-01T00:00:00+00:00"
            conn.execute("INSERT INTO findings(id,dedup_key,title,severity,state,target,rule_id,synthetic,created_at,updated_at) VALUES(?,?,?,?, 'reported',?,?,1,?,?)",
                         (finding_id, dedup, f"[SYNTHETIC DEMO] {title}", severity, target, rule, now, now))
            created += 1
        if created:
            import_id = "synthetic-demo-import-v1"
            conn.execute("INSERT OR IGNORE INTO imports(id,format,source_name,source_sha256,importer_version,imported_at,actor,result_count,synthetic) VALUES(?,?,?,?,?,?,?,?,1)",
                         (import_id, "vulnflow-json-1", SYNTHETIC_LABEL,
                          hashlib.sha256(SYNTHETIC_LABEL.encode()).hexdigest(), "seed-v1", "2026-01-01T00:00:00+00:00", "seed", created))
            for idx, (finding_id, rule, title, severity, target, line) in enumerate(records):
                if not conn.execute("SELECT 1 FROM observations WHERE import_id=? AND result_index=?", (import_id, idx)).fetchone():
                    observation_id = f"synthetic-observation-{idx + 1}"
                    raw = {"title": title, "severity": severity, "target": target, "synthetic_label": SYNTHETIC_LABEL}
                    conn.execute("INSERT INTO observations(id,import_id,finding_id,result_index,tool_name,rule_id,raw_json,raw_location,normalized_location,observed_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (observation_id, import_id, finding_id, idx, "VulnFlow synthetic demo", rule,
                                  json.dumps(raw, sort_keys=True), json.dumps({"uri": target, "line": line}),
                                  json.dumps({"uri": target, "line": line}), "2026-01-01T00:00:00+00:00"))
                    conn.execute("INSERT INTO evidence(id,observation_id,kind,locator,excerpt,content_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
                                 (f"synthetic-evidence-{idx + 1}", observation_id, "synthetic-label", target,
                                  SYNTHETIC_LABEL, hashlib.sha256(SYNTHETIC_LABEL.encode()).hexdigest(),
                                  "2026-01-01T00:00:00+00:00"))
            append_event(conn, "seed", "demo.seeded", "import", import_id,
                         {"synthetic": True, "label": SYNTHETIC_LABEL, "created_findings": created})
    return created
