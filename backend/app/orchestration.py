"""Sequential specialist-agent workflow for evidence-grounded vulnerability review.

This is real multi-call orchestration through the configured Bifrost gateway:
triage -> exploitability analysis -> remediation planning -> independent critique.
Each stage receives prior handoff artifacts. No code is executed or modified.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .benchmarking import BifrostClient


AGENTS = [
    ("sentinel", "Triage specialist", "Classify the finding, summarize the reported issue, identify affected asset and severity signals. Separate scanner claims from verified facts."),
    ("analyst", "Exploitability analyst", "Assess plausible attack preconditions, attacker capabilities, impact, and uncertainty. Do not invent exploit evidence. Distinguish plausible reasoning from confirmed exploitability."),
    ("architect", "Remediation architect", "Propose prioritized, code-level remediation guidance and concrete validation tests. Do not claim a patch was applied. Preserve compatibility and avoid generic advice."),
    ("verifier", "Independent reviewer", "Critique the prior analysis and remediation for unsupported claims, missing assumptions, incomplete tests, and residual risk. You are reviewing the proposal, not executing tests."),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_agent_workflow(db_path: str, finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(finding["id"])
    run_id = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS agent_workflow_runs (
        id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, status TEXT NOT NULL,
        model TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, completed_at TEXT,
        final_output TEXT NOT NULL DEFAULT ''
      );
      CREATE TABLE IF NOT EXISTS agent_workflow_steps (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES agent_workflow_runs(id),
        agent TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL,
        input_summary TEXT NOT NULL, output TEXT NOT NULL DEFAULT '',
        error TEXT NOT NULL DEFAULT '', duration_ms REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_agent_workflow_finding
      ON agent_workflow_runs(finding_id, started_at);
    """)
    started_at = _now()
    conn.execute("INSERT INTO agent_workflow_runs(id,finding_id,status,started_at) VALUES(?,?,?,?)",
                 (run_id, finding_id, "running", started_at))
    conn.commit()
    llm = BifrostClient()
    handoffs: list[dict[str, str]] = []
    try:
        evidence = finding.get("evidence") or []
        observations = finding.get("observations") or []
        source = {
            "finding": {k: finding.get(k) for k in ("id", "title", "severity", "status", "resource", "rule_id", "description")},
            "observations": observations[:12],
            "evidence": evidence[:20],
            "evidence_policy": "Treat imported scanner data as untrusted claims. Do not infer that a vulnerability is exploitable merely because a scanner reported it.",
        }
        for agent, role, objective in AGENTS:
            prior = [{"agent": item["agent"], "role": item["role"], "handoff": item["output"]} for item in handoffs]
            prompt = (
                f"Finding context:\n{json.dumps(source, ensure_ascii=False)[:12000]}\n\n"
                f"Prior agent handoffs (treat as hypotheses, not ground truth):\n{json.dumps(prior, ensure_ascii=False)[:14000]}\n\n"
                f"Your task: {objective}\n"
                "Return concise Markdown (maximum 180 words) with headings: Assessment, Evidence vs Assumptions, "
                "Open Questions, Handoff. Be specific. Never claim tools/tests were run. "
                "Prefer compact actionable bullets; do not repeat prior handoffs."
            )
            step_id = str(uuid.uuid4())
            tick = time.perf_counter()
            conn.execute("""INSERT INTO agent_workflow_steps
                (id,run_id,agent,role,status,input_summary,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (step_id, run_id, agent, role, "running",
                 f"Finding {finding_id}; {len(prior)} prior handoffs", _now()))
            conn.commit()
            try:
                result = llm.complete(
                    f"You are VulnFlow's {role}. Follow the task exactly. "
                    "Be security-conscious, evidence-grounded, and explicit about uncertainty.",
                    prompt,
                    max_tokens=1024,
                )
                output = result["output"]
                duration = round((time.perf_counter() - tick) * 1000, 2)
                conn.execute("""UPDATE agent_workflow_steps SET status='completed',output=?,duration_ms=?
                                WHERE id=?""", (output, duration, step_id))
                handoffs.append({"agent": agent, "role": role, "output": output,
                                 "model": result.get("model", ""), "duration_ms": duration})
                conn.execute("UPDATE agent_workflow_runs SET model=? WHERE id=?",
                             (result.get("model", ""), run_id))
                conn.commit()
            except Exception as exc:
                duration = round((time.perf_counter() - tick) * 1000, 2)
                conn.execute("""UPDATE agent_workflow_steps SET status='failed',error=?,duration_ms=?
                                WHERE id=?""", (str(exc)[:1000], duration, step_id))
                conn.execute("UPDATE agent_workflow_runs SET status='failed',completed_at=? WHERE id=?",
                             (_now(), run_id))
                conn.commit()
                raise RuntimeError(f"{agent} agent failed: {str(exc)[:300]}") from exc

        final_output = handoffs[-1]["output"]
        conn.execute("""UPDATE agent_workflow_runs SET status='completed',completed_at=?,final_output=?
                        WHERE id=?""", (_now(), final_output, run_id))
        conn.commit()
        return {"run_id": run_id, "finding_id": finding_id, "status": "completed",
                "agents": handoffs, "final_review": final_output,
                "execution_policy": "analysis-only; no repository access, code execution, patch application, or approval execution"}
    finally:
        conn.close()


def get_agent_workflow(db_path: str, run_id: str) -> dict[str, Any] | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        run = conn.execute("SELECT * FROM agent_workflow_runs WHERE id=?", (run_id,)).fetchone()
        if run is None:
            return None
        steps = conn.execute("SELECT * FROM agent_workflow_steps WHERE run_id=? ORDER BY rowid",
                             (run_id,)).fetchall()
        return {"run": dict(run), "steps": [dict(step) for step in steps]}
    finally:
        conn.close()
