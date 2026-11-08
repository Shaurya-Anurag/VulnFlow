"""Reproducible research-agent benchmark engine.

Two strategies share one Bifrost model gateway and identical task inputs:
- direct: answer from the task without web research
- research: retrieve Tavily sources, then synthesize through Bifrost

All external calls are explicit, timed, and persisted. No API key is stored in SQLite.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float = 180) -> tuple[dict[str, Any], float]:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=body, headers={**headers, "Content-Type": "application/json"}, method="POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"External request failed: {type(exc).__name__}: {str(exc)[:300]}") from exc
    return data, (time.perf_counter() - started) * 1000

class AgentAdapter(ABC):
    """Framework-neutral contract: task in, structured execution record out."""
    name: str
    @abstractmethod
    def execute(self, task: dict[str, Any], fault: str | None = None) -> dict[str, Any]: ...

class AgentRegistry:
    """Explicit registry for framework-neutral benchmark agents."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentAdapter] = {}

    def register(self, agent: AgentAdapter) -> None:
        if not isinstance(agent, AgentAdapter):
            raise TypeError("Registered agents must implement AgentAdapter")
        name = getattr(agent, "name", "")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Agent name must be a non-empty string")
        if name in self._agents:
            raise ValueError(f"Agent already registered: {name}")
        self._agents[name] = agent

    def get(self, name: str) -> AgentAdapter:
        try:
            return self._agents[name]
        except KeyError as exc:
            raise KeyError(f"Unknown benchmark agent: {name}") from exc

    def list_agents(self) -> list[AgentAdapter]:
        """Return registered agents in registration order."""
        return list(self._agents.values())


class BifrostClient:
    def __init__(self) -> None:
        self.base = os.getenv("BIFROST_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
        self.key = os.getenv("BIFROST_VIRTUAL_KEY", os.getenv("BIFROST_API_KEY", ""))
        self.model = os.getenv("BIFROST_MODEL", "ollama/qwen3:4b")

    def complete(self, system: str, user: str, fault: str | None = None, max_tokens: int = 512) -> dict[str, Any]:
        if fault == "model_unavailable":
            raise RuntimeError("Injected fault: model unavailable")
        if not self.key:
            raise RuntimeError("BIFROST_VIRTUAL_KEY is not configured; refusing unauthenticated or paid-provider inference")
        headers = {"x-bf-vk": self.key}
        data, latency = _post_json(
            f"{self.base}/v1/chat/completions",
            {"model": self.model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "temperature": 0, "max_tokens": max(128, min(int(max_tokens), 2048)), "think": False, "reasoning_effort": "none"},
            headers,
        )
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = data.get("usage") or {}
        output = str(message.get("content") or "").strip()
        import re
        output = re.sub(r"<think>.*?</think>", "", output, flags=re.DOTALL | re.IGNORECASE).strip()
        finish_reason = str(choice.get("finish_reason") or "")
        if finish_reason == "length":
            raise RuntimeError("Model completion hit the token limit; answer may be truncated")
        if not output:
            raise RuntimeError("Model returned no final answer; refusing to count an empty completion as success")
        return {
            "output": output,
            "model": data.get("model", self.model),
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
            "latency_ms": round(latency, 2),
            "request_id": data.get("id", ""),
            "finish_reason": finish_reason,
        }

class TavilyClient:
    def __init__(self) -> None:
        self.key = os.getenv("TAVILY_API_KEY", "")

    def search(self, query: str, fault: str | None = None) -> dict[str, Any]:
        if fault == "tool_unavailable":
            raise RuntimeError("Injected fault: Tavily tool unavailable")
        if not self.key:
            raise RuntimeError("TAVILY_API_KEY is not configured")
        data, latency = _post_json(
            "https://api.tavily.com/search",
            {"api_key": self.key, "query": query, "search_depth": "basic", "max_results": 5, "include_answer": False},
            {},
            timeout=25,
        )
        results = data.get("results") or []
        return {"results": results, "latency_ms": round(latency, 2), "tool_calls": 1}

class DirectResearchAgent(AgentAdapter):
    name = "direct-bifrost"
    def __init__(self, llm: BifrostClient) -> None: self.llm = llm
    def execute(self, task: dict[str, Any], fault: str | None = None) -> dict[str, Any]:
        result = self.llm.complete(
            "Answer the research task accurately in at most 120 words. State uncertainty and do not invent sources. Return the final answer directly.",
            task["prompt"], fault,
        )
        result.update({"steps": 1, "tool_calls": 0, "trace": [{"step": 1, "kind": "model", "model": result["model"], "latency_ms": result["latency_ms"]}]})
        return result

class TavilyResearchAgent(AgentAdapter):
    name = "tavily-assisted-bifrost"
    def __init__(self, llm: BifrostClient, search: TavilyClient) -> None:
        self.llm, self.search = llm, search
    def execute(self, task: dict[str, Any], fault: str | None = None) -> dict[str, Any]:
        if fault == "model_unavailable":
            raise RuntimeError("Injected fault: model unavailable")
        search = self.search.search(task["prompt"], fault)
        sources = [{"title": x.get("title", ""), "url": x.get("url", ""), "content": str(x.get("content", ""))[:3000]} for x in search["results"]]
        result = self.llm.complete(
            "Answer in at most 150 words using only the supplied research where possible. Cite source URLs inline. Identify gaps and uncertainty. Return the final answer directly.",
            task["prompt"] + "\n\nResearch sources:\n" + json.dumps(sources, ensure_ascii=False), fault,
        )
        result.update({
            "steps": 2, "tool_calls": search["tool_calls"],
            "tool_latency_ms": search["latency_ms"],
            "sources": [{"title": x["title"], "url": x["url"]} for x in sources],
            "trace": [
                {"step": 1, "kind": "tool", "tool": "tavily.search", "latency_ms": search["latency_ms"], "results": len(sources)},
                {"step": 2, "kind": "model", "model": result["model"], "latency_ms": result["latency_ms"]},
            ],
        })
        return result

def _init_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS benchmark_experiments (
      id TEXT PRIMARY KEY, task_json TEXT NOT NULL, repetitions INTEGER NOT NULL,
      fault TEXT, created_at TEXT NOT NULL, status TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS benchmark_runs (
      id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES benchmark_experiments(id),
      agent TEXT NOT NULL, repetition INTEGER NOT NULL, status TEXT NOT NULL,
      output TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
      prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0,
      tool_calls INTEGER NOT NULL DEFAULT 0, steps INTEGER NOT NULL DEFAULT 0,
      duration_ms REAL NOT NULL DEFAULT 0, tool_latency_ms REAL NOT NULL DEFAULT 0,
      model TEXT NOT NULL DEFAULT '', trace_json TEXT NOT NULL DEFAULT '[]',
      sources_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_benchmark_runs_experiment ON benchmark_runs(experiment_id);
    """)

# Lightweight, transparent rubric checks. These are lexical signals, not semantic proof.
_RUBRICS: dict[str, list[tuple[str, tuple[str, ...]]]] = {
    "sql_injection": [
        ("Explains attacker-controlled input changing SQL structure", ("attacker-controlled", "user input", "sql syntax", "query structure", "injected")),
        ("Recommends parameterized queries / prepared statements", ("parameterized quer", "prepared statement", "placeholders")),
        ("Separately binds values rather than interpolating SQL", ("bind parameter", "bound parameter", "separate parameter", "not concatenate", "not interpolate")),
        ("Includes least-privilege database access", ("least privilege", "least-privileged", "limited privileges")),
        ("Treats validation/escaping as defense-in-depth, not the primary fix", ("defense in depth", "defence in depth", "not a substitute", "not replace parameterized")),
    ],
    "xss": [
        ("Explains script execution in a victim's browser", ("victim's browser", "victim browser", "browser executes", "javascript executes")),
        ("Recommends context-aware output encoding", ("output encod", "contextual encod", "html encod")),
        ("Recommends safe DOM APIs / avoiding unsafe HTML insertion", ("textcontent", "text content", "avoid innerhtml", "safe dom")),
        ("Treats Content Security Policy as defense-in-depth", ("content security policy", "csp")),
        ("Mentions cookie protections where relevant", ("httponly", "sameSite", "same-site")),
    ],
    "idor": [
        ("Explains missing object-level authorization", ("object-level authorization", "object level authorization", "authorization check", "access control")),
        ("Requires server-side authorization on every request", ("server-side", "every request", "each request")),
        ("Does not rely on unpredictable IDs alone", ("unpredictable id", "unguessable id", "not sufficient")),
        ("Recommends deny-by-default / least privilege", ("deny by default", "least privilege")),
        ("Tests cross-user access", ("cross-user", "other user", "different user")),
    ],
    "ssrf": [
        ("Explains server-side requests to attacker-controlled destinations", ("server-side request", "attacker-controlled url", "user-controlled url")),
        ("Recommends strict destination allowlists", ("allowlist", "allow-list", "allow list")),
        ("Blocks private, loopback, and link-local destinations", ("loopback", "private ip", "link-local", "metadata endpoint")),
        ("Revalidates redirects and DNS resolution", ("redirect", "dns rebinding", "dns resolution")),
        ("Recommends outbound network / egress controls", ("egress", "outbound network")),
    ],
    "insecure_deserialization": [
        ("Identifies risk from untrusted serialized data", ("untrusted serialized", "untrusted data", "deserializ")),
        ("Avoids unsafe native object deserialization", ("unsafe deserial", "native deserial", "avoid pickle", "avoid object deserial")),
        ("Recommends safe formats and schema validation", ("json", "schema validation", "validate schema")),
        ("Notes integrity signatures do not make unsafe parsing safe", ("signature", "does not make", "parser")),
        ("Recommends least privilege / isolation", ("least privilege", "sandbox", "isolation")),
    ],
}
def evaluate_answer(task: dict[str, Any], output: str) -> dict[str, Any]:
    prompt = str(task.get("prompt", "")).lower()
    if any(x in prompt for x in ("sql injection", "sqli")):
        category = "sql_injection"
    elif "xss" in prompt or "cross-site scripting" in prompt:
        category = "xss"
    elif "idor" in prompt or "insecure direct object" in prompt:
        category = "idor"
    elif "ssrf" in prompt or "server-side request forgery" in prompt:
        category = "ssrf"
    elif "deserializ" in prompt:
        category = "insecure_deserialization"
    else:
        return {"type": "heuristic", "category": "general", "score": None,
                "label": "No rubric", "passed": 0, "total": 0, "criteria": [],
                "disclaimer": "No task-specific rubric is configured; execution success is not answer correctness."}
    text = output.lower()
    criteria = [{"name": name, "passed": any(term in text for term in terms)}
                for name, terms in _RUBRICS[category]]
    passed = sum(item["passed"] for item in criteria)
    total = len(criteria)
    score = round(passed / total * 100)
    return {"type": "heuristic", "category": category, "score": score,
            "label": "Strong signals" if score >= 80 else ("Partial signals" if score >= 40 else "Weak signals"),
            "passed": passed, "total": total, "criteria": criteria,
            "disclaimer": "Keyword-based screening only; it does not establish technical correctness or replace expert review."}

def build_default_registry(llm: BifrostClient | None = None, search: TavilyClient | None = None) -> AgentRegistry:
    """Construct and register the built-in agents; external adapters can use the same contract."""
    llm_client = llm or BifrostClient()
    search_client = search or TavilyClient()
    registry = AgentRegistry()
    registry.register(DirectResearchAgent(llm_client))
    registry.register(TavilyResearchAgent(llm_client, search_client))
    return registry


def run_experiment(db_path: str, task: dict[str, Any], repetitions: int = 2, fault: str | None = None) -> dict[str, Any]:
    if not isinstance(task.get("prompt"), str) or not task["prompt"].strip():
        raise ValueError("task.prompt is required")
    if repetitions < 1 or repetitions > 10:
        raise ValueError("repetitions must be between 1 and 10")
    if fault not in {None, "model_unavailable", "tool_unavailable"}:
        raise ValueError("Unsupported fault scenario")
    experiment_id = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _init_tables(conn)
    created = utcnow()
    conn.execute("INSERT INTO benchmark_experiments VALUES (?,?,?,?,?,?)",
                 (experiment_id, json.dumps(task), repetitions, fault, created, "running"))
    conn.commit()
    registry = build_default_registry()
    agents = registry.list_agents()
    for repetition in range(1, repetitions + 1):
        for agent in agents:
            run_id, started = str(uuid.uuid4()), time.perf_counter()
            try:
                result = agent.execute(task, fault if (fault != "tool_unavailable" or agent.name == "tavily-assisted-bifrost") else None)
                status, error = "completed", ""
            except Exception as exc:
                result, status, error = {}, "failed", str(exc)[:1000]
            duration = round((time.perf_counter() - started) * 1000, 2)
            conn.execute("""INSERT INTO benchmark_runs
                (id,experiment_id,agent,repetition,status,output,error,prompt_tokens,completion_tokens,
                 tool_calls,steps,duration_ms,tool_latency_ms,model,trace_json,sources_json,created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (run_id, experiment_id, agent.name, repetition, status, result.get("output", ""), error,
                 result.get("prompt_tokens", 0), result.get("completion_tokens", 0), result.get("tool_calls", 0),
                 result.get("steps", 0), duration, result.get("tool_latency_ms", 0), result.get("model", ""),
                 json.dumps(result.get("trace", [])), json.dumps(result.get("sources", [])), utcnow()))
            conn.commit()
    rows = [dict(x) for x in conn.execute("SELECT * FROM benchmark_runs WHERE experiment_id=? ORDER BY repetition,agent", (experiment_id,))]
    for row in rows:
        row["evaluation"] = evaluate_answer(task, row["output"]) if row["status"] == "completed" else None
    final_status = "completed" if all(x["status"] == "completed" for x in rows) else ("partial" if any(x["status"] == "completed" for x in rows) else "failed")
    conn.execute("UPDATE benchmark_experiments SET status=? WHERE id=?", (final_status, experiment_id))
    conn.commit()
    conn.close()
    summaries = []
    for agent_name in [x.name for x in agents]:
        group = [x for x in rows if x["agent"] == agent_name]
        summaries.append({
            "agent": agent_name, "runs": len(group),
            "success_rate": round(sum(x["status"] == "completed" for x in group) / len(group), 3),
            "avg_duration_ms": round(sum(x["duration_ms"] for x in group) / len(group), 2),
            "avg_tokens": round(sum(x["prompt_tokens"] + x["completion_tokens"] for x in group) / len(group), 2),
            "avg_tool_calls": round(sum(x["tool_calls"] for x in group) / len(group), 2),
            "avg_heuristic_score": (round(sum(x["evaluation"]["score"] for x in group if x.get("evaluation") and x["evaluation"]["score"] is not None) / max(1, sum(1 for x in group if x.get("evaluation") and x["evaluation"]["score"] is not None)), 1) if any(x.get("evaluation") and x["evaluation"]["score"] is not None for x in group) else None),
        })
    return {"experiment_id": experiment_id, "status": final_status, "task": task, "fault": fault,
            "repetitions": repetitions, "agents": summaries, "runs": rows}
