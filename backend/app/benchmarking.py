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

def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float = 45) -> tuple[dict[str, Any], float]:
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

class BifrostClient:
    def __init__(self) -> None:
        self.base = os.getenv("BIFROST_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
        self.key = os.getenv("BIFROST_API_KEY", "")
        self.model = os.getenv("BIFROST_MODEL", "openai/gpt-4o-mini")

    def complete(self, system: str, user: str, fault: str | None = None) -> dict[str, Any]:
        if fault == "model_unavailable":
            raise RuntimeError("Injected fault: model unavailable")
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        data, latency = _post_json(
            f"{self.base}/v1/chat/completions",
            {"model": self.model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            headers,
        )
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = data.get("usage") or {}
        return {
            "output": str(message.get("content") or ""),
            "model": data.get("model", self.model),
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
            "latency_ms": round(latency, 2),
            "request_id": data.get("id", ""),
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
            "Answer the research task accurately. State uncertainty and do not invent sources.",
            task["prompt"], fault,
        )
        result.update({"steps": 1, "tool_calls": 0, "trace": [{"step": 1, "kind": "model", "model": result["model"], "latency_ms": result["latency_ms"]}]})
        return result

class TavilyResearchAgent(AgentAdapter):
    name = "tavily-assisted-bifrost"
    def __init__(self, llm: BifrostClient, search: TavilyClient) -> None:
        self.llm, self.search = llm, search
    def execute(self, task: dict[str, Any], fault: str | None = None) -> dict[str, Any]:
        search = self.search.search(task["prompt"], fault)
        sources = [{"title": x.get("title", ""), "url": x.get("url", ""), "content": str(x.get("content", ""))[:3000]} for x in search["results"]]
        result = self.llm.complete(
            "Answer using only the supplied research where possible. Cite source URLs inline. Identify gaps and uncertainty.",
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
    llm = BifrostClient()
    agents: list[AgentAdapter] = [DirectResearchAgent(llm), TavilyResearchAgent(llm, TavilyClient())]
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
    conn.execute("UPDATE benchmark_experiments SET status='completed' WHERE id=?", (experiment_id,))
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
        })
    return {"experiment_id": experiment_id, "status": "completed", "task": task, "fault": fault,
            "repetitions": repetitions, "agents": summaries, "runs": rows}
