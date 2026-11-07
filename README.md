# VulnFlow

VulnFlow is a local-first vulnerability finding review workspace. This MVP imports existing SARIF/JSON reports; it does not scan targets, execute agent actions, or verify imported claims.

## Trust boundary

The MVP assumes one trusted interactive user on a single-user machine, with no LAN sharing. Start the API on `127.0.0.1` only. It has no authentication: loopback reduces network exposure but does not distinguish other local users or processes. Imported reports, evidence, paths, URLs, and agent activity are untrusted data. Imports are bounded and treated as data: VulnFlow never follows report URIs or executes imported content. The UI renders report text as text. SQLite and its audit events are local files; a user who can modify those files can change the audit history.

Findings move through `reported → investigating → planned → patching → verifying → resolved` or `rejected`, with explicit retry and reopen transitions. Approvals record an agent proposal and a local human decision bound to the action and parameters. An approval does not execute anything. Demo records are synthetic examples and are labeled as such; they are excluded from real import totals.

## Development

Backend (from `backend/`, with the declared Python dependencies already installed):

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend (from `frontend/`, after installing the declared npm dependencies locally):

```powershell
npm.cmd install --no-audit --no-fund
npm.cmd run dev -- --host 127.0.0.1
```

Open the local Vite URL shown by the command. The frontend uses Vite with React and TypeScript; packages are installed in the project directory, with no global install.

The database is stored in the user's local application data directory (`%LOCALAPPDATA%/VulnFlow/vulnflow.sqlite3` on Windows, or `~/.local/share/vulnflow/vulnflow.sqlite3` elsewhere). Set `VULNFLOW_DB_PATH` to use a specific database path, such as a temporary path for tests.

## Supported imports

- SARIF 2.1.0.
- VulnFlow JSON v1 report: `{ "schema_version": "1", "tool": { "name": "...", "version": "..." }, "results": [ { "rule_id", "title", "severity", "target", "location", "fingerprint", "evidence" } ] }`.

Imports preserve source/run and observation provenance. Deduplication links repeated observations to a canonical finding rather than discarding their source records. The API reports validation failures without committing partial imports.

The dashboard limits selected files to 2 MiB; the API/parser enforces a 10 MiB request ceiling and additional depth, result-count, string, and evidence limits.

## Local safety limits

The MVP binds to loopback and restricts browser origins to the local UI. Do not expose it on a LAN or use it as a multi-user service. Keep evidence size and retention in mind: scanner reports can contain sensitive paths, snippets, or personal data. Back up the database before moving or deleting it.


## Agent benchmarking (Problem 02)

VulnFlow now includes an initial framework-neutral research benchmark runner with two adapters:
- `direct-bifrost`: direct model response through Bifrost.
- `tavily-assisted-bifrost`: Tavily retrieval followed by Bifrost synthesis.

Both receive the same task prompt. Repetitions, fault scenario, per-run status, output, steps, tool calls, token usage, latency, sources and step traces are stored in the existing local SQLite database in dedicated benchmark tables. API routes:
- `POST /api/benchmarks/run` with `{"task":{"id":"research-001","prompt":"..."}, "repetitions":2, "fault":null}`
- `GET /api/benchmarks/{experiment_id}`

Environment configuration (set in the backend process environment; never commit secrets):
- `BIFROST_BASE_URL` (default `http://127.0.0.1:8080`)
- `BIFROST_VIRTUAL_KEY`
- `BIFROST_MODEL` (default `openai/gpt-4o-mini`)
- `TAVILY_API_KEY`

Supported controlled failures: `model_unavailable` and `tool_unavailable`. These are deterministic injected failures, not real provider outages. This first iteration records provider token usage where returned; monetary cost, richer retry/failover semantics, misleading-instruction suites, Docker isolation, and production-grade run cancellation remain future work. Do not claim these are implemented until added and tested.

Run backend tests from repository root:
```powershell
python -m unittest discover -s tests/backend -v
```
