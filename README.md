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
- `langgraph-bifrost`: a real LangGraph `StateGraph` with preparation and inference nodes, using the same Bifrost gateway.

All receive the same task through the framework-neutral adapter contract. Repetitions, fault scenario, per-run status, output, steps, tool calls, token usage, latency, sources, step traces, and nullable model-cost fields are stored in SQLite. Existing databases are migrated automatically. API routes:
- `POST /api/benchmarks/run` with `{"task":{"id":"research-001","prompt":"..."}, "repetitions":2, "fault":null}`
- `GET /api/benchmarks/{experiment_id}`

Environment configuration (set in the backend process environment; never commit secrets):
- `BIFROST_BASE_URL` (default `http://127.0.0.1:8080`)
- `BIFROST_VIRTUAL_KEY`
- `BIFROST_MODEL` (default `openai/gpt-4o-mini`)
- `TAVILY_API_KEY`
- `VULNFLOW_MODEL_PRICING_JSON` (optional JSON keyed by the exact returned model identifier; each value requires `input_per_1m` and `output_per_1m` USD rates). Example: `{"provider/model":{"input_per_1m":0.15,"output_per_1m":0.60}}`.

Model inference cost is calculated only when an explicit rate exists. Missing rates are `unknown` (`NULL`), never silently treated as zero. Costs exclude Tavily/tool charges and local infrastructure. An explicitly configured zero rate is valid. Existing DBs gain nullable cost columns automatically.

Supported controlled failures: `model_unavailable`, `tool_unavailable`, and `misleading_instruction`. These are controlled scenarios, not proof of resilience or real provider outages. The misleading-instruction check is marker-based only. LangGraph is a real framework integration; other frameworks can use the structural adapter contract. Docker isolation, richer retry/failover semantics, and production-grade run cancellation remain future work.

Run backend tests from repository root:
```powershell
python -m unittest discover -s tests/backend -v
```


## Guided review workflow

The Investigations view includes a **Run review workflow** action for a selected imported finding. It connects existing local capabilities in sequence:

1. Requests the deterministic, evidence-grounded investigation brief.
2. Records the finding's transition to `investigating`.
3. Creates a `propose_remediation` approval request for a human decision.
4. Refreshes the workspace so the updated state and approval are visible.

This is workflow orchestration across existing API actions, not an autonomous remediation agent. It does not generate, modify, execute, or verify a patch. The approval records a decision only.

## Specialist-agent investigation

The Investigations view also exposes **Run 4-agent investigation**. This executes four sequential calls through the configured Bifrost gateway:

1. **Sentinel** — triage and classify the imported report.
2. **Analyst** — reason about exploitability, preconditions, impact, and uncertainty.
3. **Architect** — propose remediation guidance and validation tests.
4. **Verifier** — independently critique the preceding handoffs for unsupported claims, gaps, and residual risk.

Each stage receives the prior agents' outputs. Run metadata, per-agent status, outputs, errors, and duration are persisted in local SQLite. API routes:
- POST /api/findings/{finding_id}/agent-workflow
- GET /api/agent-workflows/{run_id}

This is actual sequential multi-call orchestration, not concurrent agents or a shared Switch room. It is analysis-only: agents have no repository access, do not execute code or tests, do not apply patches, and do not independently verify vulnerabilities. A failed stage marks the run failed; automatic retries and recovery are not implemented. Configure BIFROST_VIRTUAL_KEY, BIFROST_BASE_URL, and BIFROST_MODEL in the backend environment.

## Demo walkthrough (under 3 minutes)

1. Start the backend and frontend using the Development instructions.
2. Import a SARIF 2.1.0 or VulnFlow JSON v1 report containing at least one finding.
3. Open **Investigations**, select the finding, and generate its review brief. Show the evidence, provenance, gaps, and recommended checks.
4. Click **Run review workflow**. Show the Investigating lifecycle state and the newly created remediation approval.
5. Open **Approvals**, enter a reason, and approve or reject the proposal. Explain that this records a human decision; it does not apply a patch.
6. Optionally open **Audit** to show the recorded application events.

For the agent benchmark demonstration, open **Benchmarks**, run a security task, and expand a run to inspect its model, trace, sources, and heuristic evaluation criteria. Heuristic scores are lexical screening signals, not proof of correctness.

## Switch integration disclosure

The current repository does not implement live Switch roster/session connectivity or demonstrate a shared-room agent handoff. The Agent Network view explicitly reports this limitation. Do not describe the current benchmark adapters as Switch-connected agents unless that integration is implemented and verified.


## Build validation

Run from the repository root:

```powershell
python -m pip install -e .\\backend
python -m compileall -q backend/app
python -m unittest discover -s tests/backend -v
cd frontend
npm.cmd ci
npm.cmd run build
```

GitHub Actions runs the backend test suite and TypeScript/Vite production build on pushes and pull requests. The tests use isolated temporary SQLite databases where applicable. External-provider workflows still require local Bifrost/Tavily configuration and are not represented as provider-independent CI checks.

## Verityx integration

Set `VERITYX_BASE_URL=http://127.0.0.1:8030` in the VulnFlow backend environment. Start Verityx independently with its own Tavily and Bifrost configuration. Use the finding-level **Verify with Verityx** action to retrieve an evidence assessment; the result is persisted in VulnFlow and recorded in the audit log. A Verityx result is evidence intelligence, not proof of exploitability or patch correctness.
