import type {
  ActivityEvent,
  Approval,
  DashboardData,
  Finding,
  FindingStatus,
  ReviewBrief,
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { detail?: unknown } | null;
    const detail = typeof payload?.detail === "string" ? payload.detail : `Request failed (${response.status})`;
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export async function loadDashboard(): Promise<DashboardData> {
  const [summary, findings, activities, approvals] = await Promise.all([
    request<DashboardData["summary"]>("/dashboard"),
    request<Finding[]>("/findings?limit=100"),
    request<ActivityEvent[]>("/activity?limit=50"),
    request<Approval[]>("/approvals?limit=50"),
  ]);
  return { summary, findings, activities, approvals };
}

export function importReport(format: "sarif" | "json", sourceName: string, document: unknown) {
  return request<{ import_id: string; imported: number; deduplicated: number; rejected: number }>("/imports", {
    method: "POST",
    body: JSON.stringify({ format, source_name: sourceName, document }),
  });
}

export function transitionFinding(findingId: string, status: FindingStatus, reason: string, expectedVersion: number) {
  return request<Finding>(`/findings/${encodeURIComponent(findingId)}/transition`, {
    method: "POST",
    body: JSON.stringify({ status, reason, expected_version: expectedVersion, actor: "local-operator" }),
  });
}

export function createApproval(findingId: string, action: string) {
  return request<Approval>("/approvals", {
    method: "POST",
    body: JSON.stringify({
      action,
      target: findingId,
      parameters: { proposal: "review-only", execution_enabled: false },
      requester: "vulnflow-remediation",
    }),
  });
}

export function decideApproval(approvalId: string, decision: "approved" | "rejected", reason: string) {
  return request<Approval>(`/approvals/${encodeURIComponent(approvalId)}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision, reason, approver: "local-operator" }),
  });
}

export function loadReviewBrief(findingId: string) {
  return request<ReviewBrief>(`/findings/${encodeURIComponent(findingId)}/analysis`);
}


export interface AgentWorkflowResult { run_id: string; finding_id: string; status: string; agents: { agent: string; role: string; output: string; duration_ms: number }[]; final_review: string; execution_policy: string; }

export function runAgentWorkflow(findingId: string) {
  return request<AgentWorkflowResult>(`/findings/${encodeURIComponent(findingId)}/agent-workflow`, { method: "POST" });
}



export interface VerityxAssessment {
  id: string; claim: string;
  status: "current" | "potentially_stale" | "contradicted" | "insufficient_evidence";
  summary: string; freshness_score: number | null; created_at: string; method: string; rationale: string;
  evidence: { title: string; url: string; content: string; source: string; published_date: string | null; score: number | null }[];
}
export interface VerityxVerificationResponse { finding_id: string; assessment: VerityxAssessment; }

export interface PersistedVerityxAssessment {
  id: string;
  finding_id: string;
  verityx_analysis_id: string;
  status: VerityxAssessment["status"];
  method: string;
  summary: string;
  created_at: string;
  assessment: VerityxAssessment;
}

export function loadVerityxAssessmentHistory(findingId: string) {
  return request<PersistedVerityxAssessment[]>(`/findings/${encodeURIComponent(findingId)}/verityx-assessments`);
}

export interface BenchmarkEvaluation {
  type: string;
  category: string;
  score: number | null;
  label: string;
  passed: number;
  total: number;
  criteria: { name: string; passed: boolean }[];
  disclaimer: string;
}

export interface BenchmarkRun {
  evaluation: BenchmarkEvaluation | null;
  fault_evaluation?: { scenario: string; resisted: boolean; attack_followed: boolean; indicator: string; disclaimer: string } | null;
  id: string;
  agent: string;
  repetition: number;
  status: string;
  output: string;
  error: string;
  model: string;
  duration_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  tool_calls: number;
  steps: number;
  input_cost_usd: number | null;
  output_cost_usd: number | null;
  model_cost_usd: number | null;
  trace_json: string;
  sources_json: string;
}

export interface BenchmarkResult {
  experiment_id: string;
  status: string;
  task: Record<string, unknown>;
  fault: string | null;
  repetitions: number;
  agents: {
    agent: string;
    runs: number;
    success_rate: number;
    avg_duration_ms: number;
    avg_tokens: number;
    avg_tool_calls: number;
    avg_model_cost_usd: number | null;
    priced_runs: number;
    avg_heuristic_score: number | null;
  }[];
  runs: BenchmarkRun[];
}

export type BenchmarkFault = "model_unavailable" | "tool_unavailable" | "misleading_instruction" | null;

export function runBenchmark(
  task: { id: string; category: string; prompt: string },
  repetitions: number,
  fault: BenchmarkFault,
) {
  return request<BenchmarkResult>("/benchmarks/run", {
    method: "POST",
    body: JSON.stringify({ task, repetitions, fault }),
  });
}

export function verifyFindingWithVerityx(findingId: string) { return request<VerityxVerificationResponse>(`/findings/${encodeURIComponent(findingId)}/verify`, { method: "POST" }); }
