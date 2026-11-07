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
