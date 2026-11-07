export type FindingStatus =
  | "reported"
  | "investigating"
  | "planned"
  | "patching"
  | "verifying"
  | "resolved"
  | "rejected";

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export interface Evidence {
  id: string;
  kind: string;
  excerpt?: string | null;
  uri?: string | null;
  source_hash?: string | null;
}

export interface Observation {
  id: string;
  import_id: string;
  source_name: string;
  tool_name?: string | null;
  tool_version?: string | null;
  imported_at: string;
  source_hash: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  rule_id?: string | null;
  resource?: string | null;
  description?: string | null;
  synthetic: boolean;
  created_at: string;
  updated_at: string;
  version: number;
  fingerprint: string;
  evidence: Evidence[];
  observations: Observation[];
}

export interface DashboardSummary {
  total: number;
  real_total: number;
  synthetic_total: number;
  active: number;
  pending_approvals: number;
  by_severity: Partial<Record<Severity, number>>;
  by_status: Partial<Record<FindingStatus, number>>;
}

export interface ActivityEvent {
  id: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface Approval {
  id: string;
  action: string;
  target: string;
  parameters: Record<string, unknown>;
  parameter_hash: string;
  requester: string;
  approver?: string | null;
  decision?: "approved" | "rejected" | null;
  reason?: string | null;
  status: "pending" | "approved" | "rejected" | "expired";
  created_at: string;
  expires_at: string;
}

export interface DashboardData {
  summary: DashboardSummary;
  findings: Finding[];
  activities: ActivityEvent[];
  approvals: Approval[];
}


export interface ReviewBrief {
  finding_id: string;
  title: string;
  reported_severity: string;
  workflow_state: string;
  review_status: string;
  verification_claim: string;
  summary: string;
  observations: number;
  evidence: { kind: string; locator: string; excerpt: string; has_excerpt: boolean; content_sha256: string }[];
  locations: Record<string, unknown>[];
  scanner_tools: { name: string; version: string; rule_id: string }[];
  source_count: number;
  gaps: string[];
  recommended_checks: string[];
  limitations: string[];
}
