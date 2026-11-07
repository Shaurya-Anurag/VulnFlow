import { useMemo, useState, type ChangeEvent, type ReactNode } from "react";
import type {
  ActivityEvent,
  Approval,
  DashboardSummary,
  Finding,
  FindingStatus,
  ReviewBrief,
} from "../types";
import "./VulnFlowShell.css";

export interface VulnFlowShellProps {
  summary: DashboardSummary | null;
  findings: Finding[];
  activities: ActivityEvent[];
  approvals: Approval[];
  loading: boolean;
  error: string | null;
  onRefresh: () => void | Promise<void>;
  onImportFile: (file: File) => void | Promise<void>;
  onSelectFinding: (id: string) => void;
  onAnalyzeFinding: (id: string) => void;
  reviewBrief: ReviewBrief | null;
  analysisLoading: boolean;
  onTransition: (findingId: string, status: FindingStatus, reason: string) => void | Promise<void>;
  onCreateApproval: (findingId: string, action: string) => void | Promise<void>;
  onDecideApproval: (approvalId: string, decision: "approved" | "rejected", reason: string) => void | Promise<void>;
}

type View = "overview" | "findings" | "investigations" | "remediation" | "approvals" | "agents" | "audit";

const NAV: { id: View; label: string; mark: string }[] = [
  { id: "overview", label: "Overview", mark: "OV" },
  { id: "findings", label: "Findings", mark: "FD" },
  { id: "investigations", label: "Investigations", mark: "IN" },
  { id: "remediation", label: "Remediation", mark: "RM" },
  { id: "approvals", label: "Approvals", mark: "AP" },
  { id: "agents", label: "Agent Network", mark: "AG" },
  { id: "audit", label: "Audit", mark: "AU" },
];

const STATES: { id: FindingStatus; label: string }[] = [
  { id: "reported", label: "Reported" },
  { id: "investigating", label: "Investigating" },
  { id: "planned", label: "Planned" },
  { id: "patching", label: "Patching" },
  { id: "verifying", label: "Verifying" },
  { id: "resolved", label: "Resolved" },
  { id: "rejected", label: "Rejected" },
];

const ACTIONS = [
  { id: "propose_remediation", label: "Propose remediation" },
  { id: "change_finding_state", label: "Change finding state" },
  { id: "export_evidence", label: "Export evidence" },
];

const PAGE_META: Record<View, { eyebrow: string; title: string; description: string }> = {
  overview: { eyebrow: "Workspace", title: "Overview", description: "A local view of imported findings and their review history." },
  findings: { eyebrow: "Review queue", title: "Findings", description: "Imported records with their current lifecycle state." },
  investigations: { eyebrow: "Evidence review", title: "Investigations", description: "Inspect recorded evidence and provenance for a finding." },
  remediation: { eyebrow: "Change workflow", title: "Remediation", description: "Track planned work and approval requests. No patches are executed here." },
  approvals: { eyebrow: "Human review", title: "Approvals", description: "Review action proposals and record a decision." },
  agents: { eyebrow: "Activity", title: "Agent Network", description: "Persisted agent activity only; live Switch presence is not connected." },
  audit: { eyebrow: "History", title: "Audit", description: "Application events recorded in the local database." },
};

function dateLabel(value?: string): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not recorded" : date.toLocaleString();
}

function prettyState(value: string): string {
  return value.split("_").join(" ");
}

function ActivityRows({ events, empty = "No activity has been recorded." }: { events: ActivityEvent[]; empty?: string }) {
  if (!events.length) return <p className="vf-empty">{empty}</p>;
  return <ol className="vf-activity-list">
    {events.map((event) => <li className="vf-activity" key={event.id}>
      <span className="vf-activity__dot" aria-hidden="true" />
      <div className="vf-activity__body">
        <div className="vf-activity__top"><strong>{event.action}</strong><time>{dateLabel(event.created_at)}</time></div>
        <p>{event.outcome || "Recorded"}{event.target ? ` · ${event.target}` : ""}</p>
        {event.details && Object.keys(event.details).length > 0 && <details>
          <summary>Recorded details</summary>
          <pre>{JSON.stringify(event.details, null, 2)}</pre>
        </details>}
        <small>Actor: {event.actor || "Not recorded"}</small>
      </div>
    </li>)}
  </ol>;
}

function FindingBadge({ finding }: { finding: Finding }) {
  return <>
    <span className={`vf-severity vf-severity--${finding.severity}`}>{finding.severity}</span>
    <span className="vf-state">{prettyState(finding.status)}</span>
    {finding.synthetic && <span className="vf-synthetic">Synthetic demo</span>}
  </>;
}

function FindingRows({
  findings,
  selectedId,
  onSelect,
}: {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (finding: Finding) => void;
}) {
  if (!findings.length) return <div className="vf-empty-panel"><span className="vf-empty-icon">—</span><h3>No findings here</h3><p>Import a SARIF 2.1.0 or VulnFlow JSON v1 report to populate this view.</p></div>;
  return <div className="vf-finding-list">
    {findings.map((finding) => <button
      type="button"
      className={`vf-finding-row${selectedId === finding.id ? " is-selected" : ""}`}
      key={finding.id}
      aria-pressed={selectedId === finding.id}
      onClick={() => onSelect(finding)}
    >
      <FindingBadge finding={finding} />
      <span className="vf-finding-row__main"><strong>{finding.title}</strong><small>{finding.rule_id || "Rule not recorded"} · {finding.resource || "Resource not recorded"}</small></span>
      <span className="vf-finding-row__date">{dateLabel(finding.updated_at)}</span>
    </button>)}
  </div>;
}

function Metric({ label, value, note }: { label: string; value: number | undefined; note?: string }) {
  return <article className="vf-metric">
    <span>{label}</span><strong>{value ?? 0}</strong>{note && <small>{note}</small>}
  </article>;
}

function SectionHeading({ eyebrow, title, aside }: { eyebrow?: string; title: string; aside?: ReactNode }) {
  return <div className="vf-section-heading"><div>{eyebrow && <p className="vf-eyebrow">{eyebrow}</p>}<h2>{title}</h2></div>{aside}</div>;
}

export function VulnFlowShell({
  summary,
  findings,
  activities,
  approvals,
  loading,
  error,
  onRefresh,
  onImportFile,
  onSelectFinding,
  onAnalyzeFinding,
  reviewBrief,
  analysisLoading,
  onTransition,
  onCreateApproval,
  onDecideApproval,
}: VulnFlowShellProps) {
  const [view, setView] = useState<View>("overview");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [findingFilter, setFindingFilter] = useState("all");
  const [nextState, setNextState] = useState<FindingStatus>("investigating");
  const [transitionReason, setTransitionReason] = useState("");
  const [approvalAction, setApprovalAction] = useState(ACTIONS[0].id);
  const [approvalReasons, setApprovalReasons] = useState<Record<string, string>>({});

  const normalizedSearch = search.trim().toLocaleLowerCase();
  const filteredFindings = useMemo(() => findings.filter((finding) => {
    const matchesSearch = !normalizedSearch || [finding.title, finding.rule_id, finding.resource, finding.description]
      .some((value) => value?.toLocaleLowerCase().includes(normalizedSearch));
    const matchesFilter = findingFilter === "all" || finding.status === findingFilter || finding.severity === findingFilter;
    return matchesSearch && matchesFilter;
  }), [findings, findingFilter, normalizedSearch]);
  const selected = findings.find((finding) => finding.id === selectedId) ?? filteredFindings[0] ?? findings[0] ?? null;
  const currentPage = PAGE_META[view];
  const activeStages = ["reported", "investigating", "planned", "patching", "verifying"] as const;
  const needsReview = activeStages.reduce((total, state) => total + (summary?.by_status[state] ?? 0), 0);
  const agentEvents = activities.filter((event) => event.action.startsWith("agent_activity:"));
  const relatedEvents = selected ? activities.filter((event) => event.target.includes(selected.id)) : [];
  const relatedApprovals = selected ? approvals.filter((approval) => approval.target === selected.id || approval.parameters.finding_id === selected.id) : [];

  const selectFinding = (finding: Finding) => {
    setSelectedId(finding.id);
    onSelectFinding(finding.id);
  };

  const handleImport = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    if (file) void onImportFile(file);
    event.currentTarget.value = "";
  };

  const transition = () => {
    if (!selected || !transitionReason.trim()) return;
    void onTransition(selected.id, nextState, transitionReason.trim());
    setTransitionReason("");
  };

  const requestApproval = (finding: Finding) => void onCreateApproval(finding.id, approvalAction);

  return <div className="vf-shell">
    <aside className="vf-sidebar" aria-label="Primary navigation">
      <div className="vf-brand"><span className="vf-brand__mark">V</span><span><strong>VulnFlow</strong><small>Local security workspace</small></span></div>
      <p className="vf-nav-label">Workspace</p>
      <nav className="vf-nav">
        {NAV.map((item) => <button key={item.id} type="button" className={`vf-nav__item${view === item.id ? " is-active" : ""}`}
          aria-current={view === item.id ? "page" : undefined} onClick={() => setView(item.id)}>
          <span className="vf-nav__mark">{item.mark}</span><span>{item.label}</span>
          {item.id === "approvals" && (summary?.pending_approvals ?? 0) > 0 && <span className="vf-nav__count">{summary?.pending_approvals}</span>}
        </button>)}
      </nav>
      <div className="vf-sidebar__bottom"><span className="vf-local-dot" />Local workspace <span className="vf-sidebar__version">v0.1</span></div>
    </aside>

    <main className="vf-main">
      <header className="vf-commandbar">
        <label className="vf-search"><span aria-hidden="true">⌕</span><input aria-label="Search findings" placeholder="Search findings, rules, resources..." value={search} onChange={(event) => setSearch(event.target.value)} /></label>
        <div className="vf-commandbar__actions">
          <span className="vf-local-label"><span className="vf-local-dot" />LOCAL ONLY</span>
          <label className="vf-button vf-button--secondary" htmlFor="vf-import-file">Import report</label>
          <input id="vf-import-file" className="vf-visually-hidden" type="file" accept=".sarif,.json,application/json" onChange={handleImport} />
          <button className="vf-button vf-button--primary" type="button" onClick={() => void onRefresh()} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</button>
        </div>
      </header>

      <div className="vf-content">
        <header className="vf-page-heading"><div><p className="vf-eyebrow">{currentPage.eyebrow}</p><h1>{currentPage.title}</h1><p>{currentPage.description}</p></div>
          <div className="vf-page-heading__meta"><span>{summary?.real_total ?? 0} real records</span><span>{summary?.synthetic_total ?? 0} synthetic demos</span></div>
        </header>

        {error && <div className="vf-alert" role="alert"><strong>Action needs attention</strong><span>{error}</span></div>}
        {loading && !summary && <div className="vf-loading" role="status">Loading local workspace...</div>}

        {view === "overview" && <>
          <section className="vf-metric-grid" aria-label="Workspace summary">
            <Metric label="All findings" value={summary?.total} note="Includes synthetic demos" />
            <Metric label="Real findings" value={summary?.real_total} note="From imported reports" />
            <Metric label="Synthetic demos" value={summary?.synthetic_total} note="Clearly labeled examples" />
            <Metric label="Active workflow" value={summary?.active} note={`${needsReview} awaiting resolution`} />
            <Metric label="Pending approvals" value={summary?.pending_approvals} note="Human decisions required" />
          </section>

          <div className="vf-overview-grid">
            <section className="vf-card vf-card--wide">
              <SectionHeading eyebrow="Triage" title="Findings by severity" aside={<button type="button" className="vf-text-button" onClick={() => setView("findings")}>View findings →</button>} />
              <div className="vf-severity-chart">
                {(["critical", "high", "medium", "low", "info", "unknown"] as const).map((severity) => {
                  const value = summary?.by_severity[severity] ?? 0;
                  const max = Math.max(1, ...Object.values(summary?.by_severity ?? {}));
                  return <div className="vf-chart-row" key={severity}><span className={`vf-severity vf-severity--${severity}`}>{severity}</span><span className="vf-chart-track"><span className={`vf-chart-bar vf-chart-bar--${severity}`} style={{ width: `${(value / max) * 100}%` }} /></span><strong>{value}</strong></div>;
                })}
              </div>
            </section>
            <section className="vf-card">
              <SectionHeading eyebrow="Workflow" title="Lifecycle" />
              <div className="vf-lifecycle-list">{STATES.map((state) => <button type="button" key={state.id} onClick={() => { setFindingFilter(state.id); setView("findings"); }}><span>{state.label}</span><strong>{summary?.by_status[state.id] ?? 0}</strong></button>)}</div>
            </section>
          </div>

          <section className="vf-card"><SectionHeading eyebrow="Latest events" title="Recent activity" aside={<button type="button" className="vf-text-button" onClick={() => setView("audit")}>Open audit →</button>} />
            <ActivityRows events={activities.slice(0, 5)} empty="No imports, transitions, approvals, or agent events have been recorded." />
          </section>
        </>}

        {view === "findings" && <section className="vf-card">
          <SectionHeading eyebrow="Imported records" title="Finding queue" aside={<label className="vf-filter">Filter<select value={findingFilter} onChange={(event) => setFindingFilter(event.target.value)}><option value="all">All severities and states</option><optgroup label="Severity"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></optgroup><optgroup label="Lifecycle">{STATES.map((state) => <option key={state.id} value={state.id}>{state.label}</option>)}</optgroup></select></label>} />
          <FindingRows findings={filteredFindings} selectedId={selected?.id ?? null} onSelect={selectFinding} />
        </section>}

        {view === "investigations" && <div className="vf-investigation-grid">
          <section className="vf-card"><SectionHeading eyebrow="Review queue" title="Select a finding" /><FindingRows findings={filteredFindings} selectedId={selected?.id ?? null} onSelect={selectFinding} /></section>
          <section className="vf-card vf-investigation-detail">
            {selected ? <>
              <div className="vf-detail-heading"><div><p className="vf-eyebrow">Finding investigation</p><h2>{selected.title}</h2></div><FindingBadge finding={selected} /></div>
              <div className="vf-detail-grid"><Info label="Rule" value={selected.rule_id || "Not recorded"} /><Info label="Resource" value={selected.resource || "Not recorded"} /><Info label="Created" value={dateLabel(selected.created_at)} /><Info label="Updated" value={dateLabel(selected.updated_at)} /><Info label="Dedup fingerprint" value={selected.fingerprint || "Not recorded"} /></div>
              <section className="vf-subsection vf-analysis-panel">
                <div className="vf-section-heading"><div><p className="vf-eyebrow">Evidence-grounded review</p><h2>Investigation brief</h2></div><button type="button" className="vf-button vf-button--primary" disabled={analysisLoading} onClick={() => onAnalyzeFinding(selected.id)}>{analysisLoading ? "Preparing..." : "Generate review brief"}</button></div>
                {reviewBrief?.finding_id === selected.id ? <>
                  <p className="vf-analysis-summary">{reviewBrief.summary}</p>
                  <div className="vf-detail-grid"><Info label="Review status" value={reviewBrief.review_status} /><Info label="Verification" value={reviewBrief.verification_claim} /><Info label="Observations" value={String(reviewBrief.observations)} /><Info label="Source reports" value={String(reviewBrief.source_count)} /></div>
                  <div className="vf-analysis-columns">
                    <div><strong>Evidence gaps</strong>{reviewBrief.gaps.length ? <ul>{reviewBrief.gaps.map((gap) => <li key={gap}>{gap}</li>)}</ul> : <p>No obvious metadata gaps detected.</p>}</div>
                    <div><strong>Recommended checks</strong><ul>{reviewBrief.recommended_checks.map((check) => <li key={check}>{check}</li>)}</ul></div>
                  </div>
                  <p className="vf-analysis-limit">{reviewBrief.limitations.join(" ")}</p>
                </> : <p className="vf-empty-inline">Generate a deterministic brief from the imported observations, locations and evidence. No target is contacted and no vulnerability is independently verified.</p>}
              </section>
              <div className="vf-note"><strong>Severity reasoning</strong><p>Not recorded by the imported report or current API.</p></div>
              <div className="vf-note"><strong>Agent assessments and disagreements</strong><p>Not recorded. This workspace does not synthesize reviewer opinions.</p></div>
              <section className="vf-subsection"><SectionHeading title="Recorded evidence" />
                {selected.evidence.length ? <div className="vf-evidence-list">{selected.evidence.map((evidence) => <article className="vf-evidence" key={evidence.id}><span>{evidence.kind}</span>{evidence.uri && <code>{evidence.uri}</code>}<pre>{evidence.excerpt || "Evidence locator recorded; no excerpt supplied."}</pre><small>Content hash: {evidence.source_hash || "Not recorded"}</small></article>)}</div> : <p className="vf-empty-inline">No evidence attached to this finding.</p>}
              </section>
              <section className="vf-subsection"><SectionHeading title="Provenance" />
                {selected.observations.length ? <div className="vf-provenance-list">{selected.observations.map((observation) => <article className="vf-provenance" key={observation.id}><strong>{observation.source_name || "Imported report"}</strong><span>{observation.tool_name || "Tool not recorded"}{observation.tool_version ? ` · ${observation.tool_version}` : ""}</span><small>{dateLabel(observation.imported_at)} · SHA-256 {observation.source_hash || "Not recorded"}</small></article>)}</div> : <p className="vf-empty-inline">No import provenance is recorded.</p>}
              </section>
              <section className="vf-subsection"><SectionHeading title="Investigation history" />
                <ActivityRows events={relatedEvents} empty="No activity is linked to this finding." />
              </section>
              <section className="vf-subsection"><SectionHeading title="Lifecycle update" />
                <div className="vf-form-row"><label>Next state<select value={nextState} onChange={(event) => setNextState(event.target.value as FindingStatus)}>{STATES.map((state) => <option key={state.id} value={state.id}>{state.label}</option>)}</select></label><label>Reason<input value={transitionReason} onChange={(event) => setTransitionReason(event.target.value)} placeholder="Required for the audit record" /></label><button type="button" className="vf-button vf-button--primary" disabled={!transitionReason.trim()} onClick={transition}>Save state</button></div>
              </section>
              <section className="vf-subsection"><SectionHeading title="Patch history" /><p className="vf-empty-inline">Not recorded. VulnFlow does not execute patches or track repository changes.</p></section>
              {relatedApprovals.length > 0 && <section className="vf-subsection"><SectionHeading title="Related approvals" /><ApprovalRows approvals={relatedApprovals} approvalReasons={approvalReasons} activities={activities} setApprovalReasons={setApprovalReasons} onDecideApproval={onDecideApproval} /> </section>}
            </> : <div className="vf-empty-panel"><h3>No finding selected</h3><p>Import a report to begin an evidence review.</p></div>}
          </section>
        </div>}

        {view === "remediation" && <>
          <section className="vf-card"><SectionHeading eyebrow="Planned work" title="Remediation queue" />
            <FindingRows findings={findings.filter((finding) => ["planned", "patching", "verifying", "resolved"].includes(finding.status))} selectedId={selected?.id ?? null} onSelect={(finding) => { selectFinding(finding); setView("investigations"); }} />
            <p className="vf-empty-inline">Patch contents and repository change history are not recorded by the current API. Approval requests track decisions only; they do not apply changes.</p>
          </section>
          <section className="vf-card"><SectionHeading eyebrow="Proposals" title="Remediation approvals" />
            <ApprovalRows approvals={approvals.filter((approval) => approval.action === "propose_remediation")} approvalReasons={approvalReasons} activities={activities} setApprovalReasons={setApprovalReasons} onDecideApproval={onDecideApproval} empty="No remediation proposals have been recorded." />
          </section>
          {selected && <section className="vf-card"><SectionHeading eyebrow="Workflow-only request" title="Request a human decision" />
            <div className="vf-form-row"><span className="vf-form-note">Proposed for <strong>{selected.title}</strong></span><label>Action<select value={approvalAction} onChange={(event) => setApprovalAction(event.target.value)}>{ACTIONS.map((action) => <option key={action.id} value={action.id}>{action.label}</option>)}</select></label><button type="button" className="vf-button vf-button--secondary" onClick={() => requestApproval(selected)}>Create approval request</button></div>
          </section>}
        </>}

        {view === "approvals" && <section className="vf-card"><SectionHeading eyebrow="Decision queue" title="Approvals" aside={<span className="vf-soft-tag">No action execution</span>} />
          <ApprovalRows approvals={approvals} approvalReasons={approvalReasons} activities={activities} setApprovalReasons={setApprovalReasons} onDecideApproval={onDecideApproval} empty="No approval requests have been recorded." />
        </section>}

        {view === "agents" && <>
          <section className="vf-network-banner"><span className="vf-network-icon">AG</span><div><strong>Live Switch connectivity is not integrated</strong><p>This API has no Switch roster, session, or live agent status endpoint. No online/offline status is inferred.</p></div><span className="vf-soft-tag">Unavailable</span></section>
          <section className="vf-card"><SectionHeading eyebrow="Persisted events" title="Agent activity" />
            <p className="vf-muted-copy">Only records stored through the local agent activity API are shown here.</p>
            <ActivityRows events={agentEvents} empty="No persisted agent-activity events are recorded." />
          </section>
        </>}

        {view === "audit" && <section className="vf-card"><SectionHeading eyebrow="Append-only in app" title="Audit trail" aside={<span className="vf-soft-tag">Local database</span>} />
          <p className="vf-muted-copy">Events are appended with application state changes. A local database owner can still modify the SQLite file.</p>
          <ActivityRows events={activities} empty="No audit events are recorded." />
        </section>}

        <footer className="vf-footer"><span>VulnFlow · Local-first review</span><span>Imported data is untrusted · No scanning or patch execution</span></footer>
      </div>
    </main>
  </div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="vf-info"><span>{label}</span><strong>{value}</strong></div>;
}

function ApprovalRows({
  approvals,
  approvalReasons,
  activities,
  setApprovalReasons,
  onDecideApproval,
  empty = "No approval requests.",
}: {
  approvals: Approval[];
  activities: ActivityEvent[];
  approvalReasons: Record<string, string>;
  setApprovalReasons: (update: (current: Record<string, string>) => Record<string, string>) => void;
  onDecideApproval: VulnFlowShellProps["onDecideApproval"];
  empty?: string;
}) {
  if (!approvals.length) return <div className="vf-empty-panel"><h3>No approvals</h3><p>{empty}</p></div>;
  return <div className="vf-approval-list">{approvals.map((approval) => {
    const reason = approvalReasons[approval.id] ?? "";
    const decisionEvent = [...activities].reverse().find((event) =>
      (event.target === approval.id || event.target === `approval:${approval.id}` || event.target.endsWith(`:${approval.id}`))
      && /^approval\.(approved|rejected|expired)$/.test(event.action));
    const recordedReason = approval.reason || (typeof decisionEvent?.details.reason === "string" ? decisionEvent.details.reason : "Not recorded");
    return <article className="vf-approval-card" key={approval.id}>
      <div className="vf-approval-card__top"><div><p className="vf-eyebrow">{approval.action}</p><h3>{approval.target}</h3></div><span className={`vf-state vf-state--${approval.status}`}>{prettyState(approval.status)}</span></div>
      <div className="vf-approval-facts"><Info label="Requester" value={approval.requester || "Not recorded"} /><Info label="Approver" value={approval.approver || "Not decided"} /><Info label="Created" value={dateLabel(approval.created_at)} /><Info label="Expires" value={dateLabel(approval.expires_at)} /><Info label="Decision reason" value={recordedReason} /></div>
      <details className="vf-parameters"><summary>Exact parameters</summary><pre>{JSON.stringify(approval.parameters, null, 2)}</pre></details>
      {approval.status === "pending" && <div className="vf-decision"><label>Decision reason<input value={reason} onChange={(event) => setApprovalReasons((current) => ({ ...current, [approval.id]: event.target.value }))} placeholder="Required to record a decision" /></label><button type="button" className="vf-button vf-button--primary" disabled={!reason.trim()} onClick={() => void onDecideApproval(approval.id, "approved", reason.trim())}>Approve</button><button type="button" className="vf-button vf-button--danger" disabled={!reason.trim()} onClick={() => void onDecideApproval(approval.id, "rejected", reason.trim())}>Reject</button></div>}
      <p className="vf-approval-disclaimer">Decision tracking only. VulnFlow does not execute this action.</p>
    </article>;
  })}</div>;
}



