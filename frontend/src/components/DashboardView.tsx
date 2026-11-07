import { useMemo, useState, type ChangeEvent, type ReactNode } from "react";
import type { ActivityEvent, Approval, DashboardSummary, Finding, FindingStatus } from "../types";
import "./DashboardView.css";

export interface DashboardViewProps {
  summary: DashboardSummary | null; findings: Finding[]; activities: ActivityEvent[]; approvals: Approval[];
  loading: boolean; error: string | null; onRefresh: () => void | Promise<void>;
  onImportFile: (file: File) => void | Promise<void>; onSelectFinding: (id: string) => void;
  onTransition: (findingId: string, status: FindingStatus, reason: string) => void | Promise<void>;
  onCreateApproval: (findingId: string, action: string) => void | Promise<void>;
  onDecideApproval: (approvalId: string, decision: "approved" | "rejected", reason: string) => void | Promise<void>;
}
type ViewId = "overview" | "findings" | "investigations" | "remediation" | "approvals" | "agents" | "audit";
const NAV: { id: ViewId; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "O" }, { id: "findings", label: "Findings", icon: "F" },
  { id: "investigations", label: "Investigations", icon: "I" }, { id: "remediation", label: "Remediation", icon: "R" },
  { id: "approvals", label: "Approvals", icon: "A" }, { id: "agents", label: "Agent Network", icon: "N" },
  { id: "audit", label: "Audit", icon: "H" },
];
const STATES: FindingStatus[] = ["reported", "investigating", "planned", "patching", "verifying", "resolved", "rejected"];
const ACTIONS = [["propose_remediation", "Propose remediation"], ["change_finding_state", "Change finding state"], ["export_evidence", "Export evidence"]] as const;
const nice = (value: string) => value.replaceAll("_", " ");
const time = (value: string | number | null | undefined) => {
  if (value == null) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not recorded" : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
};
const age = (value: string) => {
  const n = new Date(value).getTime();
  if (!Number.isFinite(n)) return "Time not recorded";
  const delta = Date.now() - n;
  return delta < 60000 ? "Just now" : delta < 3600000 ? Math.floor(delta / 60000) + "m ago" : delta < 86400000 ? Math.floor(delta / 3600000) + "h ago" : new Date(value).toLocaleDateString();
};
const score: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };

export function DashboardView(props: DashboardViewProps) {
  const { summary, findings, activities, approvals, loading, error, onRefresh, onImportFile, onSelectFinding, onTransition, onCreateApproval, onDecideApproval } = props;
  const [view, setView] = useState<ViewId>("overview");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [reason, setReason] = useState("");
  const [action, setAction] = useState<string>(ACTIONS[0][0]);
  const [decisionReasons, setDecisionReasons] = useState<Record<string, string>>({});
  const selected = findings.find(f => f.id === selectedId) ?? null;
  const filtered = useMemo(() => findings.filter(f => {
    const text = [f.title, f.rule_id ?? "", f.resource ?? "", f.description ?? "", ...f.observations.map(o => o.source_name)].join(" ").toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (severity === "all" || f.severity === severity) && (status === "all" || f.status === status);
  }), [findings, query, severity, status]);
  const pending = approvals.filter(a => a.status === "pending");
  const activeFindings = [...findings].filter(f => !["resolved", "rejected"].includes(f.status)).sort((a, b) => (score[b.severity] ?? 0) - (score[a.severity] ?? 0)).slice(0, 5);
  const topSeverity = Math.max(1, ...Object.values(summary?.by_severity ?? {}));
  const topState = Math.max(1, ...Object.values(summary?.by_status ?? {}));

  function pick(f: Finding, next: ViewId = "investigations") { setSelectedId(f.id); onSelectFinding(f.id); setView(next); }
  function importFile(e: ChangeEvent<HTMLInputElement>) { const f = e.currentTarget.files?.[0]; if (f) void onImportFile(f); e.currentTarget.value = ""; }
  function decide(a: Approval, decision: "approved" | "rejected") { const text = decisionReasons[a.id]?.trim(); if (text) void onDecideApproval(a.id, decision, text); }
  function saveState() { const select = document.getElementById("vf-next-state") as HTMLSelectElement | null; if (selected && select && reason.trim()) void onTransition(selected.id, select.value as FindingStatus, reason.trim()); }

  if (loading && !summary) return <div className="vf-loading" role="status"><span className="vf-mark">V</span><p>Opening local workspace</p><div /><div /></div>;
  return <div className="vf-app">
    <aside className="vf-sidebar">
      <div className="vf-brand"><span className="vf-mark">V</span><div><b>VulnFlow</b><small>SECURITY INTELLIGENCE</small></div></div>
      <small className="vf-nav-caption">WORKSPACE</small>
      <nav aria-label="Workspace navigation">{NAV.map(n => <button key={n.id} className={"vf-nav-item" + (view === n.id ? " active" : "")} aria-current={view === n.id ? "page" : undefined} onClick={() => setView(n.id)}><i>{n.icon}</i><span>{n.label}</span>{n.id === "approvals" && pending.length > 0 && <em>{pending.length}</em>}</button>)}</nav>
      <div className="vf-sidebar-foot"><i /><div><b>Local workspace</b><small>Single-user mode</small></div></div>
    </aside>
    <main className="vf-main">
      <header className="vf-commandbar"><div className="vf-crumb"><b>VULNFLOW</b><span>/</span>{NAV.find(n => n.id === view)?.label}</div>
        <div className="vf-tools"><label className="vf-search"><span>Q</span><input aria-label="Search findings" placeholder="Search findings..." value={query} onChange={e => setQuery(e.target.value)} /><kbd>CTRL K</kbd></label>
          <label className="vf-import">+ Import report<input type="file" accept=".sarif,.json,application/json" onChange={importFile} /></label><span className="vf-availability"><i /> Agent data <b>local only</b></span></div>
      </header>
      {error && <div className="vf-alert" role="alert"><span>{error}</span><button onClick={() => void onRefresh()}>Retry</button></div>}
      {loading && summary && <div className="vf-sync" role="status">Refreshing workspace...</div>}
      <div className="vf-page">
        {view === "overview" && <section>
          <PageTitle eyebrow="SECURITY INTELLIGENCE" title="Overview" subtitle="A measured view of exposure, investigation, and response." action={<button className="vf-btn vf-btn-quiet" disabled={loading} onClick={() => void onRefresh()}>Refresh</button>} />
          <div className="vf-metrics">
            <Metric title="Open exposure" value={summary?.active ?? 0} detail="Active findings in workflow" />
            <Metric title="Critical + high" value={(summary?.by_severity.critical ?? 0) + (summary?.by_severity.high ?? 0)} detail="Imported severity classifications" tone="red" />
            <Metric title="Awaiting triage" value={summary?.by_status.reported ?? 0} detail="Reported, not investigated" />
            <Metric title="Human approvals" value={pending.length} detail="Decisions awaiting review" tone="gold" />
          </div>
          <div className="vf-grid">
            <section className="vf-card"><Section eyebrow="EXPOSURE PROFILE" title="Severity distribution" detail="Real findings only" />
              {summary?.real_total === 0 && <p className="vf-note">No real assessments yet. Synthetic demos are excluded.</p>}
              <div className="vf-bars">{(["critical", "high", "medium", "low", "info", "unknown"] as const).map(s => { const n = summary?.by_severity[s] ?? 0; return <div className="vf-bar" key={s}><span className={"vf-sev vf-sev-" + s}>{s}</span><div><i style={{ width: (n ? Math.max(3, n / topSeverity * 100) : 0) + "%" }} /></div><b>{n}</b></div>; })}</div>
            </section>
            <section className="vf-card"><Section eyebrow="WORKFLOW" title="Finding lifecycle" detail="Current state across findings" />
              <div className="vf-states">{STATES.map(s => { const n = summary?.by_status[s] ?? 0; return <button key={s} onClick={() => { setStatus(s); setView("findings"); }}><i className={"vf-state-dot dot-" + s} /><span>{nice(s)}</span><div><i style={{ width: (n ? Math.max(4, n / topState * 100) : 0) + "%" }} /></div><b>{n}</b></button>; })}</div>
            </section>
          </div>
          <div className="vf-grid vf-grid-lower">
            <section className="vf-card"><Section eyebrow="PRIORITIZED QUEUE" title="Priority findings" detail="Highest severity among active findings" action={<button className="vf-link" onClick={() => setView("findings")}>All findings -&gt;</button>} />
              {activeFindings.length ? <div className="vf-priority">{activeFindings.map(f => <FindingRow key={f.id} item={f} open={() => pick(f)} />)}</div> : <Empty title="No active findings" text="Import a SARIF or VulnFlow JSON report to begin." />}
            </section>
            <section className="vf-card"><Section eyebrow="AUDIT TRAIL" title="Recent activity" detail="Persisted workspace events" action={<button className="vf-link" onClick={() => setView("audit")}>View audit -&gt;</button>} /><Activity items={activities.slice(0, 5)} empty="No activity recorded" text="Imports and workflow events appear here." /></section>
          </div>
          <p className="vf-footnote">i &nbsp; Synthetic demo findings are marked and excluded from real risk totals.</p>
        </section>}

        {view === "findings" && <section><PageTitle eyebrow="TRIAGE WORKSPACE" title="Findings" subtitle={(summary?.real_total ?? 0) + " real findings  /  " + (summary?.synthetic_total ?? 0) + " synthetic demonstrations"} />
          <section className="vf-card vf-table-card"><div className="vf-filterbar"><b>{filtered.length} records in view</b><div><label>Severity<select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{["critical", "high", "medium", "low", "info", "unknown"].map(x => <option key={x}>{x}</option>)}</select></label><label>Lifecycle<select value={status} onChange={e => setStatus(e.target.value)}><option value="all">All states</option>{STATES.map(x => <option key={x} value={x}>{nice(x)}</option>)}</select></label></div></div>
            {!filtered.length ? <Empty title={findings.length ? "No matching findings" : "Your queue is clear"} text={findings.length ? "Adjust search or filters." : "Import a structured report to add findings."} /> :
            <div className="vf-table-scroll"><table><thead><tr><th>SEVERITY</th><th>FINDING</th><th>RESOURCE</th><th>STATE</th><th>SOURCE</th><th /></tr></thead><tbody>{filtered.map(f => <tr key={f.id} tabIndex={0} onClick={() => pick(f)} onKeyDown={e => { if (e.key === "Enter") pick(f); }}><td><Severity value={f.severity} /></td><td><b>{f.title}</b><small>{f.rule_id || "Imported finding"}</small></td><td>{f.resource || "Not recorded"}</td><td><State value={f.status} /></td><td>{f.synthetic ? <span className="vf-demo">DEMO</span> : f.observations[0]?.source_name || "Imported"}</td><td>-&gt;</td></tr>)}</tbody></table></div>}
          </section>
        </section>}

        {view === "investigations" && <section><PageTitle eyebrow="EVIDENCE REVIEW" title="Investigation" subtitle="Evidence and provenance attached to an imported finding." />
          {!selected ? <section className="vf-card"><Empty title="Select a finding to investigate" text="Choose a finding from the Findings view." action={<button className="vf-btn" onClick={() => setView("findings")}>Open findings</button>} /></section> : <Investigation finding={selected} activities={activities} approvals={approvals} findings={findings} />}
        </section>}

        {view === "remediation" && <section><PageTitle eyebrow="CONTROLLED RESPONSE" title="Remediation" subtitle="Track a proposal and decision. This workspace does not apply patches." />
          {!selected ? <section className="vf-card"><Empty title="Choose a finding first" text="Remediation proposals are tied to a specific finding." action={<button className="vf-btn" onClick={() => setView("findings")}>Choose finding</button>} /></section> :
          <div className="vf-grid"><section className="vf-card"><Section eyebrow="SELECTED FINDING" title={selected.title} detail={selected.resource || "Affected resource not recorded"} /><div className="vf-facts"><Fact name="Severity"><Severity value={selected.severity} /></Fact><Fact name="State"><State value={selected.status} /></Fact><Fact name="Rule"><span>{selected.rule_id || "Not recorded"}</span></Fact></div>
            <div className="vf-form"><label htmlFor="vf-next-state">Advance workflow state</label><select id="vf-next-state" defaultValue={selected.status}>{STATES.map(s => <option key={s} value={s}>{nice(s)}</option>)}</select><input value={reason} onChange={e => setReason(e.target.value)} placeholder="Required: explain the state change" /><button className="vf-btn" disabled={!reason.trim()} onClick={saveState}>Record state</button></div>
            <div className="vf-form"><label htmlFor="vf-action">Request a human decision</label><select id="vf-action" value={action} onChange={e => setAction(e.target.value)}>{ACTIONS.map(([id, name]) => <option key={id} value={id}>{name} ({id})</option>)}</select><button className="vf-btn vf-btn-primary" onClick={() => void onCreateApproval(selected.id, action)}>Create approval record</button></div>
          </section><section className="vf-card"><Section eyebrow="BOUNDARY" title="No patch execution" detail="Approvals are records only." /><p className="vf-note">Proposal actor: <b>vulnflow-remediation</b>. Human approver: <b>local-operator</b>. Approval does not modify source files or run commands.</p><ApprovalList items={approvals.filter(a => a.target === selected.id)} findings={findings} reasons={{}} setReasons={() => undefined} decide={() => undefined} /><Empty title="Patch contents not recorded" text="The current API does not store proposed patches or verification history." /></section></div>}
        </section>}

        {view === "approvals" && <section><PageTitle eyebrow="HUMAN IN THE LOOP" title="Approvals" subtitle="Review the exact request, then record a decision and rationale." action={<span className="vf-pending">{pending.length} pending</span>} /><p className="vf-note">Approval decisions are audit records only. They do not execute a patch or change the repository.</p><ApprovalList items={approvals} findings={findings} reasons={decisionReasons} setReasons={setDecisionReasons} decide={decide} /></section>}

        {view === "agents" && <section><PageTitle eyebrow="COLLABORATION" title="Agent Network" subtitle="Activity recorded by this VulnFlow workspace." />
          <div className="vf-connect"><span>N</span><div><b>Live Switch connection is not integrated</b><p>This API exposes no agent sessions, presence, or room messages. No live agent status is shown.</p></div><small>NOT CONNECTED TO API</small></div>
          <div className="vf-metrics vf-metrics-three"><Metric title="Recorded events" value={activities.length} detail="Persisted in local audit history" /><Metric title="Agent-attributed events" value={activities.filter(a => /agent|vulnflow/i.test(a.actor)).length} detail="Based on recorded actor labels" /><Metric title="Live sessions" value="-" detail="Not provided by this API" /></div>
          <section className="vf-card"><Section eyebrow="RECORDED ONLY" title="Agent-attributed activity" detail="Persisted events, not live room messages" /><Activity items={activities.filter(a => /agent|vulnflow/i.test(a.actor))} empty="No agent events recorded" text="This does not indicate whether agents are online. A Switch event feed is not connected." /></section>
        </section>}

        {view === "audit" && <section><PageTitle eyebrow="PROVENANCE" title="Audit" subtitle="Events persisted by the local VulnFlow API." /><section className="vf-card"><Section eyebrow="APPLICATION LOG" title="Activity history" detail="Not tamper-proof against an owner of the local database." /><Activity items={activities} empty="No audit events recorded" text="Imports, workflow updates, approvals, and posted agent activity appear here." /></section></section>}
      </div>
    </main>
  </div>;
}
function PageTitle({ eyebrow, title, subtitle, action }: { eyebrow: string; title: string; subtitle: string; action?: ReactNode }) { return <div className="vf-title"><div><small>{eyebrow}</small><h1>{title}</h1><p>{subtitle}</p></div>{action}</div>; }
function Metric({ title, value, detail, tone }: { title: string; value: string | number; detail: string; tone?: string }) { return <article className={"vf-metric " + (tone || "")}><span>{title}</span><strong>{value}</strong><small>{detail}</small></article>; }
function Section({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail?: string; action?: ReactNode }) { return <header className="vf-section-title"><div><small>{eyebrow}</small><h2>{title}</h2>{detail && <p>{detail}</p>}</div>{action}</header>; }
function Empty({ title, text, action }: { title: string; text: string; action?: ReactNode }) { return <div className="vf-empty"><i>-</i><b>{title}</b><p>{text}</p>{action}</div>; }
function Severity({ value }: { value: string }) { return <span className={"vf-sev vf-sev-" + value}><i />{value}</span>; }
function State({ value }: { value: string }) { return <span className={"vf-state state-" + value}>{nice(value)}</span>; }
function FindingRow({ item, open }: { item: Finding; open: () => void }) { return <button className="vf-priority-row" onClick={open}><Severity value={item.severity} /><span><b>{item.title}</b><small>{item.resource || item.rule_id || "Resource not recorded"}</small></span><State value={item.status} />{item.synthetic && <em className="vf-demo">DEMO</em>}</button>; }
function Fact({ name, children }: { name: string; children: ReactNode }) { return <div className="vf-fact"><small>{name}</small><div>{children}</div></div>; }
function Activity({ items, empty, text }: { items: ActivityEvent[]; empty: string; text: string }) { return !items.length ? <Empty title={empty} text={text} /> : <ol className="vf-activity">{items.map(a => <li key={a.id}><i /><div><header><b>{a.action.replaceAll(".", " ").replaceAll("_", " ")}</b><time>{age(a.created_at)}</time></header><p>{a.actor} / {a.outcome}</p><small>{a.target}</small><details><summary>Event details</summary><pre>{JSON.stringify(a.details, null, 2)}</pre></details></div></li>)}</ol>; }
function ApprovalList({ items, findings, reasons, setReasons, decide, readOnly = false }: { items: Approval[]; findings: Finding[]; reasons: Record<string, string>; setReasons: (r: Record<string, string>) => void; decide: (a: Approval, d: "approved" | "rejected") => void; readOnly?: boolean }) {
  if (!items.length) return <Empty title="No approval requests" text="Bounded proposals and decisions will appear here." />;
  return <div className="vf-approval-list">{items.map(a => <article className="vf-approval-card" key={a.id}><header><div><small>REQUEST / {a.id.slice(0, 8)}</small><h3>{a.action}</h3></div><span className={"approval-" + a.status}>{nice(a.status)}</span></header>
    <div className="vf-facts"><Fact name="Finding"><span>{findings.find(f => f.id === a.target)?.title || a.target}</span></Fact><Fact name="Proposed by"><span>{a.requester}</span></Fact><Fact name="Expires"><span>{time(a.expires_at)}</span></Fact></div>
    <details><summary>Exact proposed parameters</summary><pre>{JSON.stringify(a.parameters, null, 2)}</pre><small>Parameter digest / {a.parameter_hash}</small></details>
    {a.status !== "pending" ? <div className="vf-decision"><span>Decision <b>{a.decision || a.status}</b></span><span>Approver <b>{a.approver || "Not recorded"}</b></span><p>Reason: {a.reason || "Not recorded"}</p></div> : readOnly ? <p className="vf-note">Pending decision. Open Approvals to record a human decision.</p> :
      <div className="vf-form"><label htmlFor={"decision-" + a.id}>Decision rationale</label><textarea id={"decision-" + a.id} rows={2} value={reasons[a.id] || ""} onChange={e => setReasons({ ...reasons, [a.id]: e.target.value })} placeholder="Required to record a decision" /><div className="vf-actions"><button className="vf-btn vf-btn-quiet" disabled={!reasons[a.id]?.trim()} onClick={() => decide(a, "rejected")}>Reject request</button><button className="vf-btn vf-btn-primary" disabled={!reasons[a.id]?.trim()} onClick={() => decide(a, "approved")}>Record approval</button></div><small>Recorded as local-operator. This does not run the proposed action.</small></div>}
  </article>)}</div>;
}
function Investigation({ finding, activities, approvals, findings }: { finding: Finding; activities: ActivityEvent[]; approvals: Approval[]; findings: Finding[] }) {
  const history = activities.filter(a => a.target.endsWith(":" + finding.id));
  const related = approvals.filter(a => a.target === finding.id);
  return <div className="vf-investigation"><section className="vf-card"><header className="vf-investigation-heading"><div><small>FINDING / {finding.id.slice(0, 8)}</small><h2>{finding.title}</h2></div>{finding.synthetic && <em className="vf-demo">SYNTHETIC DEMO</em>}</header><p className="vf-description">{finding.description || "No description was included in the imported report."}</p>
    <div className="vf-facts"><Fact name="Severity"><Severity value={finding.severity} /></Fact><Fact name="Lifecycle"><State value={finding.status} /></Fact><Fact name="Affected component"><span>{finding.resource || "Not recorded"}</span></Fact><Fact name="Rule"><span>{finding.rule_id || "Not recorded"}</span></Fact><Fact name="Fingerprint"><code>{finding.fingerprint}</code></Fact><Fact name="Updated"><span>{time(finding.updated_at)}</span></Fact></div>
    <div className="vf-subsection"><Section eyebrow="EVIDENCE" title="Imported evidence" detail="Rendered as inert text; source URIs are not opened." />{finding.evidence.length ? finding.evidence.map(e => <article className="vf-evidence" key={e.id}><header><b>{nice(e.kind)}</b><small>{e.source_hash ? "SHA-256 " + e.source_hash.slice(0, 12) : "No digest"}</small></header>{e.uri && <p>Source URI / {e.uri}</p>}<pre>{e.excerpt || "Evidence excerpt not provided."}</pre></article>) : <Empty title="No evidence attached" text="The source report supplied no evidence." />}</div>
    <div className="vf-subsection"><Section eyebrow="PROVENANCE" title="Source observations" />{finding.observations.length ? finding.observations.map(o => <div className="vf-observation" key={o.id}><b>{o.source_name}</b><span>{o.tool_name || "Tool not recorded"} / {time(o.imported_at)}</span><small>Import {o.import_id.slice(0, 8)} / SHA-256 {o.source_hash.slice(0, 12)}</small></div>) : <Empty title="No provenance observations" text="No source metadata is available." />}</div>
  </section><aside>
    <section className="vf-card"><Section eyebrow="ASSESSMENT" title="Analysis" /><Missing title="Severity reasoning" /><Missing title="Agent assessments" /><Missing title="Disagreements" /></section>
    <section className="vf-card"><Section eyebrow="RESPONSE" title="Remediation" />{related.length ? <ApprovalList items={related} findings={findings} reasons={{}} setReasons={() => undefined} decide={() => undefined} readOnly /> : <Empty title="No proposal recorded" text="No remediation request is attached." />}<Missing title="Patch and verification history" /></section>
    <section className="vf-card"><Section eyebrow="HISTORY" title="Investigation history" /><Activity items={history} empty="No finding-specific history" text="No persisted audit event links to this finding." /></section>
  </aside></div>;
}
function Missing({ title }: { title: string }) { return <div className="vf-missing"><i>-</i><div><b>{title}</b><p>Not recorded by the current API.</p></div></div>; }

