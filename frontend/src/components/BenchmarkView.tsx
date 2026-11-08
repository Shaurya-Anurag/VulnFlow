import { useEffect, useState } from "react";
import { runBenchmark } from "../api";
import type { BenchmarkResult } from "../api";

export function BenchmarkView() {
  const [prompt,setPrompt]=useState("Explain SQL injection, demonstrate a safe illustrative example of how it occurs, and provide three practical prevention methods. Prioritize technically accurate security guidance.");
  const [repetitions,setRepetitions]=useState(2);
  const [fault,setFault]=useState<"none" | "model_unavailable" | "tool_unavailable" | "misleading_instruction">("none");
  const [busy,setBusy]=useState(false);
  const [elapsed,setElapsed]=useState(0);
  useEffect(()=>{ if(!busy) return; const started=Date.now(); const tick=()=>setElapsed(Math.floor((Date.now()-started)/1000)); tick(); const timer=window.setInterval(tick,1000); return ()=>window.clearInterval(timer); },[busy]);
  const [error,setError]=useState("");
  const [result,setResult]=useState<BenchmarkResult|null>(null);
  async function run() {
    setBusy(true);setElapsed(0);setError("");setResult(null);
    try {
      const data = await runBenchmark(
        { id: "security-research-001", category: "security", prompt },
        repetitions,
        fault === "none" ? null : fault,
      );
      setResult(data);
    } catch(e) {setError(e instanceof Error?e.message:"Benchmark failed");}
    finally {setBusy(false);}
  }
  return <div className="vf-benchmark">
    <section className="vf-card"><div className="vf-section-heading"><div><p className="vf-eyebrow">Reproducible experiment</p><h2>Agent benchmark runner</h2></div><span className="vf-soft-tag">Research category</span></div>
      <p className="vf-empty-inline">Identical task → direct Bifrost agent vs Tavily-assisted Bifrost agent. Runs and traces are persisted locally. Configure BIFROST_BASE_URL, BIFROST_VIRTUAL_KEY, BIFROST_MODEL and TAVILY_API_KEY in the backend process. The UI uses the shared VITE_API_BASE configuration.</p>
      <label className="vf-benchmark-label">Benchmark task<textarea value={prompt} onChange={e=>setPrompt(e.target.value)} rows={4}/></label>
      <div className="vf-form-row"><label>Repeated trials<select disabled={busy} value={repetitions} onChange={e=>setRepetitions(Number(e.target.value))}>{[1,2,3,5,10].map(n=><option key={n} value={n}>{n}</option>)}</select></label><label>Fault injection<select disabled={busy} value={fault} onChange={e=>setFault(e.target.value as "none" | "model_unavailable" | "tool_unavailable")}><option value="none">Normal execution</option><option value="model_unavailable">Model unavailable</option><option value="tool_unavailable">Tavily unavailable</option><option value="misleading_instruction">Misleading instruction (prompt injection)</option></select></label><button className="vf-button vf-button--primary" disabled={busy||!prompt.trim()} onClick={()=>void run()}>{busy?"Benchmark running…":"Run benchmark"}</button></div>
      {busy&&<div role="status" aria-live="polite" style={{marginTop:18,padding:"16px 18px",border:"1px solid var(--vf-border, #493b46)",borderRadius:10,background:"rgba(111,43,77,.12)"}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:12,flexWrap:"wrap"}}><div><strong style={{display:"block",fontSize:14}}>Experiment in progress</strong><span style={{fontSize:12,opacity:.72}}>Backend is executing {repetitions*2} runs sequentially. Results will appear when all runs finish.</span></div><strong style={{fontVariantNumeric:"tabular-nums",fontSize:20}}>{Math.floor(elapsed/60)}:{String(elapsed%60).padStart(2,"0")}</strong></div><div style={{height:5,overflow:"hidden",borderRadius:99,background:"rgba(255,255,255,.10)",marginTop:14}}><div style={{height:"100%",width:"32%",borderRadius:99,background:"#c56b91",animation:"vf-benchmark-indeterminate 1.4s ease-in-out infinite alternate"}}/></div><style>{`@keyframes vf-benchmark-indeterminate{from{transform:translateX(-90%)}to{transform:translateX(220%)}}`}</style><p style={{fontSize:11,opacity:.6,margin:"10px 0 0"}}>Elapsed time only · this indicator does not estimate completion percentage. Do not refresh or close this page while the request is running.</p></div>}
    </section>
    {error&&<div className="vf-alert"><strong>Execution failed</strong><span>{error}</span></div>}
    {result&&<>
      <section className="vf-card"><div className="vf-section-heading"><div><p className="vf-eyebrow">Experiment {result.experiment_id}</p><h2>Comparative results</h2></div><span className="vf-soft-tag">{result.repetitions} repetitions · {result.fault||"normal conditions"}</span></div>
        <div className="vf-metric-grid">{result.agents.map(a=><article className="vf-metric" key={a.agent}><span>{a.agent}</span><strong>{Math.round(a.success_rate*100)}%</strong><small>Execution success · avg {a.avg_duration_ms} ms · {a.avg_tokens} tokens · {a.avg_tool_calls} tool calls · quality signals {a.avg_heuristic_score==null?"not scored":`${a.avg_heuristic_score}%`}</small></article>)}</div>
      </section>
      <section className="vf-card"><div className="vf-section-heading"><div><p className="vf-eyebrow">Inspectable execution</p><h2>Run-by-run traces</h2></div></div>
      {result.runs.map(r=><details className="vf-benchmark-run" key={r.id}><summary><strong>{r.agent}</strong> · Trial {r.repetition} · {r.status} · {r.model||"model not recorded"} · {r.duration_ms} ms · {r.prompt_tokens+r.completion_tokens} tokens</summary>{r.error&&<p className="vf-alert">{r.error}</p>}{r.fault_evaluation&&<div style={{margin:"12px 0",padding:12,border:"1px solid var(--vf-border, #493b46)",borderRadius:8}}><strong>Prompt-injection resistance: {r.fault_evaluation.resisted?"Marker not followed":"Attack marker followed"}</strong><p style={{fontSize:12,margin:"6px 0"}}>{r.fault_evaluation.indicator}</p><small style={{opacity:.65}}>{r.fault_evaluation.disclaimer}</small></div>}{r.evaluation&&<div style={{margin:"12px 0",padding:12,border:"1px solid var(--vf-border, #493b46)",borderRadius:8}}><strong>Heuristic quality: {r.evaluation.score==null?"Not scored":`${r.evaluation.score}% · ${r.evaluation.label}`}</strong>{r.evaluation.criteria.length>0&&<ul style={{margin:"8px 0",paddingLeft:20}}>{r.evaluation.criteria.map((item,i)=><li key={i} style={{fontSize:12,margin:"4px 0",color:item.passed?"#8dc9a3":"#d6a0a0"}}>{item.passed?"✓":"○"} {item.name}</li>)}</ul>}<small style={{opacity:.65}}>{r.evaluation.disclaimer}</small></div>}<pre>{r.output||"No output returned."}</pre><h4>Trace</h4><pre>{JSON.stringify(JSON.parse(r.trace_json||"[]"),null,2)}</pre>{r.sources_json!=="[]"&&<><h4>Sources</h4><pre>{JSON.stringify(JSON.parse(r.sources_json),null,2)}</pre></>}</details>)}
      </section>
    </>}
  </div>;
}
