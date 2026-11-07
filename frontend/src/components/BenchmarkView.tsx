import { useState } from "react";

type Run = { id:string; agent:string; repetition:number; status:string; output:string; error:string; duration_ms:number; prompt_tokens:number; completion_tokens:number; tool_calls:number; steps:number; trace_json:string; sources_json:string };
type Result = { experiment_id:string; status:string; repetitions:number; fault:string|null; agents:{agent:string;runs:number;success_rate:number;avg_duration_ms:number;avg_tokens:number;avg_tool_calls:number}[]; runs:Run[] };

export function BenchmarkView() {
  const [prompt,setPrompt]=useState("Research the latest stable Python release and summarize the release date and two notable changes. Include source URLs and clearly state uncertainty.");
  const [repetitions,setRepetitions]=useState(2);
  const [fault,setFault]=useState("none");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [result,setResult]=useState<Result|null>(null);
  async function run() {
    setBusy(true);setError("");setResult(null);
    try {
      const response=await fetch("http://127.0.0.1:8010/api/benchmarks/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({task:{id:"research-freshness-001",category:"research",prompt},repetitions,fault:fault==="none"?null:fault})});
      const data=await response.json();
      if(!response.ok) throw new Error(data.detail||"Benchmark request failed");
      setResult(data);
    } catch(e) {setError(e instanceof Error?e.message:"Benchmark failed");}
    finally {setBusy(false);}
  }
  return <div className="vf-benchmark">
    <section className="vf-card"><div className="vf-section-heading"><div><p className="vf-eyebrow">Reproducible experiment</p><h2>Agent benchmark runner</h2></div><span className="vf-soft-tag">Research category</span></div>
      <p className="vf-empty-inline">Identical task → direct Bifrost agent vs Tavily-assisted Bifrost agent. Runs and traces are persisted locally. Configure BIFROST_BASE_URL, BIFROST_API_KEY, BIFROST_MODEL and TAVILY_API_KEY before execution.</p>
      <label className="vf-benchmark-label">Benchmark task<textarea value={prompt} onChange={e=>setPrompt(e.target.value)} rows={4}/></label>
      <div className="vf-form-row"><label>Repeated trials<select value={repetitions} onChange={e=>setRepetitions(Number(e.target.value))}>{[1,2,3,5,10].map(n=><option key={n} value={n}>{n}</option>)}</select></label><label>Fault injection<select value={fault} onChange={e=>setFault(e.target.value)}><option value="none">Normal execution</option><option value="model_unavailable">Model unavailable</option><option value="tool_unavailable">Tavily unavailable</option></select></label><button className="vf-button vf-button--primary" disabled={busy||!prompt.trim()} onClick={()=>void run()}>{busy?"Executing agents…":"Run benchmark"}</button></div>
    </section>
    {error&&<div className="vf-alert"><strong>Execution failed</strong><span>{error}</span></div>}
    {result&&<>
      <section className="vf-card"><div className="vf-section-heading"><div><p className="vf-eyebrow">Experiment {result.experiment_id}</p><h2>Comparative results</h2></div><span className="vf-soft-tag">{result.repetitions} repetitions · {result.fault||"normal conditions"}</span></div>
        <div className="vf-metric-grid">{result.agents.map(a=><article className="vf-metric" key={a.agent}><span>{a.agent}</span><strong>{Math.round(a.success_rate*100)}%</strong><small>Success rate · avg {a.avg_duration_ms} ms · {a.avg_tokens} tokens · {a.avg_tool_calls} tool calls</small></article>)}</div>
      </section>
      <section className="vf-card"><div className="vf-section-heading"><div><p className="vf-eyebrow">Inspectable execution</p><h2>Run-by-run traces</h2></div></div>
      {result.runs.map(r=><details className="vf-benchmark-run" key={r.id}><summary><strong>{r.agent}</strong> · Trial {r.repetition} · {r.status} · {r.duration_ms} ms · {r.prompt_tokens+r.completion_tokens} tokens</summary>{r.error&&<p className="vf-alert">{r.error}</p>}<pre>{r.output||"No output returned."}</pre><h4>Trace</h4><pre>{JSON.stringify(JSON.parse(r.trace_json||"[]"),null,2)}</pre>{r.sources_json!=="[]"&&<><h4>Sources</h4><pre>{JSON.stringify(JSON.parse(r.sources_json),null,2)}</pre></>}</details>)}
      </section>
    </>}
  </div>;
}
