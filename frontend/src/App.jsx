import { useState, useRef } from 'react'
import ReactFlow, { Background, Controls } from 'reactflow'
import 'reactflow/dist/style.css'
import { Upload, ShieldAlert, FileSearch, Check, Loader2, Sparkles, ListChecks } from 'lucide-react'
import { uploadFile, uploadSample, analyze, explain } from './services/api'

const SAMPLES = [['incident_01', 'Suspicious execution'], ['incident_02', 'Credential theft'], ['incident_03', 'Ransomware-like']]
const STEPS = ['Parsing logs', 'Correlating events', 'Building timeline', 'Building attack graph', 'Preparing evidence', 'Generating explanation']
const SEV = { CRITICAL: 'bg-red-600', HIGH: 'bg-orange-500', MEDIUM: 'bg-yellow-500 text-black', LOW: 'bg-sky-600', NONE: 'bg-slate-600' }
const KIND = { user: '#334155', proc: '#1e3a5f', ext: '#7f1d1d', mass: '#78350f' }

function Panel({ title, icon: Icon, children, className = '' }) {
  return <section className={`rounded-md border border-slate-700/70 bg-[#131a23] ${className}`}>
    <h2 className="flex items-center gap-2 border-b border-slate-700/70 px-4 py-2.5 text-sm font-semibold text-slate-200">{Icon && <Icon size={15} />}{title}</h2>
    <div className="p-4">{children}</div></section>
}

export default function App() {
  const [up, setUp] = useState(null), [inc, setInc] = useState(null), [step, setStep] = useState(-1)
  const [sel, setSel] = useState([]), [ai, setAi] = useState(null), [aiBusy, setAiBusy] = useState(false)
  const [err, setErr] = useState(''), [q, setQ] = useState('Why is this suspicious?'), fileRef = useRef()
  const run = (p) => p.catch((e) => setErr(e.message))
  const onUp = (p) => run(p.then((u) => { setUp(u); setInc(null); setAi(null); setSel([]); setStep(-1); setErr('') }))

  const reconstruct = async () => {
    setInc(null); setAi(null); setSel([]); setStep(0)
    const req = analyze(up.id)
    for (let i = 0; i < STEPS.length; i++) { setStep(i + 1); await new Promise((r) => setTimeout(r, 450)) }
    run(req.then((r) => { setInc(r); setSel(r.chain.slice(0, 1).map((e) => e.id)); ask(r.id) }))
  }
  const ask = (id, question) => { setAiBusy(true); run(explain(id, question).then(setAi).finally(() => setAiBusy(false))) }

  const byId = inc ? Object.fromEntries(inc.chain.map((e) => [e.id, e])) : {}
  const Ev = ({ ids, children }) => <button onClick={() => setSel(ids)} className="text-sky-400 underline-offset-2 hover:underline text-xs">{children || 'View evidence'}</button>

  const nodes = inc?.nodes.map((n) => ({ id: n.id, position: { x: n.x, y: n.y }, data: { label: <div><b>{n.label}</b><div className="text-[11px] opacity-80">{n.sub}</div></div> },
    style: { background: KIND[n.kind], color: '#e2e8f0', border: sel.some((s) => n.event_ids.includes(s)) ? '2px solid #38bdf8' : '1px solid #475569', borderRadius: 6, width: 170, fontSize: 12 } }))
  const edges = inc?.edges.map((e) => ({ ...e, animated: true, markerEnd: { type: 'arrowclosed' }, style: { stroke: '#64748b' } }))

  return <div className="mx-auto max-w-7xl space-y-4 p-5">
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="flex items-center gap-2 text-2xl font-semibold text-white"><FileSearch /> What Happened Here?</h1>
        <p className="text-sm text-slate-400">Give us the noise. We'll reconstruct the story. AI-assisted incident reconstruction prototype.</p></div>
      <div className="flex flex-wrap gap-2">
        {SAMPLES.map(([n, l]) => <button key={n} onClick={() => onUp(uploadSample(n))} className="rounded border border-slate-600 px-3 py-1.5 text-xs hover:bg-slate-800">{l}</button>)}
        <button onClick={() => fileRef.current.click()} className="flex items-center gap-1.5 rounded bg-slate-700 px-3 py-1.5 text-xs"><Upload size={13} />Upload .json / .log</button>
        <input ref={fileRef} type="file" accept=".json,.log" hidden onChange={(e) => e.target.files[0] && onUp(uploadFile(e.target.files[0]))} />
      </div></header>
    {err && <div className="rounded border border-red-700 bg-red-950 p-3 text-sm text-red-200">{err}</div>}

    {!up && <Panel title="Upload incident" icon={Upload}><p className="text-sm text-slate-400">Pick a synthetic sample above or upload your own log file (JSON, or one JSON event per line).</p></Panel>}
    {up && <Panel title={`${up.count} events received`} icon={Upload}>
      <pre className="max-h-32 overflow-auto rounded bg-black/40 p-2 text-[11px] text-slate-400">{up.preview.map((e) => JSON.stringify(e)).join('\n')}</pre>
      <div className="mt-3 flex items-center gap-4">
        <button onClick={reconstruct} disabled={step > 0 && !inc} className="rounded bg-sky-500 px-5 py-2 font-semibold text-black hover:bg-sky-400 disabled:opacity-50">Reconstruct Incident</button>
        {step >= 0 && !inc && <ul className="text-sm">{STEPS.map((s, i) => <li key={s} className={i < step ? 'text-slate-200' : 'text-slate-600'}>
          {i < step ? <Check size={13} className="mr-1 inline text-emerald-400" /> : <Loader2 size={13} className="mr-1 inline" />}{s}</li>)}</ul>}
      </div></Panel>}

    {inc && !inc.detected && <Panel title="No incident chain found"><p className="text-sm text-slate-400">No rule matched in {inc.total_events} events.</p></Panel>}
    {inc?.detected && <>
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-slate-700 bg-[#131a23] p-4">
        <div><div className="flex items-center gap-2 text-xs text-red-300"><ShieldAlert size={14} />INCIDENT DETECTED</div>
          <div className="text-xl font-semibold text-white">{inc.title}</div>
          <div className="text-xs text-slate-400">{inc.total_events} raw events reduced to {inc.chain.length} relevant events. {inc.note}</div></div>
        <div className="text-right text-xs text-slate-400">Incident severity<div className={`mt-1 rounded px-4 py-1.5 text-lg font-bold text-white ${SEV[inc.severity]}`}>{inc.severity}</div></div></div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel title="Incident timeline" className="lg:col-span-2">
          <ol className="space-y-1">{inc.chain.map((e) => <li key={e.id}>
            <button onClick={() => setSel([e.id])} className={`w-full rounded border px-3 py-2 text-left text-sm ${sel.includes(e.id) ? 'border-sky-400 bg-sky-950/40' : 'border-slate-700 hover:bg-slate-800'}`}>
              <span className="font-mono text-xs text-slate-400">{e.timestamp}</span> <span className="font-semibold">{labelOf(e)}</span>
              <div className="text-xs text-slate-400">{e.destination || e.file || e.process}{e.count > 1 ? ` (${e.count} files)` : ''}</div></button></li>)}</ol></Panel>
        <Panel title="Attack graph (click a node)" className="lg:col-span-3"><div style={{ height: 420 }}>
          <ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} onNodeClick={(_, n) => setSel(inc.nodes.find((x) => x.id === n.id).event_ids)}><Background color="#243040" /><Controls showInteractive={false} /></ReactFlow></div></Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Evidence" icon={FileSearch}>
          <div className="space-y-2">{sel.map((id) => byId[id] && <div key={id} className="rounded bg-black/40 p-2 font-mono text-[11px]"><span className="text-sky-400">{id}</span> {JSON.stringify(byId[id].raw_event)}</div>)}</div>
          <h3 className="mb-1 mt-4 text-xs font-semibold text-slate-300">Rule findings</h3>
          <ul className="space-y-1.5 text-sm">{inc.findings.map((f) => <li key={f.rule}><span className="text-slate-400">{f.rule}</span> {f.why} <Ev ids={f.event_ids} /></li>)}</ul></Panel>
        <Panel title="AI explanation" icon={Sparkles}>
          {aiBusy && <p className="text-sm text-slate-400"><Loader2 size={13} className="mr-1 inline animate-spin" />Asking Ollama...</p>}
          {ai && !aiBusy && <div className="space-y-3 text-sm">
            <p>{ai.summary}</p><p className="text-slate-300">{ai.suspicious}</p>
            {ai.answer && <p className="rounded border-l-2 border-sky-400 bg-sky-950/30 p-2">{ai.answer}</p>}
            <ul className="space-y-1">{ai.evidence?.map((x, i) => <li key={i}>{x.claim} {x.event_ids.length > 0 && <Ev ids={x.event_ids} />}</li>)}</ul>
            <div className="text-[11px] text-slate-500">Source: {ai.source}</div></div>}
          <div className="mt-3 flex gap-2"><input value={q} onChange={(e) => setQ(e.target.value)} className="flex-1 rounded border border-slate-600 bg-transparent px-2 py-1.5 text-sm" />
            <button onClick={() => ask(inc.id, q)} className="rounded bg-slate-700 px-3 text-sm">Ask</button></div></Panel>
      </div>
      <Panel title="Recommended investigation" icon={ListChecks}>
        <ul className="list-disc space-y-1 pl-5 text-sm">{(ai?.recommendations || []).map((r, i) => <li key={i}>{r}</li>)}</ul></Panel>
    </>}
  </div>
}
const NAMES = { DOWNLOAD: 'Download', EXTRACT: 'Archive extracted', EXE_CREATE: 'Executable created', EXEC: 'Execution', POWERSHELL: 'PowerShell', EXT_CONN: 'Network connection', MASS_ACCESS: 'Mass file access', MASS_MODIFY: 'File modification', CRED_ACCESS: 'Credential access', PRIV_ACTION: 'Privileged action' }
const labelOf = (e) => NAMES[e.tag] || e.tag
