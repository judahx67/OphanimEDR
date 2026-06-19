import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import axios from 'axios'
import { CausalChain, NodeLegend, type MatchedNode, type MatchedEdge } from './CausalChain'
import SigmaGenerator from './SigmaGenerator'

// Per-detection detail shown when a /compare row is expanded (the /incidents
// dropdown pattern). Three parts: the clearer causal-edge view, a multi-LLM
// analysis of THIS flagged node (persisted to Neo4j so it survives reload), and
// a SIEM-rule generator that encodes the L2 finding the rules missed.

export interface CompareNode { uuid: string; label: string; name: string }

const FONT = 'var(--font-ui)'
const RISK_COLOR: Record<string, string> = { high: '#dc2626', medium: '#eab308', low: '#16a34a' }
const PROVIDER_ORDER = ['gemini', 'groq', 'anthropic', 'openai']

interface Analysis {
    attack_hypothesis?: string; mitre_technique?: string | null; mitre_tactic?: string | null
    evidence_summary?: string; confidence?: string; false_positive_risk?: string
    analyst_action?: string; _parse_error?: boolean; raw?: string
}
interface Cell {
    provider: string; label?: string; model?: string; premium?: boolean
    analysis?: Analysis; error?: string | null; fallback_from?: string
}
interface ProviderInfo {
    providers: string[]; labels: Record<string, string>
    available: Record<string, boolean>; premium_available: Record<string, boolean>
    models: Record<string, string>; budget: Budget
}
interface Budget {
    openai_calls_used: number; openai_call_budget: number
    premium_calls_used: number; premium_call_budget: number
}
interface Subgraph { nodes: { id: string; label: string; name: string }[]; edges: { source: string; target: string; type: string; event_id?: string; timestamp?: number }[] }

function Field({ k, v, color }: { k: string; v?: string | null; color?: string }) {
    if (!v) return null
    return (
        <div style={{ marginBottom: 6 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{k} </span>
            <span style={{ fontSize: 11, color: color || 'var(--text-secondary)' }}>{v}</span>
        </div>
    )
}

function Card({ c }: { c: Cell }) {
    const a = c.analysis
    return (
        <div style={{ flex: 1, minWidth: 240, background: 'var(--bg-card)', border: `1px solid ${c.error ? '#dc2626' : 'var(--border-light)'}`, padding: '12px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-primary)', fontFamily: FONT }}>{c.label || c.provider}</span>
                <span style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: FONT }}>{c.premium ? '★ ' : ''}{c.model}</span>
            </div>
            {c.fallback_from && (
                <div style={{ fontSize: 9, color: '#eab308', fontFamily: FONT, marginBottom: 6 }}>↳ {c.fallback_from} unavailable — fell back to {c.model}</div>
            )}
            {c.error ? (
                <div style={{ fontSize: 11, color: '#dc2626', fontFamily: FONT }}>{c.error}</div>
            ) : a?._parse_error ? (
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: FONT, whiteSpace: 'pre-wrap' }}>{a.raw}</div>
            ) : (
                <div style={{ fontFamily: FONT }}>
                    <Field k="hypothesis" v={a?.attack_hypothesis} color="var(--text-primary)" />
                    <Field k="MITRE" v={[a?.mitre_technique, a?.mitre_tactic].filter(Boolean).join(' · ') || null} />
                    <Field k="evidence" v={a?.evidence_summary} />
                    <div style={{ display: 'flex', gap: 14, margin: '6px 0' }}>
                        <Field k="confidence" v={a?.confidence} color={RISK_COLOR[(a?.confidence || '').toLowerCase()]} />
                        <Field k="FP risk" v={a?.false_positive_risk} color={RISK_COLOR[(a?.false_positive_risk || '').toLowerCase()]} />
                    </div>
                    <Field k="action" v={a?.analyst_action} />
                </div>
            )}
        </div>
    )
}

const sectionLabel: React.CSSProperties = {
    fontFamily: FONT, fontSize: 10, fontWeight: 700, color: 'var(--text-muted)',
    textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8,
}

export default function CompareDetail({ node }: { node: CompareNode }) {
    const [sg, setSg] = useState<Subgraph | null>(null)
    const [info, setInfo] = useState<ProviderInfo | null>(null)
    const [picked, setPicked] = useState<Set<string>>(new Set())
    const [premium, setPremium] = useState(false)
    const [cells, setCells] = useState<Record<string, Cell>>({})  // keyed by provider
    const [budget, setBudget] = useState<Budget | null>(null)
    const [running, setRunning] = useState(false)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        axios.get<Subgraph>(`/api/graph/subgraph?node_id=${encodeURIComponent(node.uuid)}&hops=1`)
            .then(r => setSg(r.data)).catch(() => setSg({ nodes: [], edges: [] }))
        axios.get(`/api/compare/llm/${encodeURIComponent(node.uuid)}`)
            .then(r => {
                const saved: Record<string, Cell> = {}
                for (const s of r.data.results) saved[s.provider] = s
                setCells(saved)
            }).catch(() => { /* none saved yet */ })
        axios.get<ProviderInfo>('/api/llm/providers').then(r => {
            setInfo(r.data); setBudget(r.data.budget)
            setPicked(new Set(r.data.providers.filter(p => r.data.available[p]).slice(0, 2)))
        }).catch(e => setError(String(e)))
    }, [node.uuid])

    const toggle = (p: string) => setPicked(prev => { const n = new Set(prev); n.has(p) ? n.delete(p) : n.add(p); return n })
    const anyPremiumPicked = info ? [...picked].some(p => info.premium_available[p]) : false

    const run = async () => {
        setRunning(true); setError(null)
        try {
            const res = await axios.post('/api/compare/llm', {
                node_ids: [node.uuid], providers: [...picked], premium: premium && anyPremiumPicked,
            })
            setCells(prev => {
                const next = { ...prev }
                for (const r of res.data.results) next[r.provider] = r
                return next
            })
            setBudget(res.data.budget)
        } catch (e: any) {
            setError(e?.response?.data?.detail || String(e))
        } finally { setRunning(false) }
    }

    // Map the 1-hop subgraph to the shared causal-chain shape.
    const nameOf = (id: string) => sg?.nodes.find(n => n.id === id)?.name || id.slice(0, 12)
    const mNodes: MatchedNode[] = (sg?.nodes || []).map(n => ({ id: n.id, type: (n.label || '').toUpperCase(), name: n.name || n.id }))
    const mEdges: MatchedEdge[] = (sg?.edges || []).slice(0, 25).map(e => ({
        event_id: e.event_id || '', edge_type: e.type,
        subject_id: e.source, subject_name: nameOf(e.source),
        object_id: e.target, object_name: nameOf(e.target), timestamp: e.timestamp || 0,
    }))
    const orderedCells = PROVIDER_ORDER.filter(p => cells[p]).map(p => cells[p])

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '4px 0' }}>
            {/* Causal context */}
            <div>
                <div style={sectionLabel}>// Causal context — {mEdges.length} edge{mEdges.length !== 1 ? 's' : ''} (1-hop)</div>
                {sg === null ? <Spinner size="extra-small" label="Loading edges…" />
                    : <><CausalChain edges={mEdges} nodes={mNodes} /><NodeLegend nodes={mNodes} /></>}
            </div>

            {/* LLM analysis */}
            <div>
                <div style={sectionLabel}>// LLM analysis (persisted)</div>
                {info && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                        {info.providers.map(p => {
                            const on = picked.has(p), ok = info.available[p]
                            return (
                                <button key={p} disabled={!ok} onClick={() => toggle(p)} title={ok ? info.models[p] : 'no API key'}
                                    style={{
                                        fontFamily: FONT, fontSize: 11, fontWeight: 700, padding: '4px 10px', cursor: ok ? 'pointer' : 'not-allowed',
                                        background: on ? 'var(--accent-primary)' : 'transparent', color: on ? '#fff' : ok ? 'var(--text-secondary)' : 'var(--text-muted)',
                                        border: `1px solid ${on ? 'var(--accent-primary)' : 'var(--border-light)'}`, opacity: ok ? 1 : 0.5,
                                    }}>{info.labels[p]}{!ok && ' (no key)'}</button>
                            )
                        })}
                        <label style={{ fontFamily: FONT, fontSize: 11, color: anyPremiumPicked ? 'var(--text-secondary)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, cursor: anyPremiumPicked ? 'pointer' : 'not-allowed' }}>
                            <input type="checkbox" checked={premium && anyPremiumPicked} disabled={!anyPremiumPicked} onChange={e => setPremium(e.target.checked)} /> ★ premium
                        </label>
                        <button onClick={run} disabled={running || picked.size === 0}
                            style={{ fontFamily: FONT, fontSize: 11, fontWeight: 700, padding: '5px 14px', background: running || picked.size === 0 ? 'var(--border-light)' : 'var(--accent-primary)', color: '#fff', border: 'none', cursor: running || picked.size === 0 ? 'default' : 'pointer' }}>
                            {running ? 'Running…' : `Run (${picked.size})`}
                        </button>
                        {budget && <span style={{ fontFamily: FONT, fontSize: 10, color: 'var(--text-muted)' }}>premium {budget.premium_calls_used}/{budget.premium_call_budget} · openai {budget.openai_calls_used}/{budget.openai_call_budget}</span>}
                    </div>
                )}
                {error && <div style={{ color: '#dc2626', fontFamily: FONT, fontSize: 11, marginBottom: 8 }}>Error: {error}</div>}
                {running && <Spinner size="small" label="Querying models…" />}
                {orderedCells.length > 0
                    ? <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>{orderedCells.map((c, i) => <Card key={i} c={c} />)}</div>
                    : !running && <span style={{ fontFamily: FONT, fontSize: 11, color: 'var(--text-muted)' }}>No analysis yet — pick providers and run. Results are illustrative, not an LLM evaluation.</span>}
            </div>

            {/* SIEM rule */}
            <div>
                <div style={sectionLabel}>// Encode this finding as a SIEM rule</div>
                <SigmaGenerator nodeId={node.uuid} />
            </div>
        </div>
    )
}
