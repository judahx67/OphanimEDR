import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import { BrainCircuit24Regular, Search24Regular, ArrowRight24Regular } from '@fluentui/react-icons'
import axios from 'axios'

// ── Types ──────────────────────────────────────────────────────────────────

interface EdgeFinding {
    event_id: string
    edge_type: string
    score: number | null
    quality: string | null
    is_alert: boolean
    timestamp: number | null
    subject: { id: string; name: string; label: string }
    object: { id: string; name: string; label: string }
    endpoint_id: string | null
    analysis_status?: 'ok' | 'failed' | 'none'
}

interface EdgeSummary {
    total_scored: number
    mean_score: number
    alerts: number
    degraded: number
}

interface SubgraphEdge {
    source: string
    target: string
    type: string
    event_id: string | null
    timestamp: number | null
    size: number | null
    properties: Record<string, unknown>
    ml_score: number | null
    ml_alert: boolean | null
}

interface SubgraphNode {
    id: string
    label: string
    name: string
}

interface LLMNarrative {
    attack_hypothesis: string
    mitre_technique: string | null
    mitre_tactic: string | null
    evidence_summary: string
    confidence: string
    analyst_action: string
    false_positive_risk: string
    yara_rule?: string | null
    agreement_status?: string | null
    secondary_model?: string | null
    secondary_mitre?: string | null
    secondary_confidence?: string | null
    secondary_hypothesis?: string | null
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Extract the most meaningful detail string for an edge based on its type and properties. */
function edgeDetail(edge: SubgraphEdge): string | null {
    const p = edge.properties || {}
    const str = (v: unknown) => (v != null ? String(v) : null)
    const num = (v: unknown) => (typeof v === 'number' && v > 0 ? v : null)

    switch (edge.type) {
        case 'ACCESS':
        case 'SEND':
        case 'RECEIVE': {
            const method = str(p.http_method)
            const status = str(p.http_status)
            const uri = str(p.http_uri)
            const bytes = num(edge.size ?? p.bytes as number)
            const parts: string[] = []
            if (method) parts.push(method)
            if (status) parts.push(status)
            if (uri) parts.push(uri.length > 40 ? uri.slice(0, 40) + '…' : uri)
            if (!parts.length && bytes) parts.push(fmtBytes(bytes))
            return parts.join(' · ') || null
        }
        case 'CONNECT': {
            const sport = str(p.src_port)
            const dport = str(p.dest_port)
            const proto = str(p.transport) ?? str(p.protocol)
            const bytes = num(edge.size ?? p.bytes as number)
            const parts: string[] = []
            if (sport && dport) parts.push(`${sport} → ${dport}`)
            if (proto) parts.push(proto.toUpperCase())
            if (bytes) parts.push(fmtBytes(bytes))
            return parts.join(' · ') || null
        }
        case 'EXEC':
        case 'FORK': {
            const cmd = str(p.command_line) ?? str(p.process_name)
            return cmd ? (cmd.length > 60 ? cmd.slice(0, 60) + '…' : cmd) : null
        }
        case 'READ':
        case 'WRITE':
        case 'DELETE':
        case 'RENAME':
        case 'LOAD': {
            const bytes = num(edge.size ?? p.bytes as number)
            return bytes ? fmtBytes(bytes) : null
        }
        case 'MODIFY_REG': {
            const key = str(p.registry_key)
            return key ? (key.length > 50 ? '…' + key.slice(-50) : key) : null
        }
        case 'AUTH': {
            const user = str(p.user)
            return user ?? null
        }
        default:
            return null
    }
}

function fmtBytes(b: number): string {
    if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`
    if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`
    return `${b} B`
}

/** Shorten a node name to the meaningful part (filename, hostname, last path segment). */
function shortName(name: string, label: string): string {
    if (!name) return '?'
    if (label === 'Url' || label === 'File') {
        // Show filename or last path segment
        const last = name.split(/[/\\]/).filter(Boolean).pop()
        return last && last !== name ? last : name.slice(0, 22)
    }
    if (label === 'Socket') {
        // sock:ip:port->ip:port/proto — show just the dest ip:port
        const m = name.match(/->([^/]+)/)
        return m ? m[1] : name.slice(0, 22)
    }
    return name.length > 22 ? name.slice(0, 22) + '…' : name
}

// ── Constants ──────────────────────────────────────────────────────────────

const EDGE_TYPE_COLORS: Record<string, string> = {
    ACCESS: '#7c3aed', CONNECT: '#0284c7', FORK: '#dc2626',
    WRITE: '#ea580c', READ: '#16a34a', EXEC: '#9333ea',
    MODIFY_REG: '#b45309', LOAD: '#0891b2', DELETE: '#e11d48',
    AUTH: '#db2777', SEND: '#0369a1', RECEIVE: '#0369a1',
}

const NODE_LABEL_COLORS: Record<string, string> = {
    Process: '#eab308', File: '#6366f1', Socket: '#06b6d4',
    Host: '#8b5cf6', Url: '#10b981', Registry: '#ec4899',
    Memory: '#f97316', User: '#f43f5e',
}

const SEV_COLOR = (pct: number) =>
    pct >= 90 ? 'var(--status-critical)' :
    pct >= 70 ? '#ea580c' :
    pct >= 40 ? '#ca8a04' : 'var(--status-good)'

// ── Sub-components ─────────────────────────────────────────────────────────

function EdgeTypeBadge({ type }: { type: string }) {
    return (
        <span style={{
            fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 700,
            letterSpacing: '0.05em', padding: '2px 7px',
            background: EDGE_TYPE_COLORS[type] || 'var(--text-muted)',
            color: '#fff',
        }}>{type}</span>
    )
}

function NodeChip({ label, name }: { label: string; name: string }) {
    return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span style={{
                fontFamily: 'var(--font-ui)', fontSize: '9px', fontWeight: 700,
                background: NODE_LABEL_COLORS[label] || '#888',
                color: '#fff', padding: '1px 4px',
            }}>{label[0]}</span>
            <span style={{
                fontFamily: 'var(--font-ui)', fontSize: '12px',
                color: 'var(--text-primary)',
                maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis',
                whiteSpace: 'nowrap', display: 'inline-block',
            }} title={name}>{name}</span>
        </span>
    )
}

// LightGBM scores cluster near 0 or 1 on a clear signal. To keep the
// top-of-table distinguishable, show two decimals once the integer % saturates
// (≥99 or ≤1) and one decimal otherwise — never collapsing 0.9999 and 0.995
// into the same "100%" label.
function formatPct(value: number): string {
    const pct = value * 100
    if (pct >= 99 || pct <= 1) return pct.toFixed(2) + '%'
    return pct.toFixed(1) + '%'
}

function ScoreBar({ value, label }: { value: number | null; label: string }) {
    if (value === null) return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
    const pct = value * 100
    const display = formatPct(value)
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 48, height: 6, background: 'var(--border-light)', position: 'relative' }}>
                <div style={{ position: 'absolute', left: 0, top: 0, height: '100%', width: `${pct}%`, background: SEV_COLOR(pct) }} />
            </div>
            <span style={{ fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600, color: SEV_COLOR(pct), minWidth: 46 }}>
                {display}
            </span>
            <span style={{ fontFamily: 'var(--font-ui)', fontSize: 10, color: 'var(--text-muted)' }}>{label}</span>
        </div>
    )
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function Problems() {
    const [findings, setFindings] = useState<EdgeFinding[]>([])
    const [summary, setSummary] = useState<EdgeSummary | null>(null)
    const [minScore, setMinScore] = useState(0.4)
    // Default 'ok' hides degenerate parse-error incidents (pre-fix Gemini runs)
    // so the demo screen shows actionable analysis only. 'any' restores legacy behaviour.
    const [analysisFilter, setAnalysisFilter] = useState<'ok' | 'any' | 'none'>('ok')
    const [eventIdFilter, setEventIdFilter] = useState('')
    // When the typed event_id isn't in the current top-N, fall back to the
    // /api/ml/edges/by-id/{id} endpoint and surface that single row.
    const [lookupRow, setLookupRow] = useState<EdgeFinding | null>(null)
    const [lookupErr, setLookupErr] = useState<string>('')
    const [loading, setLoading] = useState(true)
    const [selected, setSelected] = useState<EdgeFinding | null>(null)
    const [subgraph, setSubgraph] = useState<{ nodes: SubgraphNode[]; edges: SubgraphEdge[] } | null>(null)
    const [subgraphLoading, setSubgraphLoading] = useState(false)
    const [narrative, setNarrative] = useState<LLMNarrative | null>(null)

    const load = async () => {
        setLoading(true)
        try {
            const [findRes, sumRes] = await Promise.all([
                axios.get(`/api/ml/edges/top?rule_clear=false&limit=100&min_score=${minScore}&analysis=${analysisFilter}`),
                axios.get('/api/ml/edges/summary'),
            ])
            setFindings(findRes.data)
            setSummary(sumRes.data)
        } catch (e) {
            console.error('Failed to load ML findings', e)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => { load() }, [minScore, analysisFilter])

    // When user pastes a full event_id, try the dedup-bypass endpoint so the
    // exact row surfaces even if the top-N deduped it under a sibling.
    useEffect(() => {
        setLookupRow(null)
        setLookupErr('')
        const q = eventIdFilter.trim().toLowerCase()
        if (q.length < 8) return
        const hasMatchInTop = findings.some(f => f.event_id?.toLowerCase().includes(q))
        if (hasMatchInTop) return
        // Only call when it plausibly is a UUID — at least 8 hex/dash chars.
        if (!/^[0-9a-f-]+$/.test(q)) return
        const timer = setTimeout(async () => {
            try {
                const res = await axios.get(`/api/ml/edges/by-id/${encodeURIComponent(q)}`)
                setLookupRow(res.data)
            } catch {
                setLookupErr('event_id not found in graph')
            }
        }, 300)
        return () => clearTimeout(timer)
    }, [eventIdFilter, findings])

    const selectEdge = async (f: EdgeFinding) => {
        setSelected(f)
        setSubgraph(null)
        setNarrative(null)
        setSubgraphLoading(true)
        try {
            // Pass both endpoints — sockets are leaf-like so subject-only
            // 1-hop often returns just the flagged edge itself.
            const params = new URLSearchParams()
            params.append('node_id', f.subject.id)
            params.append('node_id', f.object.id)
            params.append('hops', '1')
            const res = await axios.get(`/api/graph/subgraph?${params.toString()}`)
            setSubgraph(res.data)
        } catch { /* ignore */ } finally {
            setSubgraphLoading(false)
        }
        try {
            const nr = await axios.get(`/api/ml/incidents/${encodeURIComponent(f.event_id)}`)
            setNarrative(nr.data)
        } catch { /* no narrative */ }
    }

    const THRESHOLDS = [
        { label: 'All', value: 0 },
        { label: 'Moderate 40%+', value: 0.4 },
        { label: 'High 70%+', value: 0.7 },
        { label: 'Certain 90%+', value: 0.9 },
    ]

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

            {/* Page header — matches Dashboard/Incidents pattern */}
            <div>
                <div style={{
                    fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase',
                    letterSpacing: '0.1em', marginBottom: 4,
                    display: 'flex', alignItems: 'center', gap: 6,
                }}>
                    <span style={{ color: 'var(--accent-primary)', fontWeight: 700 }}>//</span>
                    Detections
                </div>
                <h1 style={{
                    fontFamily: 'var(--font-sans)', fontSize: 28, fontWeight: 700,
                    color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.02em',
                    margin: 0,
                }}>ML Edge Anomaly Detection</h1>
                <p style={{
                    fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-secondary)',
                    marginTop: 6, maxWidth: 680, lineHeight: 1.6,
                }}>
                    Edges scored by frozen LightGBM-XT trained on BOTSv2 (ROC-AUC 0.9877 headline / 0.9135 honest).
                    Score is from the sourcetype-blind honest LightGBM model (the only model in production
                    since 2026-05-24). Table shows one row per unique subject→object pair.
                </p>
            </div>

            {/* Summary stat cards — matches Dashboard pattern */}
            {summary && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                    {[
                        { label: 'Edges Scored', value: summary.total_scored.toLocaleString(), sub: 'total' },
                        { label: 'Mean Score', value: (summary.mean_score * 100).toFixed(1) + '%', sub: 'honest model' },
                        { label: 'Alerts', value: summary.alerts.toLocaleString(), sub: '≥ 85%' },
                        { label: 'Degraded', value: summary.degraded, sub: 'no _raw' },
                    ].map(c => (
                        <div key={c.label} style={{
                            background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
                            padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 8,
                        }}>
                            <span style={{
                                fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
                            }}>{c.label}</span>
                            <span style={{
                                fontFamily: 'var(--font-ui)', fontSize: 28, fontWeight: 700,
                                color: 'var(--text-primary)', lineHeight: 1,
                            }}>{c.value}</span>
                            <span style={{ fontFamily: 'var(--font-ui)', fontSize: 10, color: 'var(--text-muted)' }}>{c.sub}</span>
                        </div>
                    ))}
                </div>
            )}

            {/* Filter bar */}
            <div style={{
                display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
                padding: '12px 16px', background: 'var(--bg-card)',
                border: '1px solid var(--border-light)',
            }}>
                <Search24Regular style={{ color: 'var(--text-muted)', fontSize: 16 }} />
                <span style={{ fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Min honest score
                </span>
                {THRESHOLDS.map(t => (
                    <button key={t.value} onClick={() => setMinScore(t.value)} style={{
                        padding: '5px 12px', fontFamily: 'var(--font-ui)', fontSize: 11,
                        fontWeight: 600, letterSpacing: '0.04em', cursor: 'pointer',
                        border: `2px solid ${Math.abs(minScore - t.value) < 0.01 ? 'var(--accent-primary)' : 'var(--border-light)'}`,
                        background: Math.abs(minScore - t.value) < 0.01 ? 'var(--accent-primary)' : 'transparent',
                        color: Math.abs(minScore - t.value) < 0.01 ? '#fff' : 'var(--text-secondary)',
                    }}>{t.label}</button>
                ))}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 8 }}>
                    <input type="range" min="0" max="0.95" step="0.05" value={minScore}
                        onChange={e => setMinScore(parseFloat(e.target.value))}
                        style={{ width: 100, accentColor: 'var(--accent-primary)' }} />
                    <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--accent-primary)', minWidth: 32 }}>
                        {(minScore * 100).toFixed(0)}%
                    </span>
                </div>
                {/* LLM analysis filter — separate concept from min_score */}
                <div style={{
                    display: 'flex', alignItems: 'center', gap: 4, marginLeft: 16,
                    paddingLeft: 12, borderLeft: '1px solid var(--border-light)',
                }}>
                    <span style={{
                        fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                        color: 'var(--text-muted)', textTransform: 'uppercase',
                        marginRight: 6,
                    }}>Analysis</span>
                    {[
                        { label: 'With LLM', value: 'ok' as const },
                        { label: 'Any', value: 'any' as const },
                        { label: 'Pending', value: 'none' as const },
                    ].map(o => (
                        <button key={o.value} onClick={() => setAnalysisFilter(o.value)} style={{
                            padding: '5px 10px', fontFamily: 'var(--font-ui)', fontSize: 11,
                            fontWeight: 600, letterSpacing: '0.04em', cursor: 'pointer',
                            border: `2px solid ${analysisFilter === o.value ? 'var(--accent-primary)' : 'var(--border-light)'}`,
                            background: analysisFilter === o.value ? 'var(--accent-primary)' : 'transparent',
                            color: analysisFilter === o.value ? '#fff' : 'var(--text-secondary)',
                        }}>{o.label}</button>
                    ))}
                </div>
                <input
                    type="text"
                    placeholder="filter by event_id…"
                    value={eventIdFilter}
                    onChange={e => setEventIdFilter(e.target.value)}
                    style={{
                        marginLeft: 12, padding: '5px 10px', minWidth: 220,
                        fontFamily: 'var(--font-ui)', fontSize: 11,
                        border: '2px solid var(--border-light)',
                        background: 'var(--bg-secondary)', color: 'var(--text-primary)',
                        outline: 'none',
                    }}
                />
                <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)' }}>
                    {(() => {
                        if (!eventIdFilter) return `${findings.length} unique pairs`
                        const q = eventIdFilter.toLowerCase()
                        const n = findings.filter(f => f.event_id?.toLowerCase().includes(q)).length
                        if (n > 0) return `${n} match${n === 1 ? '' : 'es'}`
                        if (lookupRow) return `1 match (direct lookup)`
                        if (lookupErr) return lookupErr
                        return '0 unique pairs'
                    })()}
                </span>
                <button onClick={load} style={{
                    padding: '5px 12px', fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600,
                    border: '2px solid var(--border-strong)', background: 'transparent',
                    color: 'var(--text-secondary)', cursor: 'pointer',
                }}>Refresh</button>
            </div>

            {/* Main content: table + detail panel */}
            <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>

                {/* Table */}
                <div style={{
                    flex: '1 1 0', minWidth: 0,
                    background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
                }}>
                    {loading ? (
                        <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
                            <Spinner />
                        </div>
                    ) : findings.length === 0 ? (
                        <div style={{
                            padding: 48, textAlign: 'center',
                            fontFamily: 'var(--font-ui)', fontSize: 13, color: 'var(--text-muted)',
                        }}>
                            No full-quality scored edges at this threshold.
                            <br />Try lowering the min honest score.
                        </div>
                    ) : (
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ borderBottom: '2px solid var(--border-strong)' }}>
                                    {['Type', 'Subject', 'Object', 'Score', ''].map(h => (
                                        <th key={h} style={{
                                            padding: '10px 14px', textAlign: 'left',
                                            fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                                            color: 'var(--text-muted)', textTransform: 'uppercase',
                                            letterSpacing: '0.08em', whiteSpace: 'nowrap',
                                        }}>{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {(() => {
                                    if (!eventIdFilter) return findings
                                    const q = eventIdFilter.toLowerCase()
                                    const filtered = findings.filter(f => f.event_id?.toLowerCase().includes(q))
                                    if (filtered.length > 0) return filtered
                                    if (lookupRow) return [lookupRow]
                                    return []
                                })().map((f, i) => {
                                    const isSelected = selected?.event_id === f.event_id
                                    return (
                                        <tr key={f.event_id || i}
                                            onClick={() => selectEdge(f)}
                                            style={{
                                                borderBottom: '1px solid var(--border-light)',
                                                cursor: 'pointer',
                                                background: isSelected ? 'var(--bg-hover)' : 'transparent',
                                            }}
                                            onMouseEnter={e => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = 'var(--bg-secondary)' }}
                                            onMouseLeave={e => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                                        >
                                            <td style={{ padding: '10px 14px', whiteSpace: 'nowrap' }}>
                                                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                        <EdgeTypeBadge type={f.edge_type} />
                                                        {f.analysis_status === 'ok' && (
                                                            <span title="LLM analysis available" style={{
                                                                fontSize: 9, fontWeight: 700, padding: '1px 5px',
                                                                background: 'rgba(22,163,74,0.15)', color: '#16a34a',
                                                                borderRadius: 2, letterSpacing: '0.05em',
                                                            }}>LLM</span>
                                                        )}
                                                        {f.analysis_status === 'failed' && (
                                                            <span title="LLM ran but output failed to parse" style={{
                                                                fontSize: 9, fontWeight: 700, padding: '1px 5px',
                                                                background: 'rgba(220,38,38,0.15)', color: '#dc2626',
                                                                borderRadius: 2, letterSpacing: '0.05em',
                                                            }}>ERR</span>
                                                        )}
                                                    </div>
                                                    <span
                                                        title={f.event_id ? `Full event_id: ${f.event_id}\nClick to copy` : ''}
                                                        onClick={ev => {
                                                            ev.stopPropagation()
                                                            if (f.event_id) navigator.clipboard?.writeText(f.event_id)
                                                        }}
                                                        style={{
                                                            fontFamily: 'var(--font-ui)', fontSize: 10,
                                                            color: 'var(--text-muted)',
                                                            cursor: 'copy',
                                                            userSelect: 'all',
                                                        }}
                                                    >
                                                        {f.event_id ? f.event_id.slice(0, 8) : '—'}
                                                    </span>
                                                </div>
                                            </td>
                                            <td style={{ padding: '10px 14px', maxWidth: 200 }}>
                                                <NodeChip label={f.subject.label} name={f.subject.name || f.subject.id} />
                                            </td>
                                            <td style={{ padding: '10px 14px', maxWidth: 220 }}>
                                                <NodeChip label={f.object.label} name={f.object.name || f.object.id} />
                                            </td>
                                            <td style={{ padding: '10px 14px', whiteSpace: 'nowrap' }}>
                                                <ScoreBar value={f.score} label="" />
                                            </td>
                                            <td style={{ padding: '10px 14px' }}>
                                                <ArrowRight24Regular style={{ color: 'var(--accent-primary)', fontSize: 14 }} />
                                            </td>
                                        </tr>
                                    )
                                })}
                            </tbody>
                        </table>
                    )}
                </div>

                {/* Detail panel */}
                {selected && (
                    <div style={{
                        flexShrink: 0, width: 380,
                        background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
                        position: 'sticky', top: 0, maxHeight: '80vh', overflowY: 'auto',
                    }}>

                        {/* Edge header */}
                        <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--border-light)' }}>
                            <div style={{
                                fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10,
                            }}>Selected Edge</div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                                <EdgeTypeBadge type={selected.edge_type} />
                            </div>
                            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <NodeChip label={selected.subject.label} name={selected.subject.name || selected.subject.id} />
                                    <ArrowRight24Regular style={{ color: 'var(--text-muted)', fontSize: 12, flexShrink: 0 }} />
                                    <NodeChip label={selected.object.label} name={selected.object.name || selected.object.id} />
                                </div>
                            </div>
                            <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <ScoreBar value={selected.score} label="Honest ML score" />
                            </div>
                            <div style={{ marginTop: 8, fontFamily: 'var(--font-ui)', fontSize: 10, color: 'var(--text-muted)' }}>
                                event_id: {selected.event_id?.slice(0, 36)}
                            </div>
                        </div>

                        {/* 1-hop neighbourhood */}
                        <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--border-light)' }}>
                            <div style={{
                                fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10,
                                display: 'flex', alignItems: 'center', gap: 6,
                            }}>
                                <BrainCircuit24Regular style={{ fontSize: 14 }} />
                                1-hop Neighbourhood
                            </div>
                            {subgraphLoading ? <Spinner size="extra-small" /> : subgraph ? (
                                <div>
                                    <div style={{
                                        fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 8,
                                    }}>
                                        {subgraph.nodes.length} nodes · {subgraph.edges.length} edges
                                        {subgraph.edges.filter(e => e.ml_alert).length > 0 &&
                                            <span style={{ color: 'var(--status-critical)', marginLeft: 8, fontWeight: 700 }}>
                                                ⚠ {subgraph.edges.filter(e => e.ml_alert).length} alerts
                                            </span>
                                        }
                                    </div>
                                    {/* Sparse-context hint: network flow alerts (pan_traffic/suricata) carry
                                        no process linkage, so the 1-hop graph is just the flagged edge itself. */}
                                    {subgraph.edges.length <= 2 && !subgraph.nodes.some(n => n.label === 'Process') && (
                                        <div style={{
                                            fontFamily: 'var(--font-ui)', fontSize: 10, color: 'var(--text-muted)',
                                            background: 'var(--bg-tertiary)', padding: '6px 8px', marginBottom: 8,
                                            borderLeft: '2px solid var(--accent-warning, #d97706)',
                                        }}>
                                            ℹ Network-flow alert — no process context in the graph.
                                            pan_traffic/suricata sourcetypes record socket-to-socket edges
                                            without the originating process.
                                        </div>
                                    )}
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 260, overflowY: 'auto' }}>
                                        {subgraph.edges.slice(0, 50).map((e, i) => {
                                            const srcNode = subgraph.nodes.find(n => n.id === e.source)
                                            const dstNode = subgraph.nodes.find(n => n.id === e.target)
                                            const isThis = e.event_id === selected.event_id
                                            const srcName = shortName(srcNode?.name || '', srcNode?.label || '')
                                            const dstName = shortName(dstNode?.name || '', dstNode?.label || '')
                                            const detail = edgeDetail(e)
                                            return (
                                                <div key={i} style={{
                                                    padding: '5px 8px',
                                                    background: isThis ? 'var(--bg-hover)' : e.ml_alert ? 'rgba(220,38,38,0.06)' : 'var(--bg-secondary)',
                                                    border: `1px solid ${isThis ? 'var(--accent-primary)' : e.ml_alert ? 'rgba(220,38,38,0.3)' : 'var(--border-light)'}`,
                                                    display: 'flex', alignItems: 'center', gap: 6,
                                                }}>
                                                    <EdgeTypeBadge type={e.type} />
                                                    <span style={{ fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-secondary)', flex: 1, minWidth: 0, overflow: 'hidden' }}>
                                                        <span title={srcNode?.name}>{srcName}</span>
                                                        <span style={{ color: 'var(--text-muted)' }}> → </span>
                                                        <span title={dstNode?.name}>{dstName}</span>
                                                        {detail && (
                                                            <span style={{
                                                                marginLeft: 6, color: 'var(--text-muted)',
                                                                fontSize: 10, fontStyle: 'italic',
                                                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                            }} title={detail}>
                                                                {detail}
                                                            </span>
                                                        )}
                                                    </span>
                                                    {e.ml_score !== null && (
                                                        <span style={{
                                                            fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 700,
                                                            color: SEV_COLOR((e.ml_score || 0) * 100),
                                                            minWidth: 44, textAlign: 'right', flexShrink: 0,
                                                        }}>
                                                            {formatPct(e.ml_score || 0)}
                                                        </span>
                                                    )}
                                                    {e.ml_alert && <span style={{ color: 'var(--status-critical)', fontSize: 12, flexShrink: 0 }}>⚠</span>}
                                                </div>
                                            )
                                        })}
                                        {subgraph.edges.length > 50 && (
                                            <div style={{ padding: '4px 8px', fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)' }}>
                                                + {subgraph.edges.length - 50} more…
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ) : (
                                <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-muted)' }}>
                                    Click a row to load its neighbourhood.
                                </div>
                            )}
                        </div>

                        {/* LLM Narrative */}
                        <div style={{ padding: '16px 18px' }}>
                            <div style={{
                                fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                                color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10,
                            }}>LLM Narrative</div>
                            {narrative ? (
                                <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                                    <div style={{ marginBottom: 8 }}>
                                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Hypothesis: </span>
                                        {narrative.attack_hypothesis}
                                    </div>
                                    {narrative.mitre_technique && (
                                        <div style={{ marginBottom: 8 }}>
                                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>MITRE: </span>
                                            {narrative.mitre_technique}
                                        </div>
                                    )}
                                    <div style={{
                                        borderLeft: '3px solid var(--accent-primary)',
                                        paddingLeft: 10, marginTop: 8,
                                    }}>
                                        <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Analyst Action</div>
                                        <div style={{ color: 'var(--text-primary)' }}>{narrative.analyst_action}</div>
                                    </div>
                                    {narrative.agreement_status && narrative.agreement_status !== 'disabled' && (
                                        <div style={{
                                            borderLeft: `3px solid ${
                                                narrative.agreement_status === 'exact' ? '#16a34a' :
                                                narrative.agreement_status === 'parent' ? '#84cc16' :
                                                narrative.agreement_status === 'conflict' ? '#dc2626' :
                                                'var(--text-muted)'
                                            }`,
                                            paddingLeft: 10, marginTop: 8,
                                        }}>
                                            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                                                Second Opinion ({narrative.secondary_model || 'secondary'}) — {narrative.agreement_status}
                                            </div>
                                            {narrative.secondary_mitre && (
                                                <div style={{ color: 'var(--text-primary)', fontSize: 12 }}>
                                                    MITRE: {narrative.secondary_mitre} (confidence: {narrative.secondary_confidence || '?'})
                                                </div>
                                            )}
                                            {narrative.secondary_hypothesis && (
                                                <div style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 2 }}>
                                                    {narrative.secondary_hypothesis}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    {narrative.yara_rule && (
                                        <div style={{
                                            borderLeft: '3px solid var(--accent-warning, #d97706)',
                                            paddingLeft: 10, marginTop: 8,
                                        }}>
                                            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                                                YARA Rule (LLM-generated · deploy to endpoints for live detection)
                                            </div>
                                            <pre style={{
                                                fontFamily: 'var(--font-mono, monospace)',
                                                fontSize: 11,
                                                background: '#0d1117',
                                                padding: 10, borderRadius: 4,
                                                overflow: 'auto',
                                                color: '#e6edf3',
                                                margin: 0,
                                                border: '1px solid #30363d',
                                            }}>{narrative.yara_rule}</pre>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-muted)' }}>
                                    No narrative available. Start the llm-analyzer service with ANTHROPIC_API_KEY to generate incident analysis.
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}
