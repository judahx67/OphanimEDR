import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import axios from 'axios'

// ── Types ──────────────────────────────────────────────────────────────────

interface LabelRow {
    label: string
    scored: number
    flash_seeds: number
    orthrus_scored: number
    orthrus_seeds: number
    both_seeds: number
}

interface Summary {
    per_label: LabelRow[]
    totals: {
        scored: number
        flash_seeds: number
        orthrus_scored: number
        orthrus_seeds: number
        both_seeds: number
    }
    orthrus_active: boolean
}

interface DetectorRow {
    uuid: string
    label: string
    name: string
    flash_seed: boolean
    orthrus_seed: boolean
    orthrus_score: number | null
    orthrus_scored: boolean
}

// ── Constants ──────────────────────────────────────────────────────────────

const NODE_LABEL_COLORS: Record<string, string> = {
    Process: '#eab308', File: '#6366f1', Socket: '#06b6d4',
    Memory: '#f97316', Pipe: '#14b8a6', User: '#f43f5e',
}

const FLASH_COLOR = '#dc2626'   // flood / red
const ORTHRUS_COLOR = '#16a34a' // precise / green

function pct(n: number, d: number): number {
    return d > 0 ? (100 * n) / d : 0
}

// ── Sub-components ─────────────────────────────────────────────────────────

function DetectorHeadline({
    name, sub, color, flags, active,
}: { name: string; sub: string; color: string; flags: number; active: boolean }) {
    return (
        <div style={{
            flex: 1, background: 'var(--bg-card)', border: `2px solid ${color}`,
            padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 6,
        }}>
            <div style={{
                fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
                color, textTransform: 'uppercase', letterSpacing: '0.08em',
            }}>{name}</div>
            <div style={{
                fontFamily: 'var(--font-ui)', fontSize: 40, fontWeight: 700,
                color: 'var(--text-primary)', lineHeight: 1,
            }}>
                {active ? flags.toLocaleString() : '—'}
            </div>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)' }}>
                {active ? `nodes flagged · ${sub}` : 'detector not yet wired'}
            </div>
        </div>
    )
}

/** Horizontal bar showing what fraction of scored nodes of a label each
 *  detector flags. The FLASH bar visualises the flood; Orthrus the precision. */
function LabelContrastRow({ row, orthrusActive }: { row: LabelRow; orthrusActive: boolean }) {
    const flashPct = pct(row.flash_seeds, row.scored)
    const orthrusPct = pct(row.orthrus_seeds, row.scored)
    const labelColor = NODE_LABEL_COLORS[row.label] || '#888'
    return (
        <div style={{
            display: 'grid', gridTemplateColumns: '90px 60px 1fr 1fr',
            gap: 12, alignItems: 'center', padding: '10px 0',
            borderBottom: '1px solid var(--border-light)',
        }}>
            <span style={{
                fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
                color: '#fff', background: labelColor, padding: '3px 8px',
                textTransform: 'uppercase', letterSpacing: '0.04em', textAlign: 'center',
            }}>{row.label}</span>
            <span style={{
                fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-muted)',
                textAlign: 'right',
            }}>{row.scored.toLocaleString()}</span>

            {/* FLASH bar */}
            <Bar pctValue={flashPct} count={row.flash_seeds} color={FLASH_COLOR} active />
            {/* Orthrus bar */}
            <Bar pctValue={orthrusPct} count={row.orthrus_seeds} color={ORTHRUS_COLOR} active={orthrusActive} />
        </div>
    )
}

function Bar({ pctValue, count, color, active }: {
    pctValue: number; count: number; color: string; active: boolean
}) {
    if (!active) {
        return (
            <span style={{ fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)' }}>
                pending
            </span>
        )
    }
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ flex: 1, height: 10, background: 'var(--border-light)', position: 'relative' }}>
                <div style={{
                    position: 'absolute', left: 0, top: 0, height: '100%',
                    width: `${Math.max(pctValue, count > 0 ? 2 : 0)}%`, background: color,
                }} />
            </div>
            <span style={{
                fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
                color, minWidth: 78, textAlign: 'right',
            }}>
                {count.toLocaleString()} ({pctValue.toFixed(1)}%)
            </span>
        </div>
    )
}

function Verdict({ on, label, color }: { on: boolean; label: string; color: string }) {
    return (
        <span style={{
            fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 700,
            padding: '2px 8px', letterSpacing: '0.04em',
            background: on ? color : 'transparent',
            color: on ? '#fff' : 'var(--text-muted)',
            border: `1px solid ${on ? color : 'var(--border-light)'}`,
        }}>{on ? label : '—'}</span>
    )
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function Compare() {
    const [summary, setSummary] = useState<Summary | null>(null)
    const [rows, setRows] = useState<DetectorRow[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        Promise.all([
            axios.get<Summary>('/api/compare/summary'),
            axios.get<DetectorRow[]>('/api/compare/detectors?limit=300&seeds_only=true'),
        ])
            .then(([s, r]) => { setSummary(s.data); setRows(r.data) })
            .catch(e => setError(String(e)))
            .finally(() => setLoading(false))
    }, [])

    if (loading) return <Spinner label="Loading detector comparison…" />
    if (error) return <div style={{ color: FLASH_COLOR }}>Error: {error}</div>
    if (!summary) return null

    const orthrusActive = summary.orthrus_active
    const t = summary.totals

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

            {/* Header */}
            <div>
                <div style={{
                    fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase',
                    letterSpacing: '0.1em', marginBottom: 4,
                    display: 'flex', alignItems: 'center', gap: 6,
                }}>
                    <span style={{ color: 'var(--accent-primary)', fontWeight: 700 }}>//</span>
                    Same-substrate head-to-head
                </div>
                <h1 style={{
                    fontFamily: 'var(--font-sans)', fontSize: 28, fontWeight: 700,
                    color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.02em',
                    margin: 0,
                }}>FLASH vs Orthrus-style (ours)</h1>
                <p style={{
                    fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-secondary)',
                    marginTop: 6, maxWidth: 720, lineHeight: 1.6,
                }}>
                    Both detectors score the <strong>same THEIA E3 provenance graph</strong> ({t.scored.toLocaleString()} nodes).
                    FLASH (GraphSAGE + Word2Vec, explain-away seeds) and our re-implementation of the
                    Orthrus method (GAT encoder + edge-action reconstruction, benign-p99 threshold)
                    distribute their flags differently over identical telemetry — different objectives
                    and operating points, no ground truth on this slice. The per-label flag rate below
                    is the contrast.
                </p>
            </div>

            {/* Detector headlines */}
            <div style={{ display: 'flex', gap: 16 }}>
                <DetectorHeadline
                    name="FLASH (reproduction)" sub="explain-away seeds" color={FLASH_COLOR}
                    flags={t.flash_seeds} active
                />
                <DetectorHeadline
                    name="Orthrus-style (ours)" sub="reconstruction loss" color={ORTHRUS_COLOR}
                    flags={t.orthrus_seeds} active={orthrusActive}
                />
                <div style={{
                    flex: 1, background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
                    padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 6,
                }}>
                    <div style={{
                        fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
                        color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>Agreement</div>
                    <div style={{
                        fontFamily: 'var(--font-ui)', fontSize: 40, fontWeight: 700,
                        color: 'var(--text-primary)', lineHeight: 1,
                    }}>{orthrusActive ? t.both_seeds.toLocaleString() : '—'}</div>
                    <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)' }}>
                        {orthrusActive ? 'nodes flagged by both' : 'awaiting Orthrus-style scorer'}
                    </div>
                </div>
            </div>

            {/* Per-label contrast */}
            <div style={{
                background: 'var(--bg-card)', border: '2px solid var(--border-strong)', padding: '18px 20px',
            }}>
                <div style={{
                    fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
                    marginBottom: 4,
                }}>Flag rate by node type</div>
                <p style={{ fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)', marginTop: 0, marginBottom: 12 }}>
                    Fraction of each node type each detector raises to the analyst. A long red
                    bar = flood; a short green bar = precision.
                </p>
                {/* column headers */}
                <div style={{
                    display: 'grid', gridTemplateColumns: '90px 60px 1fr 1fr', gap: 12,
                    paddingBottom: 8, borderBottom: '2px solid var(--border-strong)',
                    fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 700,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em',
                }}>
                    <span>Type</span>
                    <span style={{ textAlign: 'right' }}>Scored</span>
                    <span style={{ color: FLASH_COLOR }}>FLASH flags</span>
                    <span style={{ color: ORTHRUS_COLOR }}>Orthrus-style flags</span>
                </div>
                {summary.per_label.map(row => (
                    <LabelContrastRow key={row.label} row={row} orthrusActive={orthrusActive} />
                ))}
            </div>

            {/* Per-node table */}
            <div style={{
                background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
            }}>
                <div style={{
                    padding: '14px 18px', borderBottom: '1px solid var(--border-light)',
                    fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 600,
                    color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
                }}>Flagged nodes ({rows.length})</div>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr style={{ borderBottom: '2px solid var(--border-strong)' }}>
                            {['Type', 'Node', 'FLASH', 'Orthrus-style', 'score'].map(h => (
                                <th key={h} style={{
                                    padding: '10px 14px', textAlign: 'left',
                                    fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600,
                                    color: 'var(--text-muted)', textTransform: 'uppercase',
                                    letterSpacing: '0.06em', whiteSpace: 'nowrap',
                                }}>{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((r, i) => (
                            <tr key={r.uuid || i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                                <td style={{ padding: '8px 14px' }}>
                                    <span style={{
                                        fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 700,
                                        color: '#fff', background: NODE_LABEL_COLORS[r.label] || '#888',
                                        padding: '2px 7px',
                                    }}>{r.label}</span>
                                </td>
                                <td style={{
                                    padding: '8px 14px', fontFamily: 'var(--font-ui)', fontSize: 12,
                                    color: 'var(--text-primary)', maxWidth: 360, overflow: 'hidden',
                                    textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                }} title={`${r.name}\n${r.uuid}`}>{r.name}</td>
                                <td style={{ padding: '8px 14px' }}>
                                    <Verdict on={r.flash_seed} label="FLAG" color={FLASH_COLOR} />
                                </td>
                                <td style={{ padding: '8px 14px' }}>
                                    {r.orthrus_scored
                                        ? <Verdict on={r.orthrus_seed} label="FLAG" color={ORTHRUS_COLOR} />
                                        : <span style={{ fontFamily: 'var(--font-ui)', fontSize: 10, color: 'var(--text-muted)' }}>pending</span>}
                                </td>
                                <td style={{
                                    padding: '8px 14px', fontFamily: 'var(--font-ui)', fontSize: 11,
                                    color: 'var(--text-secondary)',
                                }}>
                                    {r.orthrus_score != null ? r.orthrus_score.toFixed(4) : '—'}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
