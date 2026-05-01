import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import axios from 'axios'

interface MLScore {
    uuid: string
    name: string
    score: number
    top_tactic: string | null
    tactic_scores: Record<string, number>
    incident_count: number
}

interface MLSummary {
    scored: number
    mean: number
    max: number
    high: number
}

const TACTICS = [
    'execution',
    'persistence',
    'privilege_escalation',
    'defense_evasion',
    'credential_access',
    'discovery',
    'lateral_movement',
    'collection',
    'command_and_control',
    'exfiltration',
    'impact',
]

const TACTIC_SHORT: Record<string, string> = {
    execution: 'EXEC',
    persistence: 'PERS',
    privilege_escalation: 'PRIV',
    defense_evasion: 'EVAD',
    credential_access: 'CRED',
    discovery: 'DISC',
    lateral_movement: 'LAT',
    collection: 'COLL',
    command_and_control: 'C2',
    exfiltration: 'EXFIL',
    impact: 'IMP',
}

const TACTIC_COLOR: Record<string, string> = {
    execution: '#dc2626',
    persistence: '#7c3aed',
    privilege_escalation: '#db2777',
    defense_evasion: '#0891b2',
    credential_access: '#ea580c',
    discovery: '#65a30d',
    lateral_movement: '#0284c7',
    collection: '#ca8a04',
    command_and_control: '#9333ea',
    exfiltration: '#e11d48',
    impact: '#525252',
}

function scoreColor(s: number): string {
    if (s >= 0.8) return '#dc2626'
    if (s >= 0.5) return '#ea580c'
    if (s >= 0.2) return '#ca8a04'
    return '#16a34a'
}

function TacticBars({ scores }: { scores: Record<string, number> }) {
    return (
        <div style={{ display: 'flex', gap: '2px', height: '22px', alignItems: 'flex-end' }}>
            {TACTICS.map(t => {
                const s = scores[t] ?? 0
                const h = Math.max(2, Math.round(s * 22))
                return (
                    <div
                        key={t}
                        title={`${t}: ${s.toFixed(3)}`}
                        style={{
                            width: '14px',
                            height: `${h}px`,
                            background: TACTIC_COLOR[t] || '#888',
                            opacity: 0.3 + 0.7 * s,
                        }}
                    />
                )
            })}
        </div>
    )
}

function MLScores() {
    const [scores, setScores] = useState<MLScore[]>([])
    const [summary, setSummary] = useState<MLSummary | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        Promise.all([
            axios.get<MLScore[]>('/api/ml/scores?limit=100'),
            axios.get<MLSummary>('/api/ml/summary'),
        ])
            .then(([s, sum]) => {
                setScores(s.data)
                setSummary(sum.data)
            })
            .catch(e => setError(String(e)))
            .finally(() => setLoading(false))
    }, [])

    if (loading) return <Spinner label="Loading ML scores…" />
    if (error) return <div style={{ color: '#dc2626' }}>Error: {error}</div>

    const pageStyles = {
        title: {
            fontFamily: 'var(--font-ui)', fontSize: '24px', fontWeight: 700,
            marginBottom: '8px', color: 'var(--text-primary)',
        },
        subtitle: {
            fontFamily: 'var(--font-sans)', fontSize: '13px',
            color: 'var(--text-muted)', marginBottom: '24px',
        },
        statsRow: {
            display: 'flex', gap: '16px', marginBottom: '24px',
        },
        statCard: {
            flex: 1, padding: '16px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-strong)',
        },
        statLabel: {
            fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 600,
            textTransform: 'uppercase' as const, letterSpacing: '0.1em',
            color: 'var(--text-muted)', marginBottom: '4px',
        },
        statValue: {
            fontFamily: 'var(--font-ui)', fontSize: '22px', fontWeight: 700,
            color: 'var(--text-primary)',
        },
        legend: {
            display: 'flex', flexWrap: 'wrap' as const, gap: '8px',
            marginBottom: '16px', fontSize: '11px',
            fontFamily: 'var(--font-ui)',
        },
        legendItem: (color: string): React.CSSProperties => ({
            display: 'flex', alignItems: 'center', gap: '4px',
            padding: '2px 6px',
            background: 'var(--bg-card)',
            border: `1px solid ${color}`,
            color: 'var(--text-secondary)',
        }),
        legendSwatch: (color: string): React.CSSProperties => ({
            width: '10px', height: '10px', background: color,
        }),
        table: {
            width: '100%', borderCollapse: 'collapse' as const,
            background: 'var(--bg-card)',
            border: '1px solid var(--border-strong)',
        },
        th: {
            padding: '10px 12px', textAlign: 'left' as const,
            fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600,
            textTransform: 'uppercase' as const, letterSpacing: '0.05em',
            color: 'var(--text-muted)',
            borderBottom: '1px solid var(--border-strong)',
        },
        td: {
            padding: '10px 12px', fontFamily: 'var(--font-sans)', fontSize: '13px',
            borderBottom: '1px solid var(--border-light)',
            color: 'var(--text-primary)',
            verticalAlign: 'middle' as const,
        },
        scorePill: (s: number) => ({
            display: 'inline-block', padding: '3px 10px',
            fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 700,
            background: scoreColor(s), color: '#fff',
            minWidth: '48px', textAlign: 'center' as const,
        }),
        tacticPill: (tactic: string | null) => ({
            display: 'inline-block', padding: '3px 8px',
            fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 700,
            background: tactic ? TACTIC_COLOR[tactic] || '#888' : '#888',
            color: '#fff',
            textTransform: 'uppercase' as const, letterSpacing: '0.05em',
        }),
    }

    return (
        <div>
            <div style={pageStyles.title}>ML Scores — MITRE Tactic Intent</div>
            <div style={pageStyles.subtitle}>
                Per-process AutoGluon multi-label classification. Each row shows the predicted
                probability of activity in each of 11 MITRE ATT&amp;CK tactics. Trained on graph
                features with rule-engine incidents as weak labels.
            </div>

            {summary && (
                <div style={pageStyles.statsRow}>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>Scored Processes</div>
                        <div style={pageStyles.statValue}>{summary.scored}</div>
                    </div>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>Mean Top-Score</div>
                        <div style={pageStyles.statValue}>{summary.mean.toFixed(3)}</div>
                    </div>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>Max Top-Score</div>
                        <div style={pageStyles.statValue}>{summary.max.toFixed(3)}</div>
                    </div>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>High Risk (≥0.5)</div>
                        <div style={pageStyles.statValue}>{summary.high}</div>
                    </div>
                </div>
            )}

            <div style={pageStyles.legend}>
                {TACTICS.map(t => (
                    <div key={t} style={pageStyles.legendItem(TACTIC_COLOR[t])}>
                        <div style={pageStyles.legendSwatch(TACTIC_COLOR[t])} />
                        <span>{TACTIC_SHORT[t]} — {t}</span>
                    </div>
                ))}
            </div>

            {scores.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No ML scores yet. Run the ml-engine:
                    <pre style={{ marginTop: '12px', fontSize: '12px' }}>
                        docker compose --profile ml run --rm ml-engine
                    </pre>
                </div>
            ) : (
                <table style={pageStyles.table}>
                    <thead>
                        <tr>
                            <th style={pageStyles.th}>Top Score</th>
                            <th style={pageStyles.th}>Top Tactic</th>
                            <th style={pageStyles.th}>Tactic Profile</th>
                            <th style={pageStyles.th}>Process</th>
                            <th style={pageStyles.th}>UUID</th>
                            <th style={pageStyles.th}>Incidents</th>
                        </tr>
                    </thead>
                    <tbody>
                        {scores.map(s => (
                            <tr key={s.uuid}>
                                <td style={pageStyles.td}>
                                    <span style={pageStyles.scorePill(s.score)}>
                                        {s.score.toFixed(3)}
                                    </span>
                                </td>
                                <td style={pageStyles.td}>
                                    <span style={pageStyles.tacticPill(s.top_tactic)}>
                                        {s.top_tactic ? TACTIC_SHORT[s.top_tactic] || s.top_tactic : '—'}
                                    </span>
                                </td>
                                <td style={pageStyles.td}>
                                    <TacticBars scores={s.tactic_scores} />
                                </td>
                                <td style={pageStyles.td}>{s.name || '(unnamed)'}</td>
                                <td style={{ ...pageStyles.td, fontFamily: 'var(--font-ui)', fontSize: '11px', color: 'var(--text-muted)' }}>
                                    {s.uuid.slice(0, 16)}…
                                </td>
                                <td style={pageStyles.td}>{s.incident_count}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    )
}

export default MLScores
