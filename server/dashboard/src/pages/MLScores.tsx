import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import axios from 'axios'

interface MLScore {
    uuid: string
    name: string
    score: number
    incident_count: number
}

interface MLSummary {
    scored: number
    mean: number
    max: number
    high: number
}

function scoreColor(s: number): string {
    if (s >= 0.8) return '#dc2626'
    if (s >= 0.5) return '#ea580c'
    if (s >= 0.2) return '#ca8a04'
    return '#16a34a'
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
        },
        scorePill: (s: number) => ({
            display: 'inline-block', padding: '3px 10px',
            fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 700,
            background: scoreColor(s), color: '#fff',
            minWidth: '48px', textAlign: 'center' as const,
        }),
    }

    return (
        <div>
            <div style={pageStyles.title}>ML Scores</div>
            <div style={pageStyles.subtitle}>
                Per-process XGBoost probability of being malicious. Trained on graph features
                using rule-engine incidents as positive labels.
            </div>

            {summary && (
                <div style={pageStyles.statsRow}>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>Scored Processes</div>
                        <div style={pageStyles.statValue}>{summary.scored}</div>
                    </div>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>Mean Score</div>
                        <div style={pageStyles.statValue}>{summary.mean.toFixed(3)}</div>
                    </div>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>Max Score</div>
                        <div style={pageStyles.statValue}>{summary.max.toFixed(3)}</div>
                    </div>
                    <div style={pageStyles.statCard}>
                        <div style={pageStyles.statLabel}>High Risk (≥0.5)</div>
                        <div style={pageStyles.statValue}>{summary.high}</div>
                    </div>
                </div>
            )}

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
                            <th style={pageStyles.th}>Score</th>
                            <th style={pageStyles.th}>Process Name</th>
                            <th style={pageStyles.th}>UUID</th>
                            <th style={pageStyles.th}>Rule Incidents</th>
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
