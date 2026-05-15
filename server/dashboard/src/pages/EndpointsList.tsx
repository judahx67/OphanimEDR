import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import {
    Desktop24Regular,
    Warning24Regular,
    ArrowTrendingLines24Regular,
    Shield24Regular,
} from '@fluentui/react-icons'
import axios from 'axios'

interface GraphEndpoint {
    endpoint_id: string
    node_count: number
    edge_count: number
    incident_count: number
    new_incidents: number
    last_seen: number | null   // nanoseconds timestamp from Neo4j
}

function formatLastSeen(ns: number | null): string {
    if (!ns) return '—'
    const ms = ns / 1_000_000
    const diff = Date.now() - ms
    const s = Math.floor(diff / 1000)
    if (s < 60) return `${s}s ago`
    if (s < 3600) return `${Math.floor(s / 60)}m ago`
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`
    return new Date(ms).toLocaleDateString()
}

function EndpointsList() {
    const [endpoints, setEndpoints] = useState<GraphEndpoint[]>([])
    const [loading, setLoading] = useState(true)
    const [hoveredRow, setHoveredRow] = useState<string | null>(null)

    useEffect(() => {
        const fetch = async () => {
            try {
                const res = await axios.get('/api/graph/endpoints')
                setEndpoints(res.data || [])
            } catch (err) {
                console.error('Failed to fetch graph endpoints:', err)
            } finally {
                setLoading(false)
            }
        }
        fetch()
        const iv = setInterval(fetch, 15000)
        return () => clearInterval(iv)
    }, [])

    if (loading) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px', flexDirection: 'column' as const, gap: '16px' }}>
                <Spinner size="large" />
                <span style={{ fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.1em' }}>
                    Loading...
                </span>
            </div>
        )
    }

    const S = {
        container: { display: 'flex', flexDirection: 'column' as const, gap: '24px' },
        header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' },
        prefix: { fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.1em', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' },
        slash: { color: 'var(--accent-primary)', fontWeight: 700 },
        title: { fontFamily: 'var(--font-sans)', fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' as const, letterSpacing: '0.02em' },
        badge: { display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '8px 16px', background: 'var(--bg-card)', border: '2px solid var(--border-strong)', fontFamily: 'var(--font-ui)', fontSize: '12px', fontWeight: 600 },
        badgeNum: { color: 'var(--accent-primary)', fontSize: '16px', fontWeight: 700 },
        tableCard: { background: 'var(--bg-card)', border: '2px solid var(--border-strong)', overflow: 'hidden' },
        tableHead: { padding: '16px 20px', background: 'var(--bg-dark)', color: 'var(--text-inverse)', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-ui)', fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em' },
        headPrefix: { color: 'var(--accent-primary)', fontWeight: 700 },
        table: { width: '100%', borderCollapse: 'collapse' as const },
        th: { padding: '12px 20px', textAlign: 'left' as const, fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.08em', borderBottom: '2px solid var(--border-strong)', background: 'var(--bg-secondary)' },
        td: { padding: '14px 20px', borderBottom: '1px solid var(--border-light)', fontFamily: 'var(--font-ui)', fontSize: '13px', color: 'var(--text-primary)' },
        empty: { textAlign: 'center' as const, padding: '80px 40px' },
        emptyTitle: { fontFamily: 'var(--font-ui)', fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase' as const, marginBottom: '8px' },
        emptyText: { fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)' },
    }

    return (
        <div style={S.container}>
            <div style={S.header}>
                <div>
                    <div style={S.prefix}><span style={S.slash}>//</span><span>Provenance Graph</span></div>
                    <h1 style={S.title}>Endpoints</h1>
                </div>
                <div style={S.badge}>
                    <span>Sources</span>
                    <span style={S.badgeNum}>{endpoints.length}</span>
                </div>
            </div>

            <div style={S.tableCard}>
                <div style={S.tableHead}>
                    <span style={S.headPrefix}>//</span>
                    <span>Graph Sources</span>
                </div>

                {endpoints.length === 0 ? (
                    <div style={S.empty}>
                        <div style={S.emptyTitle}>No graph data yet</div>
                        <div style={S.emptyText}>Run the simulator to replay BOTSv2 events into the pipeline.</div>
                    </div>
                ) : (
                    <table style={S.table}>
                        <thead>
                            <tr>
                                <th style={S.th}>Endpoint ID</th>
                                <th style={S.th}>Nodes</th>
                                <th style={S.th}>Edges</th>
                                <th style={S.th}>Incidents</th>
                                <th style={S.th}>New Alerts</th>
                                <th style={S.th}>Last Activity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {endpoints.map(ep => (
                                <tr
                                    key={ep.endpoint_id}
                                    style={{
                                        background: hoveredRow === ep.endpoint_id ? 'var(--bg-secondary)' : 'transparent',
                                        cursor: 'default',
                                        borderLeft: ep.new_incidents > 0 ? '3px solid var(--status-critical)' : '3px solid transparent',
                                    }}
                                    onMouseEnter={() => setHoveredRow(ep.endpoint_id)}
                                    onMouseLeave={() => setHoveredRow(null)}
                                >
                                    <td style={S.td}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                            <Desktop24Regular style={{ color: 'var(--text-muted)', fontSize: '18px' }} />
                                            <span style={{ fontWeight: 700 }}>{ep.endpoint_id}</span>
                                        </div>
                                    </td>
                                    <td style={S.td}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <ArrowTrendingLines24Regular style={{ color: 'var(--text-muted)', fontSize: '14px' }} />
                                            {ep.node_count.toLocaleString()}
                                        </div>
                                    </td>
                                    <td style={S.td}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <ArrowTrendingLines24Regular style={{ color: 'var(--accent-primary)', fontSize: '14px' }} />
                                            {ep.edge_count.toLocaleString()}
                                        </div>
                                    </td>
                                    <td style={S.td}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <Shield24Regular style={{ color: ep.incident_count > 0 ? 'var(--status-warning)' : 'var(--text-muted)', fontSize: '14px' }} />
                                            {ep.incident_count}
                                        </div>
                                    </td>
                                    <td style={S.td}>
                                        {ep.new_incidents > 0 ? (
                                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '3px 10px', background: 'var(--status-critical)', color: '#fff', fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 700 }}>
                                                <Warning24Regular style={{ fontSize: '12px' }} />
                                                {ep.new_incidents}
                                            </span>
                                        ) : (
                                            <span style={{ color: 'var(--text-muted)' }}>—</span>
                                        )}
                                    </td>
                                    <td style={{ ...S.td, color: 'var(--text-muted)' }}>
                                        {formatLastSeen(ep.last_seen)}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    )
}

export default EndpointsList
