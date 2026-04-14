import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import {
    Warning24Regular,
    ArrowTrendingLines24Regular,
    Shield24Regular,
    DataUsage24Regular,
} from '@fluentui/react-icons'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts'

interface GraphStats {
    node_counts: Record<string, number>
    total_edges: number
    total_incidents: number
    new_incidents: number
    process_count: number
    file_count: number
    socket_count: number
}

interface IncidentStats {
    total: number
    new: number
    investigating: number
    resolved: number
    by_severity: Record<string, number>
}

const styles = {
    container: { display: 'flex', flexDirection: 'column' as const, gap: '24px' },
    pageHeader: {
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
    },
    sectionPrefix: {
        fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600,
        color: 'var(--text-muted)', textTransform: 'uppercase' as const,
        letterSpacing: '0.1em', marginBottom: '4px',
        display: 'flex', alignItems: 'center', gap: '6px',
    },
    prefixSlash: { color: 'var(--accent-primary)', fontWeight: 700 },
    title: {
        fontFamily: 'var(--font-sans)', fontSize: '28px', fontWeight: 700,
        color: 'var(--text-primary)', textTransform: 'uppercase' as const,
        letterSpacing: '0.02em',
    },
    statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' },
    statCard: {
        background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
        padding: '20px', display: 'flex', flexDirection: 'column' as const, gap: '12px',
    },
    statCardAccent: {
        background: 'var(--accent-primary)', border: '2px solid var(--accent-primary)',
        padding: '20px', display: 'flex', flexDirection: 'column' as const, gap: '12px',
    },
    statHeader: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
    statLabel: {
        fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600,
        color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.08em',
    },
    statLabelDark: {
        fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600,
        color: 'rgba(0,0,0,0.5)', textTransform: 'uppercase' as const, letterSpacing: '0.08em',
    },
    statIcon: { color: 'var(--text-muted)', fontSize: '20px' },
    statIconDark: { color: 'rgba(0,0,0,0.5)', fontSize: '20px' },
    statValue: {
        fontFamily: 'var(--font-ui)', fontSize: '36px', fontWeight: 700,
        color: 'var(--text-primary)', lineHeight: 1,
    },
    statValueDark: {
        fontFamily: 'var(--font-ui)', fontSize: '36px', fontWeight: 700,
        color: '#0a0a0a', lineHeight: 1,
    },
    alertBanner: {
        background: 'var(--status-critical)', border: '2px solid var(--status-critical)',
        padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', color: '#ffffff',
    },
    alertTitle: {
        fontFamily: 'var(--font-ui)', fontSize: '13px', fontWeight: 700,
        textTransform: 'uppercase' as const, letterSpacing: '0.05em',
    },
    alertBtn: {
        padding: '8px 16px', background: '#ffffff', border: 'none',
        color: 'var(--status-critical)', fontFamily: 'var(--font-ui)',
        fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' as const,
        letterSpacing: '0.05em', cursor: 'pointer',
    },
    chartsGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' },
    chartCard: {
        background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
        display: 'flex', flexDirection: 'column' as const,
    },
    chartHeader: {
        padding: '16px 20px', borderBottom: '1px solid var(--border-light)',
        display: 'flex', alignItems: 'center', gap: '8px',
    },
    chartPrefix: { color: 'var(--accent-primary)', fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px' },
    chartTitle: {
        fontFamily: 'var(--font-ui)', fontSize: '12px', fontWeight: 600,
        color: 'var(--text-primary)', textTransform: 'uppercase' as const, letterSpacing: '0.08em',
    },
    chartBody: { padding: '20px', height: '280px' },
    loading: {
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        height: '400px', flexDirection: 'column' as const, gap: '16px',
    },
    loadingText: {
        fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)',
        textTransform: 'uppercase' as const, letterSpacing: '0.1em',
    },
}

function Dashboard() {
    const [graphStats, setGraphStats] = useState<GraphStats | null>(null)
    const [incStats, setIncStats] = useState<IncidentStats | null>(null)
    const [loading, setLoading] = useState(true)
    const navigate = useNavigate()

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const [graphRes, incRes] = await Promise.all([
                    axios.get('/api/graph/stats'),
                    axios.get('/api/incidents/stats'),
                ])
                setGraphStats(graphRes.data)
                setIncStats(incRes.data)
            } catch (err) {
                console.error('Failed to fetch stats:', err)
                // Leave as null — the UI shows zeros
            } finally {
                setLoading(false)
            }
        }
        fetchStats()
        const iv = setInterval(fetchStats, 15000)
        return () => clearInterval(iv)
    }, [])

    if (loading) {
        return (
            <div style={styles.loading}>
                <Spinner size="large" />
                <span style={styles.loadingText}>Loading Dashboard...</span>
            </div>
        )
    }

    // Node type bar chart data
    const nodeData = graphStats
        ? Object.entries(graphStats.node_counts)
              .filter(([, v]) => v > 0)
              .map(([label, count]) => ({ label, count }))
              .sort((a, b) => b.count - a.count)
        : []

    // Severity breakdown bar chart
    const severityData = incStats?.by_severity
        ? Object.entries(incStats.by_severity)
              .map(([sev, count]) => ({ sev: sev.toUpperCase(), count }))
        : []

    const newAlerts = incStats?.new ?? 0

    return (
        <div style={styles.container}>
            {/* Header */}
            <div style={styles.pageHeader}>
                <div>
                    <div style={styles.sectionPrefix}>
                        <span style={styles.prefixSlash}>//</span>
                        <span>System Overview</span>
                    </div>
                    <h1 style={styles.title}>Dashboard</h1>
                </div>
            </div>

            {/* Alert banner */}
            {newAlerts > 0 && (
                <div style={styles.alertBanner}>
                    <Warning24Regular style={{ fontSize: '24px' }} />
                    <div style={{ flex: 1 }}>
                        <div style={styles.alertTitle}>
                            {newAlerts} New Incident{newAlerts > 1 ? 's' : ''} — Requires Investigation
                        </div>
                    </div>
                    <button style={styles.alertBtn} onClick={() => navigate('/incidents')}>
                        View Incidents
                    </button>
                </div>
            )}

            {/* Stats grid */}
            <div style={styles.statsGrid}>
                <div style={styles.statCard}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabel}>Total Nodes</span>
                        <DataUsage24Regular style={styles.statIcon} />
                    </div>
                    <span style={styles.statValue}>
                        {Object.values(graphStats?.node_counts ?? {}).reduce((a, b) => a + b, 0).toLocaleString()}
                    </span>
                </div>

                <div style={styles.statCardAccent}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabelDark}>Total Edges</span>
                        <ArrowTrendingLines24Regular style={styles.statIconDark} />
                    </div>
                    <span style={styles.statValueDark}>
                        {(graphStats?.total_edges ?? 0).toLocaleString()}
                    </span>
                </div>

                <div style={styles.statCard}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabel}>Incidents</span>
                        <Shield24Regular style={styles.statIcon} />
                    </div>
                    <span style={styles.statValue}>{incStats?.total ?? 0}</span>
                </div>

                <div style={{
                    ...styles.statCard,
                    ...(newAlerts > 0 ? { borderColor: 'var(--status-critical)' } : {}),
                }}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabel}>New Alerts</span>
                        <Warning24Regular style={{
                            ...styles.statIcon,
                            ...(newAlerts > 0 ? { color: 'var(--status-critical)' } : {}),
                        }} />
                    </div>
                    <span style={{
                        ...styles.statValue,
                        ...(newAlerts > 0 ? { color: 'var(--status-critical)' } : {}),
                    }}>
                        {newAlerts}
                    </span>
                </div>
            </div>

            {/* Charts */}
            <div style={styles.chartsGrid}>
                {/* Node type breakdown */}
                <div style={styles.chartCard}>
                    <div style={styles.chartHeader}>
                        <span style={styles.chartPrefix}>//</span>
                        <span style={styles.chartTitle}>Graph Node Types</span>
                    </div>
                    <div style={styles.chartBody}>
                        {nodeData.length === 0 ? (
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                                <span style={{ fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)' }}>
                                    No graph data — run the simulator
                                </span>
                            </div>
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={nodeData} layout="vertical">
                                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" horizontal={false} />
                                    <XAxis
                                        type="number"
                                        tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-ui)' }}
                                        axisLine={{ stroke: 'var(--border-medium)' }}
                                    />
                                    <YAxis
                                        type="category"
                                        dataKey="label"
                                        tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-ui)' }}
                                        axisLine={{ stroke: 'var(--border-medium)' }}
                                        width={72}
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
                                            borderRadius: 0, fontFamily: 'var(--font-ui)', fontSize: '12px',
                                        }}
                                    />
                                    <Bar dataKey="count" fill="var(--accent-primary)" />
                                </BarChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </div>

                {/* Incident severity breakdown */}
                <div style={styles.chartCard}>
                    <div style={styles.chartHeader}>
                        <span style={styles.chartPrefix}>//</span>
                        <span style={styles.chartTitle}>Incidents by Severity</span>
                        <Shield24Regular style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '16px' }} />
                    </div>
                    <div style={styles.chartBody}>
                        {severityData.length === 0 ? (
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                                <span style={{ fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)' }}>
                                    No incidents yet
                                </span>
                            </div>
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={severityData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
                                    <XAxis
                                        dataKey="sev"
                                        tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-ui)' }}
                                        axisLine={{ stroke: 'var(--border-medium)' }}
                                    />
                                    <YAxis
                                        tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-ui)' }}
                                        axisLine={{ stroke: 'var(--border-medium)' }}
                                        allowDecimals={false}
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            background: 'var(--bg-card)', border: '2px solid var(--border-strong)',
                                            borderRadius: 0, fontFamily: 'var(--font-ui)', fontSize: '12px',
                                        }}
                                    />
                                    <Bar dataKey="count" fill="var(--status-critical)" />
                                </BarChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Dashboard
