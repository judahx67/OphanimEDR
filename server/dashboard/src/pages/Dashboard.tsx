import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import {
    Desktop24Regular,
    Warning24Regular,
    Checkmark24Regular,
    ArrowTrendingLines24Regular,
    Shield24Regular,
} from '@fluentui/react-icons'
import axios from 'axios'
import {
    BarChart,
    Bar,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts'

interface DashboardStats {
    totalEndpoints: number
    onlineEndpoints: number
    offlineEndpoints: number
    eventsToday: number
    criticalAlerts: number
}

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '24px',
    },
    pageHeader: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
    },
    titleSection: {},
    sectionPrefix: {
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.1em',
        marginBottom: '4px',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
    },
    prefixSlash: {
        color: 'var(--accent-primary)',
        fontWeight: 700,
    },
    title: {
        fontFamily: 'var(--font-sans)',
        fontSize: '28px',
        fontWeight: 700,
        color: 'var(--text-primary)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.02em',
    },
    statsGrid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '16px',
    },
    statCard: {
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '12px',
        position: 'relative' as const,
    },
    statCardAccent: {
        background: 'var(--accent-primary)',
        border: '2px solid var(--accent-primary)',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '12px',
        position: 'relative' as const,
    },
    statHeader: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
    },
    statLabel: {
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    statLabelDark: {
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'rgba(0,0,0,0.5)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    statIcon: {
        color: 'var(--text-muted)',
        fontSize: '20px',
    },
    statIconDark: {
        color: 'rgba(0,0,0,0.5)',
        fontSize: '20px',
    },
    statValue: {
        fontFamily: 'var(--font-mono)',
        fontSize: '36px',
        fontWeight: 700,
        color: 'var(--text-primary)',
        lineHeight: 1,
    },
    statValueDark: {
        fontFamily: 'var(--font-mono)',
        fontSize: '36px',
        fontWeight: 700,
        color: '#0a0a0a',
        lineHeight: 1,
    },
    alertBanner: {
        background: 'var(--status-critical)',
        border: '2px solid var(--status-critical)',
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        color: '#ffffff',
    },
    alertIcon: {
        fontSize: '24px',
    },
    alertText: {
        flex: 1,
    },
    alertTitle: {
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    alertBtn: {
        padding: '8px 16px',
        background: '#ffffff',
        border: 'none',
        color: 'var(--status-critical)',
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
        cursor: 'pointer',
    },
    chartsGrid: {
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '16px',
    },
    chartCard: {
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        display: 'flex',
        flexDirection: 'column' as const,
    },
    chartHeader: {
        padding: '16px 20px',
        borderBottom: '1px solid var(--border-light)',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
    chartPrefix: {
        color: 'var(--accent-primary)',
        fontFamily: 'var(--font-mono)',
        fontWeight: 700,
        fontSize: '12px',
    },
    chartTitle: {
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        fontWeight: 600,
        color: 'var(--text-primary)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    chartBody: {
        padding: '20px',
        height: '280px',
    },
    loading: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '400px',
        flexDirection: 'column' as const,
        gap: '16px',
    },
    loadingText: {
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.1em',
    },
}

function Dashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null)
    const [eventsData, setEventsData] = useState<{ day: string; events: number }[]>([])
    const [trendData, setTrendData] = useState<{ date: string; detections: number }[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const [endpointsRes, detectionsRes] = await Promise.all([
                    axios.get('/api/endpoints'),
                    axios.get('/api/detections/stats'),
                ])

                const endpoints = endpointsRes.data.endpoints || []
                const online = endpoints.filter((e: any) => e.status === 'online').length
                const eventsTotal = endpoints.reduce((sum: number, e: any) => sum + (e.events_today || 0), 0)

                setStats({
                    totalEndpoints: endpoints.length,
                    onlineEndpoints: online,
                    offlineEndpoints: endpoints.length - online,
                    eventsToday: eventsTotal,
                    criticalAlerts: detectionsRes.data.new || 0,
                })

                // Simulate weekly events data
                const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                setEventsData(days.map(day => ({
                    day,
                    events: Math.floor(Math.random() * 5000) + 1000,
                })))

                // Simulate detection trend
                setTrendData(days.map((day, i) => ({
                    date: day,
                    detections: Math.floor(Math.random() * 5) + (i === 6 ? 3 : 1),
                })))

            } catch (error) {
                console.error('Failed to fetch stats:', error)
                setStats({
                    totalEndpoints: 0,
                    onlineEndpoints: 0,
                    offlineEndpoints: 0,
                    eventsToday: 0,
                    criticalAlerts: 0,
                })
            } finally {
                setLoading(false)
            }
        }

        fetchStats()
        const interval = setInterval(fetchStats, 30000)
        return () => clearInterval(interval)
    }, [])

    if (loading) {
        return (
            <div style={styles.loading}>
                <Spinner size="large" />
                <span style={styles.loadingText}>Loading Dashboard...</span>
            </div>
        )
    }

    return (
        <div style={styles.container}>
            {/* Page Header */}
            <div style={styles.pageHeader}>
                <div style={styles.titleSection}>
                    <div style={styles.sectionPrefix}>
                        <span style={styles.prefixSlash}>//</span>
                        <span>System Overview</span>
                    </div>
                    <h1 style={styles.title}>Dashboard</h1>
                </div>
            </div>

            {/* Alert Banner */}
            {stats && stats.criticalAlerts > 0 && (
                <div style={styles.alertBanner}>
                    <Warning24Regular style={styles.alertIcon} />
                    <div style={styles.alertText}>
                        <div style={styles.alertTitle}>
                            {stats.criticalAlerts} Active Detection{stats.criticalAlerts > 1 ? 's' : ''} — Requires Investigation
                        </div>
                    </div>
                    <button style={styles.alertBtn}>View Detections</button>
                </div>
            )}

            {/* Stats Grid */}
            <div style={styles.statsGrid}>
                <div style={styles.statCard}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabel}>Total Endpoints</span>
                        <Desktop24Regular style={styles.statIcon} />
                    </div>
                    <span style={styles.statValue}>{stats?.totalEndpoints || 0}</span>
                </div>

                <div style={styles.statCardAccent}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabelDark}>Online</span>
                        <Checkmark24Regular style={styles.statIconDark} />
                    </div>
                    <span style={styles.statValueDark}>{stats?.onlineEndpoints || 0}</span>
                </div>

                <div style={styles.statCard}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabel}>Offline</span>
                        <Warning24Regular style={styles.statIcon} />
                    </div>
                    <span style={styles.statValue}>{stats?.offlineEndpoints || 0}</span>
                </div>

                <div style={styles.statCard}>
                    <div style={styles.statHeader}>
                        <span style={styles.statLabel}>Events Today</span>
                        <ArrowTrendingLines24Regular style={styles.statIcon} />
                    </div>
                    <span style={styles.statValue}>{stats?.eventsToday?.toLocaleString() || '0'}</span>
                </div>
            </div>

            {/* Charts Grid */}
            <div style={styles.chartsGrid}>
                {/* Events This Week */}
                <div style={styles.chartCard}>
                    <div style={styles.chartHeader}>
                        <span style={styles.chartPrefix}>//</span>
                        <span style={styles.chartTitle}>Events This Week</span>
                    </div>
                    <div style={styles.chartBody}>
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={eventsData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
                                <XAxis
                                    dataKey="day"
                                    tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                                    axisLine={{ stroke: 'var(--border-medium)' }}
                                />
                                <YAxis
                                    tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                                    axisLine={{ stroke: 'var(--border-medium)' }}
                                />
                                <Tooltip
                                    contentStyle={{
                                        background: 'var(--bg-card)',
                                        border: '2px solid var(--border-strong)',
                                        borderRadius: 0,
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: '12px',
                                    }}
                                />
                                <Bar dataKey="events" fill="var(--accent-primary)" />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Detection Trend */}
                <div style={styles.chartCard}>
                    <div style={styles.chartHeader}>
                        <span style={styles.chartPrefix}>//</span>
                        <span style={styles.chartTitle}>Detection Trend</span>
                        <Shield24Regular style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '16px' }} />
                    </div>
                    <div style={styles.chartBody}>
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={trendData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-light)" />
                                <XAxis
                                    dataKey="date"
                                    tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                                    axisLine={{ stroke: 'var(--border-medium)' }}
                                />
                                <YAxis
                                    tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                                    axisLine={{ stroke: 'var(--border-medium)' }}
                                    allowDecimals={false}
                                />
                                <Tooltip
                                    contentStyle={{
                                        background: 'var(--bg-card)',
                                        border: '2px solid var(--border-strong)',
                                        borderRadius: 0,
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: '12px',
                                    }}
                                />
                                <Line
                                    type="monotone"
                                    dataKey="detections"
                                    stroke="var(--status-critical)"
                                    strokeWidth={2}
                                    dot={{ fill: 'var(--status-critical)', strokeWidth: 0, r: 4 }}
                                    activeDot={{ r: 6, fill: 'var(--status-critical)' }}
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Dashboard
