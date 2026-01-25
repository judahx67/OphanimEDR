import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import {
    Desktop24Regular,
    Warning24Regular,
    Checkmark24Regular,
    ArrowTrendingLines24Regular,
} from '@fluentui/react-icons'
import axios from 'axios'
import {
    PieChart,
    Pie,
    Cell,
    BarChart,
    Bar,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    Legend,
} from 'recharts'

interface DashboardStats {
    totalEndpoints: number
    onlineEndpoints: number
    offlineEndpoints: number
    eventsToday: number
    criticalAlerts: number
}

interface EndpointOsData {
    name: string
    value: number
    color: string
    [key: string]: string | number  // Index signature for Recharts compatibility
}

interface DetectionTrendData {
    date: string
    detections: number
    [key: string]: string | number  // Index signature for Recharts compatibility
}

// OS colors matching the Ophanim theme
const OS_COLORS: Record<string, string> = {
    windows: '#0078d4',
    linux: '#dd4814',
    suse: '#73ba25',
    macos: '#555555',
}

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '32px',
    },
    titleSection: {
        marginBottom: '8px',
    },
    title: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '32px',
        fontWeight: 600,
        color: 'var(--accent-indigo)',
        marginBottom: '8px',
    },
    subtitle: {
        fontSize: '14px',
        color: 'var(--text-muted)',
    },
    statsGrid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '16px',
    },
    statCard: {
        background: 'var(--bg-card)',
        border: '1px solid var(--border-light)',
        padding: '24px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '16px',
    },
    statIcon: {
        width: '40px',
        height: '40px',
        border: '1px solid var(--border-light)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--accent-indigo)',
    },
    statContent: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '4px',
    },
    statValue: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '28px',
        fontWeight: 600,
        color: 'var(--text-primary)',
        lineHeight: 1,
    },
    statLabel: {
        fontSize: '12px',
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    alertBanner: {
        background: 'var(--bg-card)',
        border: '1px solid var(--severity-high)',
        borderLeft: '3px solid var(--severity-high)',
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
    },
    alertText: {
        flex: 1,
    },
    alertTitle: {
        fontSize: '14px',
        fontWeight: 600,
        color: 'var(--severity-high)',
        marginBottom: '4px',
    },
    alertDesc: {
        fontSize: '13px',
        color: 'var(--text-secondary)',
    },
    loading: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '300px',
    },
    sectionTitle: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '18px',
        fontWeight: 600,
        color: 'var(--accent-indigo)',
        marginBottom: '16px',
        paddingBottom: '8px',
        borderBottom: '1px solid var(--border-light)',
    },
    chartsGrid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
        gap: '24px',
    },
    chartCard: {
        background: 'var(--bg-card)',
        border: '1px solid var(--border-light)',
        padding: '24px',
    },
    chartTitle: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '16px',
        fontWeight: 600,
        color: 'var(--accent-indigo)',
        marginBottom: '16px',
    },
    chartContainer: {
        height: '250px',
    },
    legendItem: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '4px',
    },
    legendDot: {
        width: '10px',
        height: '10px',
        borderRadius: '50%',
    },
    legendText: {
        fontSize: '12px',
        color: '#4a4a5a',
    },
}

function Dashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null)
    const [osData, setOsData] = useState<EndpointOsData[]>([])
    const [trendData, setTrendData] = useState<DetectionTrendData[]>([])
    const [eventsData, setEventsData] = useState<{ day: string; events: number }[]>([])
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

                // Calculate OS breakdown
                const osCounts: Record<string, number> = {}
                endpoints.forEach((e: any) => {
                    const os = e.os_type?.toLowerCase() || 'unknown'
                    osCounts[os] = (osCounts[os] || 0) + 1
                })

                const osChartData = Object.entries(osCounts).map(([name, value]) => ({
                    name: name.charAt(0).toUpperCase() + name.slice(1),
                    value,
                    color: OS_COLORS[name] || '#8a8a9a',
                }))
                setOsData(osChartData)

                // Simulate events data for the last 7 days
                const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                const eventsChartData = days.map(day => ({
                    day,
                    events: Math.floor(Math.random() * 5000) + 1000,
                }))
                setEventsData(eventsChartData)

                // Simulate detection trend data
                const trendChartData = days.map((day, i) => ({
                    date: day,
                    detections: Math.floor(Math.random() * 5) + (i === 6 ? 3 : 1),
                }))
                setTrendData(trendChartData)

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
                <Spinner size="large" label="Loading..." />
            </div>
        )
    }

    const statCards = [
        { icon: <Desktop24Regular />, value: stats?.totalEndpoints || 0, label: 'Endpoints' },
        { icon: <Checkmark24Regular />, value: stats?.onlineEndpoints || 0, label: 'Online' },
        { icon: <Warning24Regular />, value: stats?.offlineEndpoints || 0, label: 'Offline' },
        { icon: <ArrowTrendingLines24Regular />, value: stats?.eventsToday?.toLocaleString() || '0', label: 'Events Today' },
    ]

    return (
        <div style={styles.container}>
            <div style={styles.titleSection}>
                <h1 style={styles.title}>Dashboard</h1>
                <p style={styles.subtitle}>Endpoint security overview</p>
            </div>

            {stats && stats.criticalAlerts > 0 && (
                <div style={styles.alertBanner}>
                    <Warning24Regular style={{ color: '#c44d00', fontSize: '20px' }} />
                    <div style={styles.alertText}>
                        <div style={styles.alertTitle}>
                            {stats.criticalAlerts} Active Detection{stats.criticalAlerts > 1 ? 's' : ''}
                        </div>
                        <div style={styles.alertDesc}>
                            Review the Detections page for investigation.
                        </div>
                    </div>
                </div>
            )}

            <div>
                <h2 style={styles.sectionTitle}>Overview</h2>
                <div style={styles.statsGrid}>
                    {statCards.map((card, index) => (
                        <div key={index} style={styles.statCard}>
                            <div style={styles.statIcon}>
                                {card.icon}
                            </div>
                            <div style={styles.statContent}>
                                <span style={styles.statValue}>{card.value}</span>
                                <span style={styles.statLabel}>{card.label}</span>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            <div>
                <h2 style={styles.sectionTitle}>Analytics</h2>
                <div style={styles.chartsGrid}>
                    {/* Endpoints by OS - Pie Chart */}
                    <div style={styles.chartCard}>
                        <h3 style={styles.chartTitle}>Endpoints by OS</h3>
                        <div style={styles.chartContainer}>
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={osData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={50}
                                        outerRadius={80}
                                        paddingAngle={2}
                                        dataKey="value"
                                    >
                                        {osData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{
                                            background: '#ffffff',
                                            border: '1px solid #e8e4de',
                                            borderRadius: 0,
                                        }}
                                    />
                                    <Legend
                                        formatter={(value) => (
                                            <span style={{ color: '#4a4a5a', fontSize: '12px' }}>{value}</span>
                                        )}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Events Timeline - Bar Chart */}
                    <div style={styles.chartCard}>
                        <h3 style={styles.chartTitle}>Events This Week</h3>
                        <div style={styles.chartContainer}>
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={eventsData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e8e4de" />
                                    <XAxis
                                        dataKey="day"
                                        tick={{ fill: '#8a8a9a', fontSize: 11 }}
                                        axisLine={{ stroke: '#e8e4de' }}
                                    />
                                    <YAxis
                                        tick={{ fill: '#8a8a9a', fontSize: 11 }}
                                        axisLine={{ stroke: '#e8e4de' }}
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            background: '#ffffff',
                                            border: '1px solid #e8e4de',
                                            borderRadius: 0,
                                        }}
                                    />
                                    <Bar dataKey="events" fill="#2d2d5a" />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Detection Trend - Line Chart */}
                    <div style={styles.chartCard}>
                        <h3 style={styles.chartTitle}>Detection Trend</h3>
                        <div style={styles.chartContainer}>
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={trendData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e8e4de" />
                                    <XAxis
                                        dataKey="date"
                                        tick={{ fill: '#8a8a9a', fontSize: 11 }}
                                        axisLine={{ stroke: '#e8e4de' }}
                                    />
                                    <YAxis
                                        tick={{ fill: '#8a8a9a', fontSize: 11 }}
                                        axisLine={{ stroke: '#e8e4de' }}
                                        allowDecimals={false}
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            background: '#ffffff',
                                            border: '1px solid #e8e4de',
                                            borderRadius: 0,
                                        }}
                                    />
                                    <Line
                                        type="monotone"
                                        dataKey="detections"
                                        stroke="#b8960c"
                                        strokeWidth={2}
                                        dot={{ fill: '#b8960c', strokeWidth: 0, r: 4 }}
                                        activeDot={{ r: 6, fill: '#b8960c' }}
                                    />
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Dashboard
