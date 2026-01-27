import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Spinner } from '@fluentui/react-components'
import axios from 'axios'

interface Endpoint {
    endpoint_id: string
    hostname: string
    ip_address: string
    os_type: string
    os_version: string
    agent_version: string
    status: 'online' | 'offline' | 'unknown'
    last_seen: string
    events_today: number
    policy: string
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
    countBadge: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 16px',
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        fontWeight: 600,
    },
    countNumber: {
        color: 'var(--accent-primary)',
        fontSize: '16px',
        fontWeight: 700,
    },
    tableCard: {
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        overflow: 'hidden',
    },
    tableHeader: {
        padding: '16px 20px',
        background: 'var(--bg-dark)',
        color: 'var(--text-inverse)',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    headerPrefix: {
        color: 'var(--accent-primary)',
        fontWeight: 700,
    },
    table: {
        width: '100%',
        borderCollapse: 'collapse' as const,
    },
    th: {
        padding: '12px 20px',
        textAlign: 'left' as const,
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
        borderBottom: '2px solid var(--border-strong)',
        background: 'var(--bg-secondary)',
    },
    tr: {
        cursor: 'pointer',
        transition: 'background 0.1s ease',
    },
    td: {
        padding: '14px 20px',
        borderBottom: '1px solid var(--border-light)',
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        color: 'var(--text-primary)',
    },
    statusOnline: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: '4px 10px',
        background: 'var(--status-success)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    statusOffline: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: '4px 10px',
        background: 'var(--status-critical)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    hostname: {
        fontWeight: 700,
        color: 'var(--text-primary)',
    },
    osBadge: {
        display: 'inline-block',
        padding: '4px 8px',
        border: '2px solid var(--border-strong)',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    policyBadge: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--accent-primary)',
        color: '#0a0a0a',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    emptyState: {
        textAlign: 'center' as const,
        padding: '80px 40px',
    },
    emptyTitle: {
        fontFamily: 'var(--font-mono)',
        fontSize: '14px',
        fontWeight: 600,
        color: 'var(--text-primary)',
        textTransform: 'uppercase' as const,
        marginBottom: '8px',
    },
    emptyText: {
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-muted)',
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

function EndpointsList() {
    const navigate = useNavigate()
    const [endpoints, setEndpoints] = useState<Endpoint[]>([])
    const [loading, setLoading] = useState(true)
    const [hoveredRow, setHoveredRow] = useState<string | null>(null)

    useEffect(() => {
        const fetchEndpoints = async () => {
            try {
                const response = await axios.get('/api/endpoints')
                setEndpoints(response.data.endpoints || [])
            } catch (error) {
                console.error('Failed to fetch endpoints:', error)
            } finally {
                setLoading(false)
            }
        }

        fetchEndpoints()
        const interval = setInterval(fetchEndpoints, 10000)
        return () => clearInterval(interval)
    }, [])

    const formatLastSeen = (dateStr: string) => {
        const date = new Date(dateStr)
        const now = new Date()
        const diffMs = now.getTime() - date.getTime()
        const diffSec = Math.floor(diffMs / 1000)

        if (diffSec < 60) return 'Now'
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m`
        if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h`
        return date.toLocaleDateString()
    }

    if (loading) {
        return (
            <div style={styles.loading}>
                <Spinner size="large" />
                <span style={styles.loadingText}>Loading Endpoints...</span>
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
                        <span>Asset Management</span>
                    </div>
                    <h1 style={styles.title}>Endpoints</h1>
                </div>
                <div style={styles.countBadge}>
                    <span>Registered</span>
                    <span style={styles.countNumber}>{endpoints.length}</span>
                </div>
            </div>

            {/* Table */}
            <div style={styles.tableCard}>
                <div style={styles.tableHeader}>
                    <span style={styles.headerPrefix}>//</span>
                    <span>Endpoint Registry</span>
                </div>

                {endpoints.length === 0 ? (
                    <div style={styles.emptyState}>
                        <div style={styles.emptyTitle}>No Endpoints Registered</div>
                        <div style={styles.emptyText}>Deploy an agent to see it appear here.</div>
                    </div>
                ) : (
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Hostname</th>
                                <th style={styles.th}>IP Address</th>
                                <th style={styles.th}>OS</th>
                                <th style={styles.th}>Policy</th>
                                <th style={styles.th}>Last Seen</th>
                                <th style={styles.th}>Events</th>
                            </tr>
                        </thead>
                        <tbody>
                            {endpoints.map((endpoint) => (
                                <tr
                                    key={endpoint.endpoint_id}
                                    style={{
                                        ...styles.tr,
                                        background: hoveredRow === endpoint.endpoint_id
                                            ? 'var(--bg-secondary)'
                                            : 'transparent',
                                    }}
                                    onMouseEnter={() => setHoveredRow(endpoint.endpoint_id)}
                                    onMouseLeave={() => setHoveredRow(null)}
                                    onClick={() => navigate(`/endpoints/${endpoint.endpoint_id}`)}
                                >
                                    <td style={styles.td}>
                                        <span style={endpoint.status === 'online'
                                            ? styles.statusOnline
                                            : styles.statusOffline
                                        }>
                                            {endpoint.status === 'online' ? 'Online' : 'Offline'}
                                        </span>
                                    </td>
                                    <td style={{ ...styles.td, ...styles.hostname }}>
                                        {endpoint.hostname}
                                    </td>
                                    <td style={styles.td}>{endpoint.ip_address}</td>
                                    <td style={styles.td}>
                                        <span style={styles.osBadge}>
                                            {endpoint.os_type || 'Unknown'}
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.policyBadge}>{endpoint.policy}</span>
                                    </td>
                                    <td style={styles.td}>{formatLastSeen(endpoint.last_seen)}</td>
                                    <td style={styles.td}>{endpoint.events_today.toLocaleString()}</td>
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
