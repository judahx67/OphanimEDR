import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Spinner } from '@fluentui/react-components'
import { CircleFilled } from '@fluentui/react-icons'
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

// OS badge helper
const getOsBadgeClass = (osType: string): string => {
    const os = osType?.toLowerCase() || ''
    if (os.includes('windows')) return 'os-badge os-badge-windows'
    if (os.includes('suse')) return 'os-badge os-badge-suse'
    if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian')) return 'os-badge os-badge-linux'
    if (os.includes('macos') || os.includes('darwin')) return 'os-badge os-badge-macos'
    return 'os-badge'
}

const getOsLabel = (osType: string): string => {
    const os = osType?.toLowerCase() || ''
    if (os.includes('windows')) return 'Windows'
    if (os.includes('suse')) return 'SUSE'
    if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian')) return 'Linux'
    if (os.includes('macos') || os.includes('darwin')) return 'macOS'
    return osType || 'Unknown'
}

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '24px',
    },
    title: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '32px',
        fontWeight: 600,
        color: 'var(--accent-indigo)',
        marginBottom: '4px',
    },
    subtitle: {
        fontSize: '14px',
        color: 'var(--text-muted)',
    },
    loading: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '300px',
    },
    tableCard: {
        background: 'var(--bg-card)',
        border: '1px solid var(--border-light)',
        overflow: 'hidden',
    },
    table: {
        width: '100%',
        borderCollapse: 'collapse' as const,
    },
    th: {
        padding: '12px 20px',
        textAlign: 'left' as const,
        fontSize: '10px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.1em',
        borderBottom: '1px solid var(--border-light)',
        background: 'var(--bg-primary)',
    },
    tr: {
        cursor: 'pointer',
        transition: 'background 0.15s ease',
    },
    trHover: {
        background: 'var(--bg-primary)',
    },
    td: {
        padding: '14px 20px',
        borderBottom: '1px solid var(--border-subtle)',
        fontSize: '14px',
        color: 'var(--text-primary)',
    },
    statusBadge: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
    online: {
        color: 'var(--status-online)',
    },
    offline: {
        color: 'var(--status-offline)',
    },
    hostname: {
        fontWeight: 600,
    },
    policyBadge: {
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.06em',
        padding: '3px 8px',
        border: '1px solid var(--accent-indigo)',
        color: 'var(--accent-indigo)',
    },
    emptyState: {
        textAlign: 'center' as const,
        padding: '64px',
        color: 'var(--text-muted)',
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

        if (diffSec < 60) return 'Just now'
        if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`
        if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`
        return date.toLocaleDateString()
    }

    if (loading) {
        return (
            <div style={styles.loading}>
                <Spinner size="large" label="Loading..." />
            </div>
        )
    }

    return (
        <div style={styles.container}>
            <div>
                <h1 style={styles.title}>Endpoints</h1>
                <p style={styles.subtitle}>
                    {endpoints.length} registered endpoint{endpoints.length !== 1 ? 's' : ''}
                </p>
            </div>

            <div style={styles.tableCard}>
                {endpoints.length === 0 ? (
                    <div style={styles.emptyState}>
                        <p style={{ fontSize: '14px', marginBottom: '8px' }}>No endpoints registered</p>
                        <p style={{ fontSize: '12px' }}>Deploy an agent to see it appear here.</p>
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
                                        ...(hoveredRow === endpoint.endpoint_id ? styles.trHover : {}),
                                    }}
                                    onMouseEnter={() => setHoveredRow(endpoint.endpoint_id)}
                                    onMouseLeave={() => setHoveredRow(null)}
                                    onClick={() => navigate(`/endpoints/${endpoint.endpoint_id}`)}
                                >
                                    <td style={styles.td}>
                                        <div style={styles.statusBadge}>
                                            <CircleFilled
                                                style={{
                                                    fontSize: '8px',
                                                    ...(endpoint.status === 'online' ? styles.online : styles.offline),
                                                }}
                                            />
                                            <span>{endpoint.status === 'online' ? 'Online' : 'Offline'}</span>
                                        </div>
                                    </td>
                                    <td style={{ ...styles.td, ...styles.hostname }}>{endpoint.hostname}</td>
                                    <td style={styles.td}>{endpoint.ip_address}</td>
                                    <td style={styles.td}>
                                        <span className={getOsBadgeClass(endpoint.os_type)}>
                                            {getOsLabel(endpoint.os_type)}
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
