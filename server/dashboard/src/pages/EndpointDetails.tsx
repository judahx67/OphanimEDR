import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Spinner } from '@fluentui/react-components'
import {
    ArrowLeft24Regular,
    Desktop24Regular,
    Globe24Regular,
    Clock24Regular,
} from '@fluentui/react-icons'
import axios from 'axios'

interface Endpoint {
    endpoint_id: string
    hostname: string
    ip_address: string
    os_type: string
    os_version: string
    agent_version: string
    status: 'online' | 'offline'
    registered_at: string
    last_seen: string
    events_today: number
    policy: string
}

interface Event {
    id: string
    event_type: string
    timestamp: string
    data: Record<string, any>
}

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '24px',
    },
    pageHeader: {
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
    },
    backButton: {
        width: '40px',
        height: '40px',
        border: '2px solid var(--border-strong)',
        background: 'var(--bg-card)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        cursor: 'pointer',
        color: 'var(--text-primary)',
        transition: 'all 0.1s ease',
    },
    titleSection: {
        flex: 1,
    },
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
        fontSize: '24px',
        fontWeight: 700,
        color: 'var(--text-primary)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.02em',
    },
    statusBadge: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 16px',
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    statusOnline: {
        background: 'var(--status-success)',
        color: '#ffffff',
    },
    statusOffline: {
        background: 'var(--status-critical)',
        color: '#ffffff',
    },
    grid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(2, 1fr)',
        gap: '16px',
    },
    card: {
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        display: 'flex',
        flexDirection: 'column' as const,
    },
    cardHeader: {
        padding: '16px 20px',
        background: 'var(--bg-dark)',
        color: 'var(--text-inverse)',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
    },
    cardPrefix: {
        color: 'var(--accent-primary)',
        fontFamily: 'var(--font-mono)',
        fontWeight: 700,
        fontSize: '12px',
    },
    cardTitle: {
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    cardBody: {
        padding: '20px',
    },
    infoRow: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '12px 0',
        borderBottom: '1px solid var(--border-light)',
    },
    infoLabel: {
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    infoValue: {
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        fontWeight: 600,
        color: 'var(--text-primary)',
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
    eventsCard: {
        gridColumn: '1 / -1',
    },
    table: {
        width: '100%',
        borderCollapse: 'collapse' as const,
    },
    th: {
        padding: '12px 0',
        textAlign: 'left' as const,
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
        borderBottom: '2px solid var(--border-strong)',
    },
    td: {
        padding: '12px 0',
        borderBottom: '1px solid var(--border-light)',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-primary)',
    },
    typeBadge: {
        display: 'inline-block',
        padding: '3px 8px',
        border: '2px solid var(--border-medium)',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
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
    notFound: {
        textAlign: 'center' as const,
        padding: '80px',
    },
    notFoundText: {
        fontFamily: 'var(--font-mono)',
        fontSize: '14px',
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        marginBottom: '20px',
    },
}

function EndpointDetails() {
    const { id } = useParams<{ id: string }>()
    const navigate = useNavigate()
    const [endpoint, setEndpoint] = useState<Endpoint | null>(null)
    const [events, setEvents] = useState<Event[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [endpointRes, eventsRes] = await Promise.all([
                    axios.get(`/api/endpoints/${id}`),
                    axios.get(`/api/events?endpoint_id=${id}&page_size=10`),
                ])
                setEndpoint(endpointRes.data)
                setEvents(eventsRes.data.events || [])
            } catch (error) {
                console.error('Failed to fetch endpoint:', error)
            } finally {
                setLoading(false)
            }
        }

        if (id) fetchData()
    }, [id])

    const formatDate = (dateStr: string) => new Date(dateStr).toLocaleString()

    if (loading) {
        return (
            <div style={styles.loading}>
                <Spinner size="large" />
                <span style={styles.loadingText}>Loading Endpoint...</span>
            </div>
        )
    }

    if (!endpoint) {
        return (
            <div style={styles.notFound}>
                <div style={styles.notFoundText}>Endpoint Not Found</div>
                <button
                    style={styles.backButton}
                    onClick={() => navigate('/endpoints')}
                    onMouseOver={(e) => {
                        e.currentTarget.style.background = 'var(--accent-primary)'
                        e.currentTarget.style.borderColor = 'var(--accent-primary)'
                    }}
                    onMouseOut={(e) => {
                        e.currentTarget.style.background = 'var(--bg-card)'
                        e.currentTarget.style.borderColor = 'var(--border-strong)'
                    }}
                >
                    <ArrowLeft24Regular />
                </button>
            </div>
        )
    }

    return (
        <div style={styles.container}>
            {/* Page Header */}
            <div style={styles.pageHeader}>
                <button
                    style={styles.backButton}
                    onClick={() => navigate('/endpoints')}
                    onMouseOver={(e) => {
                        e.currentTarget.style.background = 'var(--accent-primary)'
                        e.currentTarget.style.borderColor = 'var(--accent-primary)'
                    }}
                    onMouseOut={(e) => {
                        e.currentTarget.style.background = 'var(--bg-card)'
                        e.currentTarget.style.borderColor = 'var(--border-strong)'
                    }}
                >
                    <ArrowLeft24Regular />
                </button>
                <div style={styles.titleSection}>
                    <div style={styles.sectionPrefix}>
                        <span style={styles.prefixSlash}>//</span>
                        <span>Endpoint Details</span>
                    </div>
                    <h1 style={styles.title}>{endpoint.hostname}</h1>
                </div>
                <span style={{
                    ...styles.statusBadge,
                    ...(endpoint.status === 'online' ? styles.statusOnline : styles.statusOffline)
                }}>
                    {endpoint.status === 'online' ? 'Online' : 'Offline'}
                </span>
            </div>

            {/* Info Cards Grid */}
            <div style={styles.grid}>
                {/* System Info */}
                <div style={styles.card}>
                    <div style={styles.cardHeader}>
                        <span style={styles.cardPrefix}>//</span>
                        <Desktop24Regular />
                        <span style={styles.cardTitle}>System</span>
                    </div>
                    <div style={styles.cardBody}>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>Hostname</span>
                            <span style={styles.infoValue}>{endpoint.hostname}</span>
                        </div>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>Endpoint ID</span>
                            <span style={styles.infoValue}>{endpoint.endpoint_id}</span>
                        </div>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>OS</span>
                            <span style={styles.osBadge}>{endpoint.os_type}</span>
                        </div>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>Version</span>
                            <span style={styles.infoValue}>{endpoint.os_version || 'N/A'}</span>
                        </div>
                    </div>
                </div>

                {/* Network Info */}
                <div style={styles.card}>
                    <div style={styles.cardHeader}>
                        <span style={styles.cardPrefix}>//</span>
                        <Globe24Regular />
                        <span style={styles.cardTitle}>Network</span>
                    </div>
                    <div style={styles.cardBody}>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>IP Address</span>
                            <span style={styles.infoValue}>{endpoint.ip_address}</span>
                        </div>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>Agent Version</span>
                            <span style={styles.infoValue}>{endpoint.agent_version}</span>
                        </div>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>Policy</span>
                            <span style={styles.policyBadge}>{endpoint.policy}</span>
                        </div>
                        <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>Last Seen</span>
                            <span style={styles.infoValue}>{formatDate(endpoint.last_seen)}</span>
                        </div>
                    </div>
                </div>

                {/* Events Card - Full Width */}
                <div style={{ ...styles.card, ...styles.eventsCard }}>
                    <div style={styles.cardHeader}>
                        <span style={styles.cardPrefix}>//</span>
                        <Clock24Regular />
                        <span style={styles.cardTitle}>Recent Events</span>
                        <span style={{
                            marginLeft: 'auto',
                            background: 'var(--accent-primary)',
                            color: '#0a0a0a',
                            padding: '2px 8px',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            fontWeight: 700,
                        }}>
                            {events.length}
                        </span>
                    </div>
                    <div style={styles.cardBody}>
                        {events.length === 0 ? (
                            <p style={{
                                color: 'var(--text-muted)',
                                textAlign: 'center',
                                padding: '40px',
                                fontFamily: 'var(--font-mono)',
                                fontSize: '12px',
                                textTransform: 'uppercase',
                                letterSpacing: '0.1em',
                            }}>
                                No Events Recorded
                            </p>
                        ) : (
                            <table style={styles.table}>
                                <thead>
                                    <tr>
                                        <th style={styles.th}>Time</th>
                                        <th style={styles.th}>Type</th>
                                        <th style={styles.th}>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {events.slice(0, 10).map((event, idx) => (
                                        <tr key={event.id || idx}>
                                            <td style={styles.td}>{formatDate(event.timestamp)}</td>
                                            <td style={styles.td}>
                                                <span style={styles.typeBadge}>{event.event_type}</span>
                                            </td>
                                            <td style={styles.td}>
                                                {event.data?.name || event.data?.path || JSON.stringify(event.data).slice(0, 50)}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default EndpointDetails
