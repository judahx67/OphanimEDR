import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Spinner, Badge } from '@fluentui/react-components'
import {
    ArrowLeft24Regular,
    CircleFilled,
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
    header: {
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
    },
    backButton: {
        width: '36px',
        height: '36px',
        border: '1px solid #e8e4de',
        background: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        cursor: 'pointer',
        color: '#4a4a5a',
    },
    titleSection: {
        flex: 1,
    },
    title: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '24px',
        fontWeight: 600,
        color: '#2d2d5a',
        marginBottom: '4px',
    },
    statusBadge: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '12px',
        color: '#4a4a5a',
    },
    online: { color: '#2d5a2d' },
    offline: { color: '#8b3a3a' },
    grid: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '16px',
    },
    card: {
        background: '#ffffff',
        border: '1px solid #e8e4de',
        padding: '24px',
    },
    cardHeader: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        marginBottom: '20px',
        paddingBottom: '12px',
        borderBottom: '1px solid #e8e4de',
    },
    cardIcon: {
        width: '32px',
        height: '32px',
        border: '1px solid #e8e4de',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: '#2d2d5a',
    },
    cardTitle: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '16px',
        fontWeight: 600,
        color: '#2d2d5a',
    },
    infoRow: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '10px 0',
        borderBottom: '1px solid #f0ece6',
    },
    infoLabel: {
        fontSize: '12px',
        color: '#8a8a9a',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    infoValue: {
        fontSize: '14px',
        fontWeight: 500,
        color: '#1a1a2e',
    },
    policyBadge: {
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.06em',
        padding: '3px 8px',
        border: '1px solid #2d2d5a',
        color: '#2d2d5a',
    },
    eventsCard: {
        gridColumn: '1 / -1',
    },
    table: {
        width: '100%',
        borderCollapse: 'collapse' as const,
    },
    th: {
        padding: '10px 0',
        textAlign: 'left' as const,
        fontSize: '10px',
        fontWeight: 600,
        color: '#8a8a9a',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
        borderBottom: '1px solid #e8e4de',
    },
    td: {
        padding: '10px 0',
        borderBottom: '1px solid #f0ece6',
        fontSize: '13px',
        color: '#1a1a2e',
    },
    typeBadge: {
        fontSize: '10px',
        padding: '2px 6px',
        border: '1px solid #e8e4de',
        color: '#4a4a5a',
    },
    loading: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '300px',
    },
    notFound: {
        textAlign: 'center' as const,
        padding: '64px',
        color: '#8a8a9a',
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
                <Spinner size="large" label="Loading..." />
            </div>
        )
    }

    if (!endpoint) {
        return (
            <div style={styles.notFound}>
                <p>Endpoint not found</p>
                <button style={styles.backButton} onClick={() => navigate('/endpoints')}>
                    Back
                </button>
            </div>
        )
    }

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <button style={styles.backButton} onClick={() => navigate('/endpoints')}>
                    <ArrowLeft24Regular />
                </button>
                <div style={styles.titleSection}>
                    <h1 style={styles.title}>{endpoint.hostname}</h1>
                    <div style={styles.statusBadge}>
                        <CircleFilled
                            style={{
                                fontSize: '8px',
                                ...(endpoint.status === 'online' ? styles.online : styles.offline),
                            }}
                        />
                        <span>{endpoint.status === 'online' ? 'Online' : 'Offline'}</span>
                    </div>
                </div>
            </div>

            <div style={styles.grid}>
                <div style={styles.card}>
                    <div style={styles.cardHeader}>
                        <div style={styles.cardIcon}>
                            <Desktop24Regular />
                        </div>
                        <span style={styles.cardTitle}>System</span>
                    </div>
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
                        <Badge appearance="outline">{endpoint.os_type}</Badge>
                    </div>
                    <div style={styles.infoRow}>
                        <span style={styles.infoLabel}>Version</span>
                        <span style={styles.infoValue}>{endpoint.os_version || 'N/A'}</span>
                    </div>
                </div>

                <div style={styles.card}>
                    <div style={styles.cardHeader}>
                        <div style={styles.cardIcon}>
                            <Globe24Regular />
                        </div>
                        <span style={styles.cardTitle}>Network</span>
                    </div>
                    <div style={styles.infoRow}>
                        <span style={styles.infoLabel}>IP Address</span>
                        <span style={styles.infoValue}>{endpoint.ip_address}</span>
                    </div>
                    <div style={styles.infoRow}>
                        <span style={styles.infoLabel}>Agent</span>
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

                <div style={{ ...styles.card, ...styles.eventsCard }}>
                    <div style={styles.cardHeader}>
                        <div style={styles.cardIcon}>
                            <Clock24Regular />
                        </div>
                        <span style={styles.cardTitle}>Recent Events</span>
                        <Badge appearance="outline" style={{ marginLeft: 'auto' }}>{events.length}</Badge>
                    </div>
                    {events.length === 0 ? (
                        <p style={{ color: '#8a8a9a', textAlign: 'center', padding: '24px' }}>
                            No events recorded
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
                                            {event.data?.name || event.data?.path || JSON.stringify(event.data).slice(0, 40)}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>
        </div>
    )
}

export default EndpointDetails
