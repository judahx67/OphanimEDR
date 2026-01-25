import { useEffect, useState } from 'react'
import { Spinner, Input, Button } from '@fluentui/react-components'
import {
    Search24Regular,
    Filter24Regular,
    Warning24Regular,
    Checkmark24Regular,
} from '@fluentui/react-icons'
import axios from 'axios'

interface Detection {
    id: string
    detection_type: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    status: 'new' | 'investigating' | 'resolved' | 'false_positive'
    title: string
    description: string
    endpoint_id: string
    ml_confidence: number
    mitre_technique: string | null
    created_at: string
}

interface DetectionStats {
    total: number
    new: number
    investigating: number
    resolved: number
}

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '24px',
    },
    header: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap' as const,
        gap: '16px',
    },
    title: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '32px',
        fontWeight: 600,
        color: '#2d2d5a',
        marginBottom: '4px',
    },
    subtitle: {
        fontSize: '14px',
        color: '#8a8a9a',
    },
    filters: {
        display: 'flex',
        gap: '12px',
        alignItems: 'center',
    },
    statsRow: {
        display: 'flex',
        gap: '16px',
        flexWrap: 'wrap' as const,
    },
    statCard: {
        background: '#ffffff',
        border: '1px solid #e8e4de',
        padding: '16px 24px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        minWidth: '120px',
    },
    statValue: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '24px',
        fontWeight: 600,
        color: '#1a1a2e',
    },
    statLabel: {
        fontSize: '11px',
        color: '#8a8a9a',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    tableCard: {
        background: '#ffffff',
        border: '1px solid #e8e4de',
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
        color: '#8a8a9a',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.1em',
        borderBottom: '1px solid #e8e4de',
        background: '#faf8f5',
    },
    tr: {
        transition: 'background 0.15s ease',
    },
    trHover: {
        background: '#faf8f5',
    },
    td: {
        padding: '14px 20px',
        borderBottom: '1px solid #f0ece6',
        fontSize: '14px',
        color: '#1a1a2e',
    },
    severityBadge: {
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.06em',
        padding: '3px 8px',
        border: '1px solid',
    },
    critical: {
        color: '#8b0000',
        borderColor: '#8b0000',
        background: 'rgba(139, 0, 0, 0.05)',
    },
    high: {
        color: '#c44d00',
        borderColor: '#c44d00',
        background: 'rgba(196, 77, 0, 0.05)',
    },
    medium: {
        color: '#946b00',
        borderColor: '#946b00',
        background: 'rgba(148, 107, 0, 0.05)',
    },
    low: {
        color: '#2d5a2d',
        borderColor: '#2d5a2d',
        background: 'rgba(45, 90, 45, 0.05)',
    },
    titleCell: {
        fontWeight: 600,
    },
    mitre: {
        fontSize: '11px',
        color: '#2d2d5a',
        marginTop: '4px',
    },
    typeBadge: {
        fontSize: '10px',
        padding: '2px 6px',
        border: '1px solid #e8e4de',
        color: '#4a4a5a',
    },
    confidenceBar: {
        width: '50px',
        height: '4px',
        background: '#e8e4de',
        marginBottom: '4px',
    },
    confidenceFill: {
        height: '100%',
        background: '#b8960c',
    },
    statusBadge: {
        fontSize: '10px',
        fontWeight: 500,
        padding: '3px 8px',
        textTransform: 'capitalize' as const,
    },
    statusNew: {
        background: 'rgba(139, 0, 0, 0.08)',
        color: '#8b3a3a',
    },
    statusInvestigating: {
        background: 'rgba(148, 107, 0, 0.08)',
        color: '#946b00',
    },
    statusResolved: {
        background: 'rgba(45, 90, 45, 0.08)',
        color: '#2d5a2d',
    },
    loading: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '300px',
    },
    emptyState: {
        textAlign: 'center' as const,
        padding: '64px',
        color: '#8a8a9a',
    },
}

function Problems() {
    const [detections, setDetections] = useState<Detection[]>([])
    const [stats, setStats] = useState<DetectionStats | null>(null)
    const [loading, setLoading] = useState(true)
    const [search, setSearch] = useState('')
    const [hoveredRow, setHoveredRow] = useState<string | null>(null)

    const fetchData = async () => {
        try {
            const params = new URLSearchParams()
            if (search) params.append('search', search)

            const [detectionsRes, statsRes] = await Promise.all([
                axios.get(`/api/detections?${params.toString()}`),
                axios.get('/api/detections/stats'),
            ])

            setDetections(detectionsRes.data.detections || [])
            setStats(statsRes.data)
        } catch (error) {
            console.error('Failed to fetch detections:', error)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchData()
    }, [])

    const handleSearch = () => {
        setLoading(true)
        fetchData()
    }

    const formatDate = (dateStr: string) => new Date(dateStr).toLocaleString()

    const getSeverityStyle = (severity: string) => {
        switch (severity) {
            case 'critical': return styles.critical
            case 'high': return styles.high
            case 'medium': return styles.medium
            default: return styles.low
        }
    }

    const getStatusStyle = (status: string) => {
        switch (status) {
            case 'new': return styles.statusNew
            case 'investigating': return styles.statusInvestigating
            default: return styles.statusResolved
        }
    }

    if (loading && detections.length === 0) {
        return (
            <div style={styles.loading}>
                <Spinner size="large" label="Loading..." />
            </div>
        )
    }

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <div>
                    <h1 style={styles.title}>Detections</h1>
                    <p style={styles.subtitle}>Security alerts and threat analysis</p>
                </div>

                <div style={styles.filters}>
                    <Input
                        placeholder="Search..."
                        contentBefore={<Search24Regular />}
                        value={search}
                        onChange={(_e, data) => setSearch(data.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                    />
                    <Button
                        icon={<Filter24Regular />}
                        onClick={handleSearch}
                    >
                        Filter
                    </Button>
                </div>
            </div>

            {stats && (
                <div style={styles.statsRow}>
                    <div style={styles.statCard}>
                        <Warning24Regular style={{ color: '#8b3a3a' }} />
                        <div>
                            <div style={styles.statValue}>{stats.new}</div>
                            <div style={styles.statLabel}>New</div>
                        </div>
                    </div>
                    <div style={styles.statCard}>
                        <Warning24Regular style={{ color: '#946b00' }} />
                        <div>
                            <div style={styles.statValue}>{stats.investigating}</div>
                            <div style={styles.statLabel}>Investigating</div>
                        </div>
                    </div>
                    <div style={styles.statCard}>
                        <Checkmark24Regular style={{ color: '#2d5a2d' }} />
                        <div>
                            <div style={styles.statValue}>{stats.resolved}</div>
                            <div style={styles.statLabel}>Resolved</div>
                        </div>
                    </div>
                </div>
            )}

            <div style={styles.tableCard}>
                {detections.length === 0 ? (
                    <div style={styles.emptyState}>
                        <p style={{ fontSize: '14px', marginBottom: '8px' }}>No detections found</p>
                        <p style={{ fontSize: '12px' }}>ML engine alerts will appear here.</p>
                    </div>
                ) : (
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Severity</th>
                                <th style={styles.th}>Title</th>
                                <th style={styles.th}>Type</th>
                                <th style={styles.th}>Endpoint</th>
                                <th style={styles.th}>Confidence</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {detections.map((detection) => (
                                <tr
                                    key={detection.id}
                                    style={{
                                        ...styles.tr,
                                        ...(hoveredRow === detection.id ? styles.trHover : {}),
                                    }}
                                    onMouseEnter={() => setHoveredRow(detection.id)}
                                    onMouseLeave={() => setHoveredRow(null)}
                                >
                                    <td style={styles.td}>
                                        <span style={{ ...styles.severityBadge, ...getSeverityStyle(detection.severity) }}>
                                            {detection.severity}
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        <div style={styles.titleCell}>{detection.title}</div>
                                        {detection.mitre_technique && (
                                            <div style={styles.mitre}>{detection.mitre_technique}</div>
                                        )}
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.typeBadge}>
                                            {detection.detection_type.replace('_', ' ')}
                                        </span>
                                    </td>
                                    <td style={styles.td}>{detection.endpoint_id}</td>
                                    <td style={styles.td}>
                                        <div style={styles.confidenceBar}>
                                            <div
                                                style={{
                                                    ...styles.confidenceFill,
                                                    width: `${detection.ml_confidence * 100}%`,
                                                }}
                                            />
                                        </div>
                                        <span style={{ fontSize: '11px', color: '#8a8a9a' }}>
                                            {Math.round(detection.ml_confidence * 100)}%
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={{ ...styles.statusBadge, ...getStatusStyle(detection.status) }}>
                                            {detection.status.replace('_', ' ')}
                                        </span>
                                    </td>
                                    <td style={styles.td}>{formatDate(detection.created_at)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    )
}

export default Problems
