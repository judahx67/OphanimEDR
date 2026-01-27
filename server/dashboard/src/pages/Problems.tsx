import { useEffect, useState } from 'react'
import { Spinner } from '@fluentui/react-components'
import {
    Search24Regular,
    Warning24Regular,
    Checkmark24Regular,
    Eye24Regular,
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
    pageHeader: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap' as const,
        gap: '16px',
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
    searchBox: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '10px 16px',
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        minWidth: '280px',
    },
    searchIcon: {
        color: 'var(--text-muted)',
        fontSize: '18px',
    },
    searchInput: {
        background: 'transparent',
        border: 'none',
        outline: 'none',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-primary)',
        flex: 1,
    },
    searchBtn: {
        padding: '10px 20px',
        background: 'var(--accent-primary)',
        border: '2px solid var(--accent-primary)',
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
        color: '#0a0a0a',
        cursor: 'pointer',
    },
    statsRow: {
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: '16px',
    },
    statCard: {
        background: 'var(--bg-card)',
        border: '2px solid var(--border-strong)',
        padding: '20px',
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
    },
    statCardAlert: {
        background: 'var(--status-critical)',
        border: '2px solid var(--status-critical)',
        color: '#ffffff',
        padding: '20px',
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
    },
    statIcon: {
        fontSize: '24px',
        color: 'var(--text-muted)',
    },
    statIconWhite: {
        fontSize: '24px',
        color: '#ffffff',
    },
    statValue: {
        fontFamily: 'var(--font-mono)',
        fontSize: '32px',
        fontWeight: 700,
        lineHeight: 1,
    },
    statValueWhite: {
        fontFamily: 'var(--font-mono)',
        fontSize: '32px',
        fontWeight: 700,
        lineHeight: 1,
        color: '#ffffff',
    },
    statLabel: {
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
    },
    statLabelWhite: {
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 600,
        color: 'rgba(255,255,255,0.7)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.08em',
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
        transition: 'background 0.1s ease',
    },
    td: {
        padding: '14px 20px',
        borderBottom: '1px solid var(--border-light)',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: 'var(--text-primary)',
    },
    severityCritical: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--severity-critical-bg)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    severityHigh: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--severity-high-bg)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    severityMedium: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--severity-medium-bg)',
        color: '#0a0a0a',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    severityLow: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--severity-low-bg)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    titleCell: {
        fontWeight: 700,
        color: 'var(--text-primary)',
    },
    mitre: {
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        color: 'var(--text-muted)',
        marginTop: '4px',
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
    confidenceBar: {
        width: '60px',
        height: '6px',
        background: 'var(--border-light)',
        marginBottom: '4px',
    },
    confidenceFill: {
        height: '100%',
        background: 'var(--accent-primary)',
    },
    statusNew: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--status-critical)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    statusInvestigating: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--status-warning)',
        color: '#0a0a0a',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    statusResolved: {
        display: 'inline-block',
        padding: '4px 10px',
        background: 'var(--status-success)',
        color: '#ffffff',
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 700,
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

    const formatDate = (dateStr: string) => {
        const date = new Date(dateStr)
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }

    const getSeverityStyle = (severity: string) => {
        switch (severity) {
            case 'critical': return styles.severityCritical
            case 'high': return styles.severityHigh
            case 'medium': return styles.severityMedium
            default: return styles.severityLow
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
                <Spinner size="large" />
                <span style={styles.loadingText}>Loading Detections...</span>
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
                        <span>Threat Intelligence</span>
                    </div>
                    <h1 style={styles.title}>Detections</h1>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                    <div style={styles.searchBox}>
                        <Search24Regular style={styles.searchIcon} />
                        <input
                            type="text"
                            placeholder="Search detections..."
                            style={styles.searchInput}
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                        />
                    </div>
                    <button style={styles.searchBtn} onClick={handleSearch}>
                        Search
                    </button>
                </div>
            </div>

            {/* Stats Row */}
            {stats && (
                <div style={styles.statsRow}>
                    <div style={stats.new > 0 ? styles.statCardAlert : styles.statCard}>
                        <Warning24Regular style={stats.new > 0 ? styles.statIconWhite : styles.statIcon} />
                        <div>
                            <div style={stats.new > 0 ? styles.statValueWhite : styles.statValue}>{stats.new}</div>
                            <div style={stats.new > 0 ? styles.statLabelWhite : styles.statLabel}>New Alerts</div>
                        </div>
                    </div>
                    <div style={styles.statCard}>
                        <Eye24Regular style={styles.statIcon} />
                        <div>
                            <div style={styles.statValue}>{stats.investigating}</div>
                            <div style={styles.statLabel}>Investigating</div>
                        </div>
                    </div>
                    <div style={styles.statCard}>
                        <Checkmark24Regular style={styles.statIcon} />
                        <div>
                            <div style={styles.statValue}>{stats.resolved}</div>
                            <div style={styles.statLabel}>Resolved</div>
                        </div>
                    </div>
                </div>
            )}

            {/* Table */}
            <div style={styles.tableCard}>
                <div style={styles.tableHeader}>
                    <span style={styles.headerPrefix}>//</span>
                    <span>Detection Log</span>
                </div>

                {detections.length === 0 ? (
                    <div style={styles.emptyState}>
                        <div style={styles.emptyTitle}>No Detections Found</div>
                        <div style={styles.emptyText}>ML engine alerts will appear here.</div>
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
                                        background: hoveredRow === detection.id
                                            ? 'var(--bg-secondary)'
                                            : 'transparent',
                                    }}
                                    onMouseEnter={() => setHoveredRow(detection.id)}
                                    onMouseLeave={() => setHoveredRow(null)}
                                >
                                    <td style={styles.td}>
                                        <span style={getSeverityStyle(detection.severity)}>
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
                                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                            {Math.round(detection.ml_confidence * 100)}%
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={getStatusStyle(detection.status)}>
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
