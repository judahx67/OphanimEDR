import { useEffect, useState, useCallback } from 'react'
import { Spinner } from '@fluentui/react-components'
import SigmaGenerator from '../components/SigmaGenerator'
import { CausalChain, NodeLegend, type MatchedNode, type MatchedEdge } from '../components/CausalChain'
import {
    Search24Regular,
    Warning24Regular,
    Checkmark24Regular,
    Eye24Regular,
    ChevronDown24Regular,
    ChevronRight24Regular,
    Dismiss24Regular,
} from '@fluentui/react-icons'
import axios from 'axios'

// ── Types ──────────────────────────────────────────────────────────────────

interface Incident {
    incident_id: string; rule_id: string; rule_name: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    status: 'new' | 'investigating' | 'resolved' | 'false_positive'
    title: string; description: string
    mitre_technique: string | null; endpoint_id: string
    confidence: number
    matched_nodes: MatchedNode[]; matched_edges: MatchedEdge[]
    rule_conditions: string[]; root_node_id: string | null
    created_at: string
}
interface IncidentStats {
    total: number; new: number; investigating: number; resolved: number
    by_severity: Record<string, number>
}

// ── Constants ──────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#16a34a',
}
const STATUS_NEXT: Record<string, { label: string; value: string }> = {
    new:           { label: 'Mark Investigating', value: 'investigating' },
    investigating: { label: 'Mark Resolved',      value: 'resolved' },
    resolved:      { label: 'Reopen',             value: 'new' },
    false_positive:{ label: 'Reopen',             value: 'new' },
}


// ── Expanded detail panel ──────────────────────────────────────────────────

function IncidentDetail({ incident, onStatusChange }: {
    incident: Incident
    onStatusChange: (id: string, status: string) => void
}) {
    // Export-to-SIEM: deterministic template path (the LLM path lives in the
    // reusable SigmaGenerator below). Both are integration claims, not detection.
    const [exporting, setExporting] = useState(false)
    const [exportMsg, setExportMsg] = useState<string | null>(null)

    const exportToSiem = async () => {
        setExporting(true); setExportMsg(null)
        try {
            const { data } = await axios.post('/api/wazuh/export-rule',
                { incident_id: incident.incident_id })
            setExportMsg(data.ok
                ? `✓ Rule ${data.rule_id} delivered to Wazuh — ${data.filename}`
                : `✗ Wazuh rejected the rule (HTTP ${data.put_status})`)
        } catch {
            setExportMsg('✗ Export failed — is the Wazuh manager running?')
        } finally { setExporting(false) }
    }

    const panel: React.CSSProperties = {
        padding: '0', background: 'var(--bg-secondary)',
        borderBottom: '2px solid var(--border-strong)',
    }
    const section: React.CSSProperties = {
        padding: '16px 24px', borderBottom: '1px solid var(--border-light)',
    }
    const label: React.CSSProperties = {
        fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 600,
        color: 'var(--text-muted)', textTransform: 'uppercase' as const,
        letterSpacing: '0.1em', marginBottom: '10px',
    }
    const meta: React.CSSProperties = {
        fontFamily: 'var(--font-ui)', fontSize: '11px',
        color: 'var(--text-secondary)', lineHeight: 1.8,
    }

    const next = STATUS_NEXT[incident.status]

    return (
        <tr>
            <td colSpan={7} style={panel}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', borderBottom: '1px solid var(--border-light)' }}>

                    {/* Left: causal chain */}
                    <div style={{ ...section, borderRight: '1px solid var(--border-light)', borderBottom: 'none' }}>
                        <div style={label}>// Causal chain — {incident.matched_edges.length} edge{incident.matched_edges.length !== 1 ? 's' : ''}</div>
                        <CausalChain edges={incident.matched_edges} nodes={incident.matched_nodes} />
                        <NodeLegend nodes={incident.matched_nodes} />
                    </div>

                    {/* Right: metadata */}
                    <div style={{ ...section, borderBottom: 'none' }}>
                        <div style={label}>// Detection details</div>
                        <div style={meta}>
                            <table style={{ borderCollapse: 'collapse' as const, width: '100%' }}>
                                <tbody>
                                    {[
                                        ['Rule',       incident.rule_id],
                                        ['Technique',  incident.mitre_technique || 'n/a'],
                                        ['Endpoint',   incident.endpoint_id],
                                        ['Confidence', Math.round(incident.confidence * 100) + '%'],
                                        ['Root node',  incident.root_node_id ? incident.root_node_id.slice(0, 18) + '…' : 'n/a'],
                                    ].map(([k, v]) => (
                                        <tr key={k}>
                                            <td style={{ color: 'var(--text-muted)', paddingRight: '16px', paddingBottom: '4px', whiteSpace: 'nowrap' }}>{k}</td>
                                            <td style={{ color: 'var(--text-primary)', wordBreak: 'break-all' as const }}>{v}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Actions: status transition + export to SIEM */}
                        <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' as const }}>
                            {next && (
                                <button
                                    onClick={() => onStatusChange(incident.incident_id, next.value)}
                                    style={{
                                        padding: '7px 16px', background: 'transparent',
                                        border: '2px solid var(--border-strong)',
                                        fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600,
                                        color: 'var(--text-primary)', textTransform: 'uppercase' as const,
                                        letterSpacing: '0.05em', cursor: 'pointer',
                                    }}
                                >
                                    {next.label}
                                </button>
                            )}
                            <button
                                onClick={exportToSiem}
                                disabled={exporting}
                                title="Convert to a Sigma rule and push it to the Wazuh SIEM"
                                style={{
                                    padding: '7px 16px', background: 'transparent',
                                    border: '2px solid var(--accent-primary)',
                                    fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600,
                                    color: 'var(--accent-primary)', textTransform: 'uppercase' as const,
                                    letterSpacing: '0.05em', cursor: exporting ? 'wait' : 'pointer',
                                    opacity: exporting ? 0.6 : 1,
                                }}
                            >
                                {exporting ? 'Exporting…' : 'Export to SIEM'}
                            </button>
                            {exportMsg && (
                                <span style={{
                                    fontFamily: 'var(--font-ui)', fontSize: '11px',
                                    color: exportMsg.startsWith('✓') ? 'var(--status-good, #16a34a)' : 'var(--status-critical, #dc2626)',
                                }}>{exportMsg}</span>
                            )}
                        </div>

                        {/* LLM-authored Sigma: generate → review → push (human-in-the-loop) */}
                        <div style={{ marginTop: '16px' }}>
                            <div style={{ ...label, marginBottom: '8px' }}>// Or generate the rule with an LLM</div>
                            <SigmaGenerator incidentId={incident.incident_id} />
                        </div>
                    </div>
                </div>
            </td>
        </tr>
    )
}

// ── Severity filter tabs ───────────────────────────────────────────────────

const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low'] as const
type SeverityFilter = typeof SEVERITY_FILTERS[number]

// ── Main component ─────────────────────────────────────────────────────────

function Incidents() {
    const [incidents, setIncidents] = useState<Incident[]>([])
    const [stats, setStats] = useState<IncidentStats | null>(null)
    const [loading, setLoading] = useState(true)
    const [search, setSearch] = useState('')
    const [sevFilter, setSevFilter] = useState<SeverityFilter>('all')
    const [statusFilter, setStatusFilter] = useState<string>('all')
    const [expanded, setExpanded] = useState<string | null>(null)
    const [hoveredRow, setHoveredRow] = useState<string | null>(null)

    const fetchData = useCallback(async () => {
        try {
            const params = new URLSearchParams()
            if (search) params.append('search', search)
            if (sevFilter !== 'all') params.append('severity', sevFilter)
            if (statusFilter !== 'all') params.append('status', statusFilter)
            params.append('page_size', '200')

            const [incRes, statsRes] = await Promise.all([
                axios.get(`/api/incidents?${params}`),
                axios.get('/api/incidents/stats'),
            ])
            setIncidents(incRes.data.incidents || [])
            setStats(statsRes.data)
        } catch (err) {
            console.error('Failed to fetch incidents:', err)
            setIncidents([])
        } finally {
            setLoading(false)
        }
    }, [search, sevFilter, statusFilter])

    useEffect(() => {
        fetchData()
        const iv = setInterval(fetchData, 10000)
        return () => clearInterval(iv)
    }, [fetchData])

    const handleStatusChange = async (id: string, newStatus: string) => {
        try {
            await axios.patch(`/api/incidents/${id}/status?status=${newStatus}`)
            // Optimistic update
            setIncidents(prev => prev.map(inc =>
                inc.incident_id === id ? { ...inc, status: newStatus as Incident['status'] } : inc
            ))
            fetchData()
        } catch (err) {
            console.error('Failed to update status:', err)
        }
    }

    const formatDate = (s: string) => {
        const d = new Date(s)
        return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
            + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }

    if (loading && incidents.length === 0) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px', flexDirection: 'column' as const, gap: '16px' }}>
                <Spinner size="large" />
                <span style={{ fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.1em' }}>
                    Loading Incidents...
                </span>
            </div>
        )
    }

    // ── Styles ───────────────────────────────────────────────────────────────

    const S = {
        container: { display: 'flex', flexDirection: 'column' as const, gap: '20px' },
        header: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap' as const, gap: '16px' },
        prefix: { fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.1em', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' },
        slash: { color: 'var(--accent-primary)', fontWeight: 700 },
        title: { fontFamily: 'var(--font-sans)', fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' as const, letterSpacing: '0.02em' },
        searchWrap: { display: 'flex', gap: '8px', alignItems: 'center' },
        searchBox: { display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px', background: 'var(--bg-card)', border: '2px solid var(--border-strong)', minWidth: '260px' },
        searchInput: { background: 'transparent', border: 'none', outline: 'none', fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-primary)', flex: 1 },
        searchBtn: { padding: '10px 20px', background: 'var(--accent-primary)', border: '2px solid var(--accent-primary)', fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: '#0a0a0a', cursor: 'pointer' },
        statsRow: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' },
        statCard: (alert: boolean) => ({
            background: alert ? 'var(--status-critical)' : 'var(--bg-card)',
            border: `2px solid ${alert ? 'var(--status-critical)' : 'var(--border-strong)'}`,
            padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '14px',
        }),
        statVal: (alert: boolean) => ({ fontFamily: 'var(--font-ui)', fontSize: '28px', fontWeight: 700, lineHeight: 1, color: alert ? '#fff' : 'var(--text-primary)' }),
        statLbl: (alert: boolean) => ({ fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 600, color: alert ? 'rgba(255,255,255,0.7)' : 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.08em' }),
        // Severity filter tabs
        tabs: { display: 'flex', gap: '0', border: '2px solid var(--border-strong)', width: 'fit-content' },
        tab: (active: boolean, sev: string) => ({
            padding: '7px 16px', cursor: 'pointer',
            fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 700,
            textTransform: 'uppercase' as const, letterSpacing: '0.05em',
            background: active ? (sev !== 'all' ? SEV_COLORS[sev] || 'var(--accent-primary)' : 'var(--accent-primary)') : 'transparent',
            color: active ? (sev === 'medium' ? '#0a0a0a' : sev === 'all' ? '#0a0a0a' : '#fff') : 'var(--text-muted)',
            border: 'none', borderRight: '1px solid var(--border-strong)',
        }),
        tableCard: { background: 'var(--bg-card)', border: '2px solid var(--border-strong)', overflow: 'hidden' },
        tableHead: { padding: '14px 20px', background: 'var(--bg-dark)', color: 'var(--text-inverse)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
        headTitle: { fontFamily: 'var(--font-ui)', fontSize: '12px', fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: '8px' },
        headPrefix: { color: 'var(--accent-primary)', fontWeight: 700 },
        headMeta: { fontFamily: 'var(--font-ui)', fontSize: '11px', color: 'rgba(255,255,255,0.4)', fontWeight: 400 },
        table: { width: '100%', borderCollapse: 'collapse' as const },
        th: { padding: '10px 16px', textAlign: 'left' as const, fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.08em', borderBottom: '2px solid var(--border-strong)', background: 'var(--bg-secondary)' },
        td: { padding: '12px 16px', borderBottom: '1px solid var(--border-light)', fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-primary)', verticalAlign: 'middle' as const },
        empty: { textAlign: 'center' as const, padding: '80px 40px' },
        emptyTitle: { fontFamily: 'var(--font-ui)', fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase' as const, marginBottom: '8px' },
        emptyText: { fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-muted)' },
    }

    const sevBadge = (sev: string): React.CSSProperties => ({
        display: 'inline-flex', alignItems: 'center', gap: '5px',
        padding: '3px 10px', fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 700,
        textTransform: 'uppercase', letterSpacing: '0.05em',
        background: SEV_COLORS[sev] || '#888', color: sev === 'medium' ? '#0a0a0a' : '#fff',
    })

    const statusBadge = (status: string): React.CSSProperties => {
        const map: Record<string, string> = { new: 'var(--status-critical)', investigating: 'var(--status-warning)', resolved: 'var(--status-success)', false_positive: 'var(--border-strong)' }
        return { display: 'inline-block', padding: '3px 10px', fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', background: map[status] || '#888', color: status === 'investigating' ? '#0a0a0a' : '#fff' }
    }

    const statusFilters = ['all', 'new', 'investigating', 'resolved']

    return (
        <div style={S.container}>
            {/* Header */}
            <div style={S.header}>
                <div>
                    <div style={S.prefix}><span style={S.slash}>//</span><span>Rule-Based Detection</span></div>
                    <h1 style={S.title}>Incidents</h1>
                </div>
                <div style={S.searchWrap}>
                    <div style={S.searchBox}>
                        <Search24Regular style={{ color: 'var(--text-muted)', fontSize: '18px' }} />
                        <input
                            type="text" placeholder="Search..."
                            style={S.searchInput} value={search}
                            onChange={e => setSearch(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && fetchData()}
                        />
                        {search && (
                            <Dismiss24Regular
                                style={{ color: 'var(--text-muted)', cursor: 'pointer', fontSize: '14px' }}
                                onClick={() => setSearch('')}
                            />
                        )}
                    </div>
                    <button style={S.searchBtn} onClick={fetchData}>Search</button>
                </div>
            </div>

            {/* Stats cards */}
            {stats && (
                <div style={S.statsRow}>
                    {[
                        { label: 'New',           val: stats.new,          alert: stats.new > 0,  icon: <Warning24Regular /> },
                        { label: 'Investigating', val: stats.investigating, alert: false,          icon: <Eye24Regular /> },
                        { label: 'Resolved',      val: stats.resolved,     alert: false,          icon: <Checkmark24Regular /> },
                        { label: 'Total',         val: stats.total,        alert: false,          icon: <Warning24Regular /> },
                    ].map(({ label, val, alert, icon }) => (
                        <div key={label} style={S.statCard(alert)}>
                            <span style={{ color: alert ? 'rgba(255,255,255,0.7)' : 'var(--text-muted)', fontSize: '20px' }}>{icon}</span>
                            <div>
                                <div style={S.statVal(alert)}>{val}</div>
                                <div style={S.statLbl(alert)}>{label}</div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Filters row */}
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                {/* Severity tabs */}
                <div style={S.tabs}>
                    {SEVERITY_FILTERS.map((sev, i) => (
                        <button
                            key={sev}
                            style={{ ...S.tab(sevFilter === sev, sev), borderRight: i < SEVERITY_FILTERS.length - 1 ? '1px solid var(--border-strong)' : 'none' }}
                            onClick={() => setSevFilter(sev)}
                        >
                            {sev === 'all' ? 'All Severity' : sev}
                            {sev !== 'all' && stats?.by_severity[sev] ? ` (${stats.by_severity[sev]})` : ''}
                        </button>
                    ))}
                </div>

                {/* Status filter */}
                <div style={S.tabs}>
                    {statusFilters.map((st, i) => (
                        <button
                            key={st}
                            style={{ ...S.tab(statusFilter === st, 'all'), borderRight: i < statusFilters.length - 1 ? '1px solid var(--border-strong)' : 'none' }}
                            onClick={() => setStatusFilter(st)}
                        >
                            {st === 'all' ? 'All Status' : st}
                        </button>
                    ))}
                </div>
            </div>

            {/* Table */}
            <div style={S.tableCard}>
                <div style={S.tableHead}>
                    <span style={S.headTitle}>
                        <span style={S.headPrefix}>//</span>
                        Incident Log
                    </span>
                    <span style={S.headMeta}>{incidents.length} shown — click row to expand</span>
                </div>

                {incidents.length === 0 ? (
                    <div style={S.empty}>
                        <div style={S.emptyTitle}>No Incidents</div>
                        <div style={S.emptyText}>
                            {sevFilter !== 'all' || statusFilter !== 'all'
                                ? 'No incidents match the current filters.'
                                : 'Run the THEIA replay — the rule engine will detect attack patterns.'}
                        </div>
                    </div>
                ) : (
                    <table style={S.table}>
                        <thead>
                            <tr>
                                <th style={{ ...S.th, width: '24px', padding: '10px 8px 10px 16px' }} />
                                <th style={S.th}>Severity</th>
                                <th style={S.th}>Title</th>
                                <th style={S.th}>Rule</th>
                                <th style={S.th}>Chain</th>
                                <th style={S.th}>Status</th>
                                <th style={S.th}>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {incidents.map(inc => (
                                <>
                                    <tr
                                        key={inc.incident_id}
                                        style={{
                                            cursor: 'pointer',
                                            background: expanded === inc.incident_id
                                                ? 'var(--bg-secondary)'
                                                : hoveredRow === inc.incident_id
                                                    ? 'color-mix(in srgb, var(--bg-secondary) 60%, transparent)'
                                                    : 'transparent',
                                            borderLeft: expanded === inc.incident_id
                                                ? `3px solid ${SEV_COLORS[inc.severity] || '#888'}`
                                                : '3px solid transparent',
                                        }}
                                        onClick={() => setExpanded(prev => prev === inc.incident_id ? null : inc.incident_id)}
                                        onMouseEnter={() => setHoveredRow(inc.incident_id)}
                                        onMouseLeave={() => setHoveredRow(null)}
                                    >
                                        {/* Expand chevron */}
                                        <td style={{ ...S.td, color: 'var(--text-muted)', paddingRight: '4px', paddingLeft: '12px' }}>
                                            {expanded === inc.incident_id
                                                ? <ChevronDown24Regular style={{ fontSize: '14px' }} />
                                                : <ChevronRight24Regular style={{ fontSize: '14px' }} />
                                            }
                                        </td>

                                        {/* Severity */}
                                        <td style={S.td}>
                                            <span style={sevBadge(inc.severity)}>{inc.severity}</span>
                                        </td>

                                        {/* Title + MITRE */}
                                        <td style={S.td}>
                                            <div style={{ fontWeight: 700 }}>{inc.title}</div>
                                            {inc.mitre_technique && (
                                                <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                                                    {inc.mitre_technique}
                                                </div>
                                            )}
                                        </td>

                                        {/* Rule badge */}
                                        <td style={S.td}>
                                            <span style={{
                                                display: 'inline-block', padding: '2px 8px',
                                                border: '2px solid var(--border-medium)',
                                                fontFamily: 'var(--font-ui)', fontSize: '10px',
                                                fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em',
                                            }}>
                                                {inc.rule_id.replace(/_/g, ' ')}
                                            </span>
                                        </td>

                                        {/* Mini chain preview */}
                                        <td style={S.td}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
                                                {inc.matched_edges.slice(0, 3).map((e, i) => (
                                                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
                                                        {i > 0 && <span style={{ color: 'var(--border-strong)', fontSize: '10px' }}>›</span>}
                                                        <span style={{
                                                            padding: '1px 6px', fontSize: '9px', fontWeight: 700,
                                                            fontFamily: 'var(--font-ui)', textTransform: 'uppercase',
                                                            background: 'var(--border-strong)', color: 'var(--text-muted)',
                                                        }}>{e.edge_type}</span>
                                                    </span>
                                                ))}
                                                {inc.matched_edges.length > 3 && (
                                                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>+{inc.matched_edges.length - 3}</span>
                                                )}
                                            </div>
                                        </td>

                                        {/* Status */}
                                        <td style={S.td}>
                                            <span style={statusBadge(inc.status)}>
                                                {inc.status.replace('_', ' ')}
                                            </span>
                                        </td>

                                        {/* Time */}
                                        <td style={{ ...S.td, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                                            {formatDate(inc.created_at)}
                                        </td>
                                    </tr>

                                    {expanded === inc.incident_id && (
                                        <IncidentDetail
                                            key={`detail-${inc.incident_id}`}
                                            incident={inc}
                                            onStatusChange={handleStatusChange}
                                        />
                                    )}
                                </>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    )
}

export default Incidents
