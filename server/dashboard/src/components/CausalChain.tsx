// Shared causal-chain edge display — the clearer subject→edge→object pill view
// used on /incidents and /compare. Extracted so both pages render edges identically.

export interface MatchedNode { id: string; type: string; name: string }
export interface MatchedEdge {
    event_id: string; edge_type: string
    subject_id: string; subject_name: string
    object_id: string; object_name: string
    timestamp: number
}

export const NODE_COLORS: Record<string, string> = {
    PROCESS: '#eab308', FILE: '#6366f1', SOCKET: '#06b6d4',
    MEMORY: '#f97316', PIPE: '#8b5cf6', REGISTRY: '#ec4899',
}
export const NODE_TEXT_COLOR: Record<string, string> = {
    PROCESS: '#0a0a0a',
}

export function CausalChain({ edges, nodes }: { edges: MatchedEdge[]; nodes: MatchedNode[] }) {
    if (edges.length === 0)
        return <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-ui)' }}>No edge data</span>

    const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]))

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {edges.map((edge, i) => {
                const subjType = nodeMap[edge.subject_id]?.type || 'PROCESS'
                const objType = nodeMap[edge.object_id]?.type || 'FILE'
                const subjName = edge.subject_name || edge.subject_id?.slice(0, 12) || '?'
                const objName = edge.object_name || edge.object_id?.slice(0, 12) || '?'

                const pillBase: React.CSSProperties = {
                    display: 'inline-block', padding: '3px 10px',
                    fontFamily: 'var(--font-ui)', fontSize: '11px', fontWeight: 700,
                    maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                }
                const subjStyle: React.CSSProperties = { ...pillBase, background: NODE_COLORS[subjType] || '#888', color: NODE_TEXT_COLOR[subjType] || '#fff' }
                const objStyle: React.CSSProperties = { ...pillBase, background: NODE_COLORS[objType] || '#888', color: NODE_TEXT_COLOR[objType] || '#fff' }
                const edgeStyle: React.CSSProperties = {
                    display: 'flex', alignItems: 'center', gap: '4px',
                    fontFamily: 'var(--font-ui)', fontSize: '10px', fontWeight: 700,
                    color: 'var(--accent-primary)', whiteSpace: 'nowrap', padding: '0 4px',
                }

                return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
                        <span style={{
                            width: '18px', height: '18px', borderRadius: '50%',
                            background: 'var(--border-strong)', display: 'flex',
                            alignItems: 'center', justifyContent: 'center',
                            fontFamily: 'var(--font-ui)', fontSize: '9px',
                            fontWeight: 700, color: 'var(--text-muted)', flexShrink: 0,
                        }}>{i + 1}</span>
                        <span style={subjStyle} title={subjName}>{subjName}</span>
                        <span style={edgeStyle}>
                            <span style={{ color: 'var(--border-strong)' }}>──</span>
                            {edge.edge_type}
                            <span style={{ color: 'var(--accent-primary)' }}>──▶</span>
                        </span>
                        <span style={objStyle} title={objName}>{objName}</span>
                    </div>
                )
            })}
        </div>
    )
}

export function NodeLegend({ nodes }: { nodes: MatchedNode[] }) {
    const byType: Record<string, MatchedNode[]> = {}
    nodes.forEach(n => { byType[n.type] = byType[n.type] || []; byType[n.type].push(n) })
    if (Object.keys(byType).length === 0) return null

    return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '8px' }}>
            {Object.entries(byType).map(([type, ns]) => (
                ns.map((n, i) => (
                    <span key={`${type}-${i}`} style={{
                        padding: '2px 8px', fontFamily: 'var(--font-ui)', fontSize: '10px',
                        background: NODE_COLORS[type] || '#888',
                        color: NODE_TEXT_COLOR[type] || '#fff',
                        border: '1px solid rgba(255,255,255,0.15)',
                    }} title={`${type}: ${n.name}`}>
                        {type[0]}: {n.name.length > 24 ? '...' + n.name.slice(-20) : n.name}
                    </span>
                ))
            ))}
        </div>
    )
}
