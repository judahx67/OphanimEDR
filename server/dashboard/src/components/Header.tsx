import { useLocation } from 'react-router-dom'
import { Alert24Regular, Search24Regular } from '@fluentui/react-icons'
import type { ThemeName } from '../App'

interface HeaderProps {
    theme: ThemeName
}

const isModern = (theme: ThemeName) => theme === 'light' || theme === 'dark'

function Header({ theme }: HeaderProps) {
    const location = useLocation()
    const modern = isModern(theme)
    const currentRoute = location.pathname

    const routeTitles: Record<string, string> = {
        '/': 'Dashboard',
        '/endpoints': 'Endpoints',
        '/problems': 'Detections',
    }
    const pageTitle = routeTitles[currentRoute] || 'Unknown'

    const now = new Date()
    const timeStr = now.toLocaleTimeString('en-US', { hour12: false })

    const styles = {
        header: {
            height: '60px',
            background: 'var(--bg-card)',
            borderBottom: modern ? '2px solid var(--border-strong)' : '1px solid var(--border-strong)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 24px',
            ...(theme === 'classic' ? { boxShadow: '0 1px 3px rgba(0,0,0,0.04)' } : {}),
        },
        left: {
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
        },
        breadcrumb: {
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontFamily: modern ? 'var(--font-mono)' : 'var(--font-sans)',
            fontSize: '13px',
            fontWeight: 600,
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.05em' : 'normal',
        },
        breadcrumbPrefix: {
            color: 'var(--accent-primary)',
            fontWeight: 700,
        },
        breadcrumbText: {
            color: 'var(--text-primary)',
        },
        breadcrumbSep: {
            color: 'var(--text-muted)',
            margin: '0 4px',
        },
        center: {
            display: 'flex',
            alignItems: 'center',
            gap: '24px',
        },
        searchBox: {
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            background: 'var(--bg-secondary)',
            border: modern ? '2px solid var(--border-light)' : '1px solid var(--border-medium)',
            borderRadius: modern ? '0' : '8px',
            minWidth: '300px',
        },
        searchIcon: {
            color: 'var(--text-muted)',
            fontSize: '18px',
        },
        searchInput: {
            background: 'transparent',
            border: 'none',
            outline: 'none',
            fontFamily: modern ? 'var(--font-mono)' : 'var(--font-sans)',
            fontSize: '12px',
            color: 'var(--text-primary)',
            flex: 1,
        },
        right: {
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
        },
        alertBtn: {
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '40px',
            height: '40px',
            background: 'transparent',
            border: modern ? '2px solid var(--border-strong)' : '1px solid var(--border-medium)',
            borderRadius: modern ? '0' : '8px',
            cursor: 'pointer',
            color: 'var(--text-primary)',
            position: 'relative' as const,
        },
        alertBadge: {
            position: 'absolute' as const,
            top: '-4px',
            right: '-4px',
            width: '16px',
            height: '16px',
            background: 'var(--status-critical)',
            color: '#ffffff',
            fontSize: '10px',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontFamily: 'var(--font-mono)',
            borderRadius: modern ? '0' : '50%',
        },
        timestamp: {
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: 'var(--text-muted)',
            textTransform: 'uppercase' as const,
            letterSpacing: '0.05em',
        },
    }

    return (
        <header style={styles.header}>
            <div style={styles.left}>
                <div style={styles.breadcrumb}>
                    {modern && <span style={styles.breadcrumbPrefix}>//</span>}
                    <span style={styles.breadcrumbText}>Ophanim</span>
                    <span style={styles.breadcrumbSep}>/</span>
                    <span style={styles.breadcrumbText}>{pageTitle}</span>
                </div>
            </div>

            <div style={styles.center}>
                <div style={styles.searchBox}>
                    <Search24Regular style={styles.searchIcon} />
                    <input
                        type="text"
                        placeholder="Search endpoints, detections..."
                        style={styles.searchInput}
                    />
                </div>
            </div>

            <div style={styles.right}>
                <span style={styles.timestamp}>{timeStr}</span>
                <button style={styles.alertBtn}>
                    <Alert24Regular />
                    <span style={styles.alertBadge}>3</span>
                </button>
            </div>
        </header>
    )
}

export default Header
