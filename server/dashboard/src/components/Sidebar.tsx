import { NavLink } from 'react-router-dom'
import {
    Home24Regular,
    Desktop24Regular,
    Shield24Regular,
    Warning24Regular,
    Settings24Regular,
    PaintBrush24Regular,
    BrainCircuit24Regular,
} from '@fluentui/react-icons'
import type { ThemeName } from '../App'

interface SidebarProps {
    theme: ThemeName
    onSetTheme: (theme: ThemeName) => void
}

const isModern = (theme: ThemeName) => theme === 'light' || theme === 'dark'

function Sidebar({ theme, onSetTheme }: SidebarProps) {
    const modern = isModern(theme)

    const styles = {
        sidebar: {
            width: '260px',
            height: '100%',
            background: 'var(--bg-card)',
            borderRight: modern ? '2px solid var(--border-strong)' : '1px solid var(--border-strong)',
            display: 'flex',
            flexDirection: 'column' as const,
            position: 'relative' as const,
            ...(theme === 'classic' ? { boxShadow: '1px 0 4px rgba(0,0,0,0.04)' } : {}),
        },
        header: {
            padding: '20px 16px',
            borderBottom: modern ? '2px solid var(--border-strong)' : '1px solid var(--border-strong)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
        },
        logo: {
            width: '40px',
            height: '40px',
            background: 'var(--accent-primary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative' as const,
            borderRadius: modern ? '0' : '8px',
        },
        logoInner: {
            width: '16px',
            height: '16px',
            background: modern ? 'var(--bg-dark)' : '#ffffff',
            borderRadius: '50%',
        },
        logoText: {
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '14px',
            fontWeight: 700,
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.05em' : 'normal',
            color: 'var(--text-primary)',
        },
        logoSubtext: {
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '10px',
            fontWeight: 500,
            color: 'var(--text-muted)',
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.1em' : 'normal',
        },
        sectionHeader: {
            padding: '16px 16px 8px',
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '11px',
            fontWeight: 600,
            textTransform: 'uppercase' as const,
            letterSpacing: '0.1em',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
        },
        sectionPrefix: {
            color: 'var(--accent-primary)',
            fontWeight: 700,
        },
        nav: {
            display: 'flex',
            flexDirection: 'column' as const,
            padding: '0 8px',
            flex: 1,
        },
        link: {
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 12px',
            textDecoration: 'none',
            color: 'var(--text-secondary)',
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '13px',
            fontWeight: 500,
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.03em' : 'normal',
            border: modern ? '2px solid transparent' : '1px solid transparent',
            borderRadius: modern ? '0' : '6px',
            marginBottom: '4px',
            transition: 'all 0.15s ease',
        },
        linkActive: {
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 12px',
            textDecoration: 'none',
            color: modern ? '#0a0a0a' : '#ffffff',
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '13px',
            fontWeight: 600,
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.03em' : 'normal',
            background: 'var(--accent-primary)',
            border: modern ? '2px solid var(--accent-primary)' : '1px solid var(--accent-primary)',
            borderRadius: modern ? '0' : '6px',
            marginBottom: '4px',
        },
        linkIcon: {
            fontSize: '20px',
            flexShrink: 0,
        },
        footer: {
            marginTop: 'auto',
            borderTop: modern ? '2px solid var(--border-strong)' : '1px solid var(--border-strong)',
            padding: '12px 8px',
        },
        themeSection: {
            padding: '8px 12px',
            marginBottom: '8px',
        },
        themeLabel: {
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '10px',
            fontWeight: 600,
            color: 'var(--text-muted)',
            textTransform: 'uppercase' as const,
            letterSpacing: '0.08em',
            marginBottom: '8px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
        },
        themeButtons: {
            display: 'flex',
            gap: '4px',
        },
        themeBtn: (isActive: boolean) => ({
            flex: 1,
            padding: '6px 4px',
            background: isActive ? 'var(--accent-primary)' : 'var(--bg-secondary)',
            border: modern
                ? `2px solid ${isActive ? 'var(--accent-primary)' : 'var(--border-light)'}`
                : `1px solid ${isActive ? 'var(--accent-primary)' : 'var(--border-medium)'}`,
            borderRadius: modern ? '0' : '4px',
            cursor: 'pointer',
            color: isActive
                ? (modern ? '#0a0a0a' : '#ffffff')
                : 'var(--text-secondary)',
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '10px',
            fontWeight: isActive ? 700 : 500,
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.03em' : 'normal',
            transition: 'all 0.1s ease',
        }),
        footerBtn: {
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '10px 12px',
            width: '100%',
            background: 'transparent',
            border: modern ? '2px solid var(--border-light)' : '1px solid var(--border-medium)',
            borderRadius: modern ? '0' : '6px',
            cursor: 'pointer',
            color: 'var(--text-secondary)',
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '11px',
            fontWeight: 500,
            textTransform: modern ? 'uppercase' as const : 'none' as const,
            letterSpacing: modern ? '0.05em' : 'normal',
            transition: 'all 0.1s ease',
            marginBottom: '4px',
        },
        statusBar: {
            padding: '12px 16px',
            background: 'var(--bg-secondary)',
            borderTop: '1px solid var(--border-light)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
        },
        statusDot: {
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: 'var(--status-success)',
        },
        statusText: {
            fontFamily: modern ? 'var(--font-ui)' : 'var(--font-sans)',
            fontSize: '10px',
            fontWeight: 500,
            color: 'var(--text-muted)',
            textTransform: 'uppercase' as const,
            letterSpacing: '0.05em',
        },
    }

    const themes: { key: ThemeName; label: string }[] = [
        { key: 'classic', label: 'Classic' },
        { key: 'light', label: 'Modern' },
        { key: 'dark', label: 'Dark' },
    ]

    return (
        <aside style={styles.sidebar}>
            {/* Header/Logo */}
            <div style={styles.header}>
                <div style={styles.logo}>
                    <div style={styles.logoInner} />
                </div>
                <div>
                    <div style={styles.logoText}>Ophanim</div>
                    <div style={styles.logoSubtext}>
                        {modern ? 'EDR Terminal' : 'EDR Dashboard'}
                    </div>
                </div>
            </div>

            {/* Navigation Section */}
            <div style={styles.sectionHeader}>
                {modern && <span style={styles.sectionPrefix}>//</span>}
                <span>Navigation</span>
            </div>

            <nav style={styles.nav}>
                <NavLink
                    to="/"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                    end
                >
                    <Home24Regular style={styles.linkIcon} />
                    <span>Dashboard</span>
                </NavLink>

                <NavLink
                    to="/endpoints"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <Desktop24Regular style={styles.linkIcon} />
                    <span>Endpoints</span>
                </NavLink>

                <NavLink
                    to="/incidents"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <Warning24Regular style={styles.linkIcon} />
                    <span>Incidents</span>
                </NavLink>

                <NavLink
                    to="/problems"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <Shield24Regular style={styles.linkIcon} />
                    <span>Detections</span>
                </NavLink>

                <NavLink
                    to="/compare"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <BrainCircuit24Regular style={styles.linkIcon} />
                    <span>FLASH vs Orthrus-style</span>
                </NavLink>

            </nav>

            {/* Footer Actions */}
            <div style={styles.footer}>
                {/* Theme Selector */}
                <div style={styles.themeSection}>
                    <div style={styles.themeLabel}>
                        <PaintBrush24Regular style={{ fontSize: '14px' }} />
                        Theme
                    </div>
                    <div style={styles.themeButtons}>
                        {themes.map(t => (
                            <button
                                key={t.key}
                                style={styles.themeBtn(theme === t.key)}
                                onClick={() => onSetTheme(t.key)}
                                title={`Switch to ${t.label} theme`}
                            >
                                {t.label}
                            </button>
                        ))}
                    </div>
                </div>

                <button style={styles.footerBtn}>
                    <Settings24Regular />
                    <span>Settings</span>
                </button>
            </div>

            {/* Status Bar */}
            <div style={styles.statusBar}>
                <div style={styles.statusDot} />
                <span style={styles.statusText}>System Online</span>
            </div>
        </aside>
    )
}

export default Sidebar
