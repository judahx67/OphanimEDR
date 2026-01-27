import { NavLink } from 'react-router-dom'
import {
    Home24Regular,
    Desktop24Regular,
    Shield24Regular,
    WeatherMoon24Regular,
    WeatherSunny24Regular,
    Settings24Regular,
} from '@fluentui/react-icons'

interface SidebarProps {
    isDarkMode: boolean
    onToggleTheme: () => void
}

const styles = {
    sidebar: {
        width: '260px',
        height: '100%',
        background: 'var(--bg-card)',
        borderRight: '2px solid var(--border-strong)',
        display: 'flex',
        flexDirection: 'column' as const,
        position: 'relative' as const,
    },
    header: {
        padding: '20px 16px',
        borderBottom: '2px solid var(--border-strong)',
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
    },
    logoInner: {
        width: '16px',
        height: '16px',
        background: 'var(--bg-dark)',
        borderRadius: '50%',
    },
    logoText: {
        fontFamily: 'var(--font-mono)',
        fontSize: '14px',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
        color: 'var(--text-primary)',
    },
    logoSubtext: {
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 500,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.1em',
    },
    sectionHeader: {
        padding: '16px 16px 8px',
        fontFamily: 'var(--font-mono)',
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
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        fontWeight: 500,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.03em',
        border: '2px solid transparent',
        marginBottom: '4px',
        transition: 'all 0.1s ease',
    },
    linkHover: {
        background: 'var(--bg-secondary)',
    },
    linkActive: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '12px 12px',
        textDecoration: 'none',
        color: '#0a0a0a',  // Dark text on yellow for maximum contrast
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.03em',
        background: 'var(--accent-primary)',
        border: '2px solid var(--accent-primary)',
        marginBottom: '4px',
    },
    linkIcon: {
        fontSize: '20px',
        flexShrink: 0,
    },
    footer: {
        marginTop: 'auto',
        borderTop: '2px solid var(--border-strong)',
        padding: '12px 8px',
    },
    footerBtn: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '10px 12px',
        width: '100%',
        background: 'transparent',
        border: '2px solid var(--border-light)',
        cursor: 'pointer',
        color: 'var(--text-secondary)',
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 500,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
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
        fontFamily: 'var(--font-mono)',
        fontSize: '10px',
        fontWeight: 500,
        color: 'var(--text-muted)',
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
}

function Sidebar({ isDarkMode, onToggleTheme }: SidebarProps) {
    return (
        <aside style={styles.sidebar}>
            {/* Header/Logo */}
            <div style={styles.header}>
                <div style={styles.logo}>
                    <div style={styles.logoInner} />
                </div>
                <div>
                    <div style={styles.logoText}>Ophanim</div>
                    <div style={styles.logoSubtext}>EDR Terminal</div>
                </div>
            </div>

            {/* Navigation Section */}
            <div style={styles.sectionHeader}>
                <span style={styles.sectionPrefix}>//</span>
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
                    to="/problems"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <Shield24Regular style={styles.linkIcon} />
                    <span>Detections</span>
                </NavLink>
            </nav>

            {/* Footer Actions */}
            <div style={styles.footer}>
                <button
                    style={styles.footerBtn}
                    onClick={onToggleTheme}
                    title={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                    {isDarkMode ? <WeatherSunny24Regular /> : <WeatherMoon24Regular />}
                    <span>{isDarkMode ? 'Light Mode' : 'Dark Mode'}</span>
                </button>
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
