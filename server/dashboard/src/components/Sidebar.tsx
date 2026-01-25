import { NavLink } from 'react-router-dom'
import {
    Home24Regular,
    Desktop24Regular,
    Shield24Regular,
    WeatherMoon24Regular,
    WeatherSunny24Regular,
} from '@fluentui/react-icons'

interface SidebarProps {
    isDarkMode: boolean
    onToggleTheme: () => void
}

const styles = {
    sidebar: {
        width: '240px',
        height: '100%',
        background: 'var(--bg-card)',
        borderRight: '1px solid var(--border-light)',
        display: 'flex',
        flexDirection: 'column' as const,
        padding: '24px 16px',
    },
    brand: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '8px 12px',
        marginBottom: '8px',
    },
    brandIcon: {
        width: '36px',
        height: '36px',
        border: '2px solid var(--accent-indigo)',
        borderRadius: '50%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative' as const,
    },
    brandEye: {
        width: '16px',
        height: '10px',
        background: 'var(--accent-gold)',
        borderRadius: '50% / 50%',
        clipPath: 'ellipse(50% 50% at 50% 50%)',
    },
    brandText: {
        fontFamily: "'Crimson Pro', Georgia, serif",
        fontSize: '22px',
        fontWeight: 600,
        color: 'var(--accent-indigo)',
        letterSpacing: '-0.02em',
    },
    divider: {
        height: '1px',
        background: 'linear-gradient(90deg, transparent 0%, var(--border-light) 50%, transparent 100%)',
        margin: '16px 0',
    },
    sectionLabel: {
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.1em',
        color: 'var(--text-muted)',
        padding: '0 12px',
        marginBottom: '8px',
    },
    nav: {
        display: 'flex',
        flexDirection: 'column' as const,
        gap: '2px',
        flex: 1,
    },
    link: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '10px 12px',
        textDecoration: 'none',
        color: 'var(--text-secondary)',
        fontSize: '14px',
        fontWeight: 500,
        borderLeft: '2px solid transparent',
        transition: 'all 0.15s ease',
    },
    linkActive: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '10px 12px',
        textDecoration: 'none',
        color: 'var(--accent-indigo)',
        fontSize: '14px',
        fontWeight: 600,
        background: 'var(--bg-secondary)',
        borderLeft: '2px solid var(--accent-gold)',
    },
    options: {
        marginTop: 'auto',
        padding: '8px 0',
    },
    optionButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '10px 12px',
        width: '100%',
        background: 'transparent',
        border: 'none',
        cursor: 'pointer',
        color: 'var(--text-secondary)',
        fontSize: '14px',
        fontWeight: 500,
        transition: 'all 0.15s ease',
    },
}

function Sidebar({ isDarkMode, onToggleTheme }: SidebarProps) {
    return (
        <aside style={styles.sidebar}>
            <div style={styles.brand}>
                <div style={styles.brandIcon}>
                    <div style={styles.brandEye} />
                </div>
                <span style={styles.brandText}>Ophanim</span>
            </div>

            <div style={styles.divider} />

            <div style={styles.sectionLabel}>Navigation</div>

            <nav style={styles.nav}>
                <NavLink
                    to="/"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                    end
                >
                    <Home24Regular />
                    <span>Dashboard</span>
                </NavLink>

                <NavLink
                    to="/endpoints"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <Desktop24Regular />
                    <span>Endpoints</span>
                </NavLink>

                <NavLink
                    to="/problems"
                    style={({ isActive }) => isActive ? styles.linkActive : styles.link}
                >
                    <Shield24Regular />
                    <span>Detections</span>
                </NavLink>
            </nav>

            <div style={styles.options}>
                <button
                    style={styles.optionButton}
                    onClick={onToggleTheme}
                    title={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                    {isDarkMode ? <WeatherSunny24Regular /> : <WeatherMoon24Regular />}
                    <span>{isDarkMode ? 'Light Mode' : 'Dark Mode'}</span>
                </button>
            </div>
        </aside>
    )
}

export default Sidebar
