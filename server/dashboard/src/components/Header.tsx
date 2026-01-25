import { Button, Tooltip } from '@fluentui/react-components'
import { Settings24Regular } from '@fluentui/react-icons'

interface HeaderProps {
    onToggleTheme: () => void
}

const styles = {
    header: {
        height: '56px',
        background: 'var(--bg-card)',
        borderBottom: '1px solid var(--border-light)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 40px',
    },
    left: {
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
    },
    status: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '12px',
        color: 'var(--text-secondary)',
    },
    statusDot: {
        width: '6px',
        height: '6px',
        borderRadius: '50%',
        background: 'var(--status-online)',
    },
    right: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
    iconButton: {
        minWidth: '32px',
        height: '32px',
        border: '1px solid var(--border-light)',
        background: 'transparent',
        color: 'var(--text-secondary)',
    },
}

function Header({ onToggleTheme: _onToggleTheme }: HeaderProps) {
    return (
        <header style={styles.header}>
            <div style={styles.left}>
                <div style={styles.status}>
                    <div style={styles.statusDot} />
                    <span>All systems operational</span>
                </div>
            </div>

            <div style={styles.right}>
                <Tooltip content="Settings" relationship="label">
                    <Button
                        appearance="subtle"
                        icon={<Settings24Regular />}
                        style={styles.iconButton}
                    />
                </Tooltip>
            </div>
        </header>
    )
}

export default Header
