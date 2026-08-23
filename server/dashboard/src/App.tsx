import { useState, useEffect } from 'react'
import { Routes, Route } from 'react-router-dom'
import {
    FluentProvider,
    webLightTheme,
    webDarkTheme,
} from '@fluentui/react-components'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import EndpointsList from './pages/EndpointsList'
import EndpointDetails from './pages/EndpointDetails'
import Dashboard from './pages/Dashboard'
import Incidents from './pages/Incidents'
import Compare from './pages/Compare'

export type ThemeName = 'classic' | 'light' | 'dark'

const appStyles = {
    root: {
        display: 'flex',
        height: '100vh',
        width: '100vw',
        overflow: 'hidden',
        position: 'relative' as const,
        zIndex: 1,
    },
    main: {
        flex: 1,
        display: 'flex',
        flexDirection: 'column' as const,
        overflow: 'hidden',
    },
    content: {
        flex: 1,
        overflow: 'auto',
        padding: '32px 40px',
    },
}

const classicLightTheme = {
    ...webLightTheme,
    fontFamilyBase: "'Inter', -apple-system, system-ui, sans-serif",
}

const fluentThemeMap = {
    classic: classicLightTheme,
    light: webLightTheme,
    dark: webDarkTheme,
}

function App() {
    const [theme, setTheme] = useState<ThemeName>(() => {
        const saved = localStorage.getItem('ophanim-theme') as ThemeName | null
        if (saved && ['classic', 'light', 'dark'].includes(saved)) return saved
        return 'classic'  // Default to professional theme
    })

    const handleSetTheme = (newTheme: ThemeName) => {
        setTheme(newTheme)
        localStorage.setItem('ophanim-theme', newTheme)
    }

    // Apply theme to document
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme)
    }, [theme])

    return (
        <FluentProvider theme={fluentThemeMap[theme]}>
            <div style={appStyles.root}>
                <Sidebar theme={theme} onSetTheme={handleSetTheme} />
                <div style={appStyles.main}>
                    <Header theme={theme} />
                    <main style={appStyles.content}>
                        <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/endpoints" element={<EndpointsList />} />
                            <Route path="/endpoints/:id" element={<EndpointDetails />} />
                            <Route path="/incidents" element={<Incidents />} />
                            <Route path="/compare" element={<Compare />} />
                        </Routes>
                    </main>
                </div>
            </div>
        </FluentProvider>
    )
}

export default App

