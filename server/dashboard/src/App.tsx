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
import Problems from './pages/Problems'

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

function App() {
    const [isDarkMode, setIsDarkMode] = useState(() => {
        // Check localStorage for saved preference
        const saved = localStorage.getItem('ophanim-theme')
        return saved === 'dark'
    })

    const toggleTheme = () => {
        setIsDarkMode(prev => {
            const newValue = !prev
            localStorage.setItem('ophanim-theme', newValue ? 'dark' : 'light')
            return newValue
        })
    }

    // Apply theme to document
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', isDarkMode ? 'dark' : 'light')
    }, [isDarkMode])

    return (
        <FluentProvider theme={isDarkMode ? webDarkTheme : webLightTheme}>
            <div style={appStyles.root}>
                <Sidebar isDarkMode={isDarkMode} onToggleTheme={toggleTheme} />
                <div style={appStyles.main}>
                    <Header onToggleTheme={toggleTheme} />
                    <main style={appStyles.content}>
                        <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/endpoints" element={<EndpointsList />} />
                            <Route path="/endpoints/:id" element={<EndpointDetails />} />
                            <Route path="/problems" element={<Problems />} />
                        </Routes>
                    </main>
                </div>
            </div>
        </FluentProvider>
    )
}

export default App
