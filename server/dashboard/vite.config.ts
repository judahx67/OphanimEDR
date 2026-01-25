import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In Docker, use 'backend:8000', otherwise 'localhost:8000'
const apiTarget = process.env.VITE_API_TARGET || 'http://localhost:8000'

export default defineConfig({
    plugins: [react()],
    server: {
        port: 3000,
        proxy: {
            '/api': {
                target: apiTarget,
                changeOrigin: true,
            },
        },
    },
})
