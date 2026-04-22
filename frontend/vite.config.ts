import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      // Use the CJS build — Vite/esbuild converts CJS→ESM, preserving named exports.
      // The ESM build (dist/es/) is incomplete in this install; UMD doesn't expose names.
      'framer-motion': path.resolve(
        __dirname,
        'node_modules/framer-motion/dist/cjs/index.js'
      ),
    },
  },
  optimizeDeps: {
    include: ['framer-motion'],
    // Force esbuild to pre-bundle framer-motion as CJS→ESM so named imports work
    esbuildOptions: {
      format: 'esm',
    },
  },
  build: {
    rollupOptions: {
      // Suppress the harmless SignalR /*#__PURE__*/ position warnings
      onwarn(warning, warn) {
        if (
          warning.code === 'INVALID_ANNOTATION' &&
          warning.id?.includes('@microsoft/signalr')
        ) return
        warn(warning)
      },
      output: {
        manualChunks: {
          // React core — almost never changes
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          // Heavy animation lib
          'vendor-motion': ['framer-motion'],
          // Data-fetching + state
          'vendor-query': ['@tanstack/react-query'],
          // Real-time transport
          'vendor-signalr': ['@microsoft/signalr'],
          // i18n strings
          'vendor-i18n': ['i18next', 'react-i18next'],
          // Icon set (lucide ships every icon, bulk of the bytes)
          'vendor-icons': ['lucide-react'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/hubs': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
