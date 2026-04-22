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
