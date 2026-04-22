import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { Layout } from '@/components/layout/Layout'
import { ErrorBoundary } from '@/components/shared/ErrorBoundary'

// Lazy-load pages so each route becomes its own chunk
const Dashboard    = lazy(() => import('@/pages/Dashboard').then(m => ({ default: m.Dashboard })))
const ScanTerminal = lazy(() => import('@/pages/ScanTerminal').then(m => ({ default: m.ScanTerminal })))
const Report       = lazy(() => import('@/pages/Report').then(m => ({ default: m.Report })))
const History      = lazy(() => import('@/pages/History').then(m => ({ default: m.History })))

function PageLoader() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <span className="font-mono text-xs text-terminal-dim animate-pulse tracking-widest">
        LOADING...
      </span>
    </div>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <Layout>
        <AnimatePresence mode="wait">
          <Suspense fallback={<PageLoader />}>
            <Routes>
              <Route path="/"               element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
              <Route path="/scan"           element={<Navigate to="/" replace />} />
              <Route path="/scan/:scanId"   element={<ErrorBoundary><ScanTerminal /></ErrorBoundary>} />
              <Route path="/report/:scanId" element={<ErrorBoundary><Report /></ErrorBoundary>} />
              <Route path="/history"        element={<ErrorBoundary><History /></ErrorBoundary>} />
              <Route path="*"               element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </AnimatePresence>
      </Layout>
    </ErrorBoundary>
  )
}
