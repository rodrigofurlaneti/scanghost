import { Routes, Route, Navigate } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { Layout } from '@/components/layout/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { ScanTerminal } from '@/pages/ScanTerminal'
import { Report } from '@/pages/Report'
import { History } from '@/pages/History'
import { ErrorBoundary } from '@/components/shared/ErrorBoundary'

export default function App() {
  return (
    <ErrorBoundary>
      <Layout>
        <AnimatePresence mode="wait">
          <Routes>
            <Route path="/"               element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
            <Route path="/scan"           element={<Navigate to="/" replace />} />
            <Route path="/scan/:scanId"   element={<ErrorBoundary><ScanTerminal /></ErrorBoundary>} />
            <Route path="/report/:scanId" element={<ErrorBoundary><Report /></ErrorBoundary>} />
            <Route path="/history"        element={<ErrorBoundary><History /></ErrorBoundary>} />
            <Route path="*"              element={<Navigate to="/" replace />} />
          </Routes>
        </AnimatePresence>
      </Layout>
    </ErrorBoundary>
  )
}
