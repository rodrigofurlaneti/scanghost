import { Routes, Route, Navigate } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { Layout } from '@/components/layout/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { ScanTerminal } from '@/pages/ScanTerminal'
import { Report } from '@/pages/Report'
import { History } from '@/pages/History'

export default function App() {
  return (
    <Layout>
      <AnimatePresence mode="wait">
        <Routes>
          <Route path="/"              element={<Dashboard />} />
          <Route path="/scan"          element={<Navigate to="/" replace />} />
          <Route path="/scan/:scanId"  element={<ScanTerminal />} />
          <Route path="/report/:scanId" element={<Report />} />
          <Route path="/history"       element={<History />} />
          <Route path="*"              element={<Navigate to="/" replace />} />
        </Routes>
      </AnimatePresence>
    </Layout>
  )
}
