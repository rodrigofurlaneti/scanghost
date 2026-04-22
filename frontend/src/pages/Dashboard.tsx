import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  Search, Shield, Activity, Target, AlertTriangle,
  ChevronRight, Clock, Loader2, Zap,
} from 'lucide-react'

import { MatrixRain } from '@/components/shared/MatrixRain'
import { GlitchText } from '@/components/shared/GlitchText'
import { StatCard } from '@/components/shared/StatCard'
import { TerminalCard } from '@/components/shared/TerminalCard'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { startScan, getScans } from '@/api/client'
import { formatDate, formatDuration } from '@/lib/utils'
import type { ScanProfile } from '@/types'

const PROFILES: ScanProfile[] = ['Quick', 'Standard', 'Deep']

export function Dashboard() {
  const { t } = useTranslation()
  const navigate = useNavigate()

  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState<ScanProfile>('Standard')
  const [error, setError] = useState('')

  const { data: scansData } = useQuery({
    queryKey: ['scans', 1, 5],
    queryFn: () => getScans(1, 5),
    refetchInterval: 8000,
  })

  const scanMutation = useMutation({
    mutationFn: startScan,
    onSuccess: ({ scanId }) => navigate(`/scan/${scanId}`),
    onError: () => setError('Failed to start scan. Check the target and try again.'),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    const t2 = target.trim()
    if (!t2) { setError('Target is required'); return }
    scanMutation.mutate({ target: t2, profile })
  }

  const scans = scansData?.items ?? []

  // Derived stats from recent scans
  const totalScans   = scansData?.totalCount ?? 0
  const criticalCount = scans.reduce((a, s) => a + (s.findingsCount > 0 ? 1 : 0), 0)
  const uniqueTargets = new Set(scans.map(s => s.target)).size

  return (
    <div className="relative min-h-full overflow-auto">
      {/* Matrix rain background */}
      <div className="fixed inset-0 pointer-events-none">
        <MatrixRain opacity={0.08} speed={0.7} density={0.025} />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 py-6 sm:py-10">

        {/* ── Hero ──────────────────────────────────────────── */}
        <motion.div
          className="text-center mb-10 sm:mb-14"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-sm border border-matrix-400/30 bg-matrix-400/5 mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-matrix-400 animate-pulse" />
            <span className="font-mono text-xs text-matrix-400 tracking-widest uppercase">
              System Online
            </span>
          </div>

          <GlitchText
            text="GHOSTSCAN"
            tag="h1"
            className="neon-text font-mono font-bold tracking-[0.25em] text-4xl sm:text-5xl lg:text-6xl 4k:text-8xl mb-3"
            glitchInterval={4000}
          />
          <p className="font-mono text-sm sm:text-base text-terminal-dim max-w-lg mx-auto">
            {t('dashboard.subtitle')}
          </p>
        </motion.div>

        {/* ── Stats row ─────────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-8">
          <StatCard
            label={t('dashboard.stats.totalScans')}
            value={totalScans}
            icon={Shield}
            color="#00FF41"
            delay={0.05}
          />
          <StatCard
            label={t('dashboard.stats.critical')}
            value={criticalCount}
            icon={AlertTriangle}
            color="#ff0033"
            delay={0.1}
          />
          <StatCard
            label={t('dashboard.stats.targets')}
            value={uniqueTargets}
            icon={Target}
            color="#00aaff"
            delay={0.15}
          />
          <StatCard
            label="Active Scans"
            value={scans.filter(s => s.status === 'Running').length}
            icon={Activity}
            color="#ffcc00"
            delay={0.2}
          />
        </div>

        {/* ── Scan form ─────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.25 }}
        >
          <TerminalCard
            title={t('dashboard.quickScan')}
            neon
            className="mb-8"
          >
            <form onSubmit={handleSubmit} className="p-4 sm:p-6 space-y-4">
              {/* Target input */}
              <div>
                <label className="block font-mono text-xs text-terminal-dim uppercase tracking-widest mb-2">
                  Target
                </label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search
                      size={14}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-terminal-ghost pointer-events-none"
                    />
                    <input
                      type="text"
                      value={target}
                      onChange={e => { setTarget(e.target.value); setError('') }}
                      placeholder={t('dashboard.targetPlaceholder')}
                      className="terminal-input pl-8 text-base"
                      disabled={scanMutation.isPending}
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </div>
                </div>
                {error && (
                  <p className="mt-1.5 font-mono text-xs text-red-400">{error}</p>
                )}
              </div>

              {/* Profile selection */}
              <div>
                <label className="block font-mono text-xs text-terminal-dim uppercase tracking-widest mb-2">
                  {t('dashboard.profile')}
                </label>
                <div className="flex flex-wrap gap-2">
                  {PROFILES.map(p => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => setProfile(p)}
                      className={`
                        px-4 py-2 rounded-sm font-mono text-xs uppercase tracking-widest
                        border transition-all duration-200
                        ${profile === p
                          ? 'border-matrix-400 text-matrix-400 bg-matrix-400/10 shadow-[0_0_12px_rgba(0,255,65,0.2)]'
                          : 'border-terminal-border text-terminal-dim hover:border-terminal-muted hover:text-matrix-400'
                        }
                      `}
                    >
                      <span className="flex items-center gap-1.5">
                        {p === 'Quick' && <Zap size={11} />}
                        {p === 'Standard' && <Shield size={11} />}
                        {p === 'Deep' && <Target size={11} />}
                        {p}
                      </span>
                    </button>
                  ))}
                </div>
                <p className="mt-1.5 font-mono text-xs text-terminal-ghost">
                  {t(`dashboard.profiles.${profile}`)}
                </p>
              </div>

              {/* Submit */}
              <div className="flex items-center gap-3 pt-2">
                <button
                  type="submit"
                  disabled={scanMutation.isPending || !target.trim()}
                  className="btn-ghost-scan flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {scanMutation.isPending ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Search size={14} />
                  )}
                  {t('dashboard.startScan')}
                </button>
              </div>
            </form>
          </TerminalCard>
        </motion.div>

        {/* ── Recent scans ──────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.35 }}
        >
          <TerminalCard
            title={t('dashboard.recentScans')}
            titleRight={
              <button
                onClick={() => navigate('/history')}
                className="font-mono text-xs text-terminal-dim hover:text-matrix-400 flex items-center gap-1 transition-colors"
              >
                View all <ChevronRight size={12} />
              </button>
            }
          >
            {scans.length === 0 ? (
              <div className="px-4 py-12 text-center">
                <p className="font-mono text-sm text-terminal-ghost">
                  {t('dashboard.noScans')}
                </p>
              </div>
            ) : (
              <div className="divide-y divide-terminal-border overflow-x-auto">
                {/* Header */}
                <div className="hidden sm:grid grid-cols-[2fr_1fr_1fr_1fr_auto] gap-4 px-4 py-2">
                  {['target', 'profile', 'status', 'findings', ''].map(h => (
                    <span key={h} className="font-mono text-xs text-terminal-ghost uppercase tracking-wider">
                      {h}
                    </span>
                  ))}
                </div>

                {scans.map((scan, i) => (
                  <motion.div
                    key={scan.id}
                    className="px-4 py-3 hover:bg-terminal-muted/30 transition-colors cursor-pointer"
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    onClick={() =>
                      scan.status === 'Completed' || scan.status === 'Failed'
                        ? navigate(`/report/${scan.id}`)
                        : navigate(`/scan/${scan.id}`)
                    }
                  >
                    {/* Mobile layout */}
                    <div className="sm:hidden flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="font-mono text-sm text-matrix-400 truncate">{scan.target}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <StatusBadge status={scan.status} pulse />
                          <span className="font-mono text-xs text-terminal-dim">{scan.profile}</span>
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className="font-mono text-sm text-matrix-400">{scan.findingsCount}</p>
                        <p className="font-mono text-xs text-terminal-ghost">findings</p>
                      </div>
                    </div>

                    {/* Desktop layout */}
                    <div className="hidden sm:grid grid-cols-[2fr_1fr_1fr_1fr_auto] gap-4 items-center">
                      <div className="min-w-0">
                        <p className="font-mono text-sm text-matrix-400 truncate">{scan.target}</p>
                        <p className="font-mono text-xs text-terminal-ghost flex items-center gap-1 mt-0.5">
                          <Clock size={10} />
                          {formatDate(scan.startedAt)}
                        </p>
                      </div>
                      <span className="font-mono text-xs text-terminal-dim">{scan.profile}</span>
                      <StatusBadge status={scan.status} pulse />
                      <span className="font-mono text-sm text-matrix-400">
                        {scan.findingsCount}
                      </span>
                      <ChevronRight size={14} className="text-terminal-ghost" />
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </TerminalCard>
        </motion.div>
      </div>
    </div>
  )
}
