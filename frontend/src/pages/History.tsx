import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  History as HistoryIcon, ChevronLeft, ChevronRight,
  FileText, Search, Clock, AlertTriangle, RefreshCw,
} from 'lucide-react'

import { TerminalCard } from '@/components/shared/TerminalCard'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { getScans } from '@/api/client'
import { formatDate, formatDuration } from '@/lib/utils'
import type { ScanStatus } from '@/types'

const STATUS_OPTIONS: Array<ScanStatus | ''> = [
  '', 'Completed', 'Running', 'Failed', 'Pending', 'Cancelled',
]

export function History() {
  const navigate = useNavigate()
  const { t } = useTranslation()

  const [page, setPage] = useState(1)
  const pageSize = 15
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<ScanStatus | ''>('')

  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['scans-history', page, pageSize],
    queryFn: () => getScans(page, pageSize),
    refetchInterval: 15_000,
  })

  const allItems = data?.items ?? []

  // Client-side filter (search + status)
  const filtered = allItems.filter(s => {
    const matchSearch = !search || s.target.toLowerCase().includes(search.toLowerCase())
    const matchStatus = !statusFilter || s.status === statusFilter
    return matchSearch && matchStatus
  })

  const totalPages = data?.totalPages ?? 1

  return (
    <div className="min-h-full overflow-auto bg-scan">
      <div className="max-w-7xl mx-auto px-3 sm:px-6 py-6 sm:py-8">

        {/* ── Header ──────────────────────────────────────── */}
        <motion.div
          className="flex items-center justify-between gap-4 mb-6"
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h1 className="font-mono font-bold text-xl sm:text-2xl text-matrix-400 flex items-center gap-2">
            <HistoryIcon size={20} />
            {t('history.title')}
          </h1>

          <button
            onClick={() => refetch()}
            disabled={isRefetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm border border-terminal-border text-terminal-dim hover:text-matrix-400 hover:border-matrix-400 font-mono text-xs transition-all disabled:opacity-40"
          >
            <RefreshCw size={12} className={isRefetching ? 'animate-spin' : ''} />
            Refresh
          </button>
        </motion.div>

        {/* ── Filters ─────────────────────────────────────── */}
        <motion.div
          className="flex flex-wrap gap-3 mb-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <div className="relative flex-1 min-w-40">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-terminal-ghost pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              placeholder={t('history.filter.search')}
              className="terminal-input pl-8 text-sm"
            />
          </div>
          <select
            value={statusFilter}
            onChange={e => { setStatusFilter(e.target.value as ScanStatus | ''); setPage(1) }}
            className="font-mono text-xs bg-terminal-bg border border-terminal-border text-terminal-dim rounded-sm px-3 py-2 focus:outline-none focus:border-matrix-400 min-w-36"
          >
            <option value="">{t('history.filter.all')}</option>
            {STATUS_OPTIONS.filter(Boolean).map(s => (
              <option key={s} value={s}>{t(`status.${s}`, s)}</option>
            ))}
          </select>
        </motion.div>

        {/* ── Table ───────────────────────────────────────── */}
        <TerminalCard>
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-6 h-6 border-2 border-matrix-400 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="py-16 text-center">
              <HistoryIcon size={32} className="text-terminal-ghost mx-auto mb-3" />
              <p className="font-mono text-sm text-terminal-ghost">{t('history.noHistory')}</p>
            </div>
          ) : (
            <>
              {/* Desktop header */}
              <div className="hidden sm:grid grid-cols-[2fr_1fr_1fr_1fr_1fr_auto] gap-4 px-4 py-2 border-b border-terminal-border">
                {[
                  t('history.target'),
                  t('history.profile'),
                  t('history.status'),
                  t('history.started'),
                  t('history.findings'),
                  t('history.actions'),
                ].map(h => (
                  <span key={h} className="font-mono text-xs text-terminal-ghost uppercase tracking-wider">
                    {h}
                  </span>
                ))}
              </div>

              {/* Rows */}
              <div className="divide-y divide-terminal-border">
                {filtered.map((scan, i) => (
                  <motion.div
                    key={scan.id}
                    className="px-4 py-3 hover:bg-terminal-muted/20 transition-colors"
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03 }}
                  >
                    {/* Mobile layout */}
                    <div className="sm:hidden">
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div className="min-w-0">
                          <p className="font-mono text-sm text-matrix-400 truncate">{scan.target}</p>
                          <p className="font-mono text-xs text-terminal-ghost mt-0.5 flex items-center gap-1">
                            <Clock size={10} />{formatDate(scan.startedAt)}
                          </p>
                        </div>
                        <StatusBadge status={scan.status} pulse />
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs text-terminal-dim">{scan.profile}</span>
                        <span className="font-mono text-xs text-matrix-400">
                          {scan.findingsCount} findings
                        </span>
                        <button
                          onClick={() =>
                            scan.status === 'Completed' || scan.status === 'Failed'
                              ? navigate(`/report/${scan.id}`)
                              : navigate(`/scan/${scan.id}`)
                          }
                          className="ml-auto flex items-center gap-1 font-mono text-xs text-matrix-400 hover:text-white border border-terminal-border hover:border-matrix-400 px-2 py-1 rounded-sm transition-all"
                        >
                          <FileText size={11} />
                          {scan.status === 'Completed' || scan.status === 'Failed'
                            ? t('dashboard.viewReport')
                            : 'View'
                          }
                        </button>
                      </div>
                    </div>

                    {/* Desktop layout */}
                    <div className="hidden sm:grid grid-cols-[2fr_1fr_1fr_1fr_1fr_auto] gap-4 items-center">
                      <div className="min-w-0">
                        <p className="font-mono text-sm text-matrix-400 truncate">{scan.target}</p>
                        <p className="font-mono text-xs text-terminal-ghost mt-0.5">{scan.id.slice(0, 8)}…</p>
                      </div>
                      <span className="font-mono text-xs text-terminal-dim">{scan.profile}</span>
                      <StatusBadge status={scan.status} pulse />
                      <div>
                        <p className="font-mono text-xs text-terminal-dim">{formatDate(scan.startedAt)}</p>
                        {scan.duration && (
                          <p className="font-mono text-xs text-terminal-ghost flex items-center gap-1 mt-0.5">
                            <Clock size={9} />{formatDuration(scan.duration)}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-1">
                        {scan.findingsCount > 0 && (
                          <AlertTriangle size={11} className="text-yellow-400" />
                        )}
                        <span className={`font-mono text-sm font-bold ${scan.findingsCount > 0 ? 'text-yellow-400' : 'text-matrix-400'}`}>
                          {scan.findingsCount}
                        </span>
                      </div>
                      <button
                        onClick={() =>
                          scan.status === 'Completed' || scan.status === 'Failed'
                            ? navigate(`/report/${scan.id}`)
                            : navigate(`/scan/${scan.id}`)
                        }
                        className="flex items-center gap-1.5 font-mono text-xs text-matrix-400 hover:text-white border border-terminal-border hover:border-matrix-400 px-3 py-1.5 rounded-sm transition-all"
                      >
                        <FileText size={12} />
                        {scan.status === 'Completed' || scan.status === 'Failed'
                          ? t('dashboard.viewReport')
                          : 'Live'
                        }
                      </button>
                    </div>
                  </motion.div>
                ))}
              </div>
            </>
          )}
        </TerminalCard>

        {/* ── Pagination ──────────────────────────────────── */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4">
            <p className="font-mono text-xs text-terminal-ghost">
              {t('history.page', { page, total: totalPages })}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="flex items-center gap-1 px-3 py-1.5 rounded-sm border border-terminal-border font-mono text-xs text-terminal-dim hover:text-matrix-400 hover:border-matrix-400 disabled:opacity-30 transition-all"
              >
                <ChevronLeft size={13} /> Prev
              </button>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="flex items-center gap-1 px-3 py-1.5 rounded-sm border border-terminal-border font-mono text-xs text-terminal-dim hover:text-matrix-400 hover:border-matrix-400 disabled:opacity-30 transition-all"
              >
                Next <ChevronRight size={13} />
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
