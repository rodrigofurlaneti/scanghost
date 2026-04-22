import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Terminal, Activity, AlertTriangle, Clock,
  FileText, StopCircle, Wifi, WifiOff, Loader2,
} from 'lucide-react'

import { TerminalCard } from '@/components/shared/TerminalCard'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { useSignalR } from '@/hooks/useSignalR'
import { getScanStatus, cancelScan } from '@/api/client'
import { formatDuration } from '@/lib/utils'
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from '@/types'

interface LogLine {
  id: number
  time: string
  phase: string
  activity: string
  type: 'info' | 'finding' | 'warn' | 'complete' | 'error'
}

function now() {
  return new Date().toLocaleTimeString('en-US', { hour12: false })
}

function lineColor(type: LogLine['type']): string {
  switch (type) {
    case 'finding':  return 'text-yellow-400'
    case 'warn':     return 'text-orange-400'
    case 'complete': return 'text-matrix-400'
    case 'error':    return 'text-red-400'
    default:         return 'text-terminal-dim'
  }
}

function linePrefix(type: LogLine['type']): string {
  switch (type) {
    case 'finding':  return '[FIND]'
    case 'warn':     return '[WARN]'
    case 'complete': return '[DONE]'
    case 'error':    return '[ERR!]'
    default:         return '[INFO]'
  }
}

export function ScanTerminal() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const { t } = useTranslation()

  const [logs, setLogs] = useState<LogLine[]>([])
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('')
  const [activity, setActivity] = useState(t('scan.connecting'))
  const [findings, setFindings] = useState(0)
  const [done, setDone] = useState(false)
  const [failed, setFailed] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [cancelling, setCancelling] = useState(false)

  const logRef = useRef<HTMLDivElement>(null)
  const logCounter = useRef(0)
  const startTime = useRef(Date.now())

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [logs])

  // Elapsed timer
  useEffect(() => {
    if (done || failed) return
    const iv = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime.current) / 1000))
    }, 1000)
    return () => clearInterval(iv)
  }, [done, failed])

  const addLog = useCallback((activity: string, phase: string, type: LogLine['type'] = 'info') => {
    setLogs(prev => [
      ...prev.slice(-200), // keep last 200 lines
      {
        id: logCounter.current++,
        time: now(),
        phase,
        activity,
        type,
      },
    ])
  }, [])

  // SignalR — .NET hubs send PascalCase by default; normalise to camelCase here
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function norm<T>(e: any, camel: string, pascal: string, fallback: T): T {
    return e[camel] ?? e[pascal] ?? fallback
  }

  const onProgress = useCallback((raw: ScanProgressEvent) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const e = raw as any
    const pct      = norm(e, 'percentComplete', 'PercentComplete', 0)
    const ph       = norm(e, 'phase',           'Phase',           '')
    const act      = norm(e, 'activity',        'Activity',        '')
    const found    = norm(e, 'findingsCount',   'FindingsCount',   0)

    setProgress(pct)
    setPhase(ph)
    setActivity(act)
    setFindings(found)

    const type: LogLine['type'] =
      found > findings    ? 'finding'
      : (ph as string).toLowerCase().includes('error') ? 'warn'
      : 'info'
    addLog(act, ph, type)
  }, [findings, addLog])

  const onCompleted = useCallback((raw: ScanCompletedEvent) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const e = raw as any
    const found    = norm(e, 'findingsCount', 'FindingsCount', 0)
    const duration = norm(e, 'duration',      'Duration',      '')

    setProgress(100)
    setFindings(found)
    setDone(true)
    setActivity(t('scan.completed'))
    addLog(`Scan completed — ${found} findings — ${duration}`, 'COMPLETE', 'complete')
  }, [t, addLog])

  const onFailed = useCallback((raw: ScanFailedEvent) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const e = raw as any
    const err = norm(e, 'error', 'Error', 'Unknown error')

    setFailed(true)
    setActivity(t('scan.failed'))
    addLog(`Scan failed: ${err}`, 'FAILED', 'error')
  }, [t, addLog])

  const { state: signalRState } = useSignalR({
    scanId: scanId ?? null,
    onProgress,
    onCompleted,
    onFailed,
  })

  // Fallback polling if SignalR not available
  const { data: statusData } = useQuery({
    queryKey: ['scan-status', scanId],
    queryFn: () => getScanStatus(scanId!),
    enabled: !!scanId && signalRState !== 'connected',
    refetchInterval: done || failed ? false : 3000,
  })

  useEffect(() => {
    if (!statusData) return
    setProgress(statusData.percentComplete)
    setPhase(statusData.phase)
    setActivity(statusData.activity)
    setFindings(statusData.findingsCount)
    if (statusData.status === 'Completed') setDone(true)
    if (statusData.status === 'Failed') setFailed(true)
  }, [statusData])

  const handleCancel = async () => {
    if (!scanId) return
    setCancelling(true)
    try {
      await cancelScan(scanId)
      navigate('/')
    } catch {
      setCancelling(false)
    }
  }

  const elapsedStr = `${Math.floor(elapsed / 60).toString().padStart(2, '0')}:${(elapsed % 60).toString().padStart(2, '0')}`

  return (
    <div className="min-h-full overflow-auto bg-scan">
      <div className="max-w-6xl mx-auto px-3 sm:px-6 py-6 sm:py-8">

        {/* ── Header ─────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4 mb-6">
          <div>
            <h1 className="font-mono font-bold text-xl sm:text-2xl text-matrix-400 flex items-center gap-2">
              <Terminal size={20} />
              {t('scan.title')}
            </h1>
            <p className="font-mono text-xs text-terminal-ghost mt-0.5">
              ID: {scanId}
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* SignalR state */}
            <div className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-sm border border-terminal-border">
              {signalRState === 'connected' ? (
                <><Wifi size={11} className="text-matrix-400" /><span className="font-mono text-xs text-matrix-400">LIVE</span></>
              ) : (
                <><WifiOff size={11} className="text-terminal-dim" /><span className="font-mono text-xs text-terminal-dim">{signalRState}</span></>
              )}
            </div>

            {!done && !failed && (
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm border border-red-800 text-red-400 font-mono text-xs uppercase hover:bg-red-950 transition-all disabled:opacity-40"
              >
                {cancelling ? <Loader2 size={12} className="animate-spin" /> : <StopCircle size={12} />}
                {t('scan.cancel')}
              </button>
            )}

            {(done || failed) && (
              <button
                onClick={() => navigate(`/report/${scanId}`)}
                className="btn-ghost-scan flex items-center gap-1.5 text-xs py-1.5"
              >
                <FileText size={13} />
                {t('scan.viewReport')}
              </button>
            )}
          </div>
        </div>

        {/* ── Status cards ───────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {[
            {
              icon: Activity,
              label: t('scan.progress'),
              value: `${progress ?? 0}%`,
              color: '#00FF41',
            },
            {
              icon: AlertTriangle,
              label: t('scan.findings'),
              value: (findings ?? 0).toString(),
              color: (findings ?? 0) > 0 ? '#ffcc00' : '#00FF41',
            },
            {
              icon: Clock,
              label: t('scan.elapsed'),
              value: elapsedStr,
              color: '#00aaff',
            },
            {
              icon: Terminal,
              label: t('scan.phase'),
              value: phase || '—',
              color: '#888888',
            },
          ].map(({ icon: Icon, label, value, color }, i) => (
            <motion.div
              key={label}
              className="terminal-card p-3"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.05 }}
            >
              <div className="flex items-center gap-1.5 mb-1">
                <Icon size={11} style={{ color }} />
                <span className="font-mono text-xs text-terminal-ghost uppercase tracking-wider">
                  {label}
                </span>
              </div>
              <p className="font-mono text-lg font-bold" style={{ color }}>
                {value}
              </p>
            </motion.div>
          ))}
        </div>

        {/* ── Progress bar ───────────────────────────────────── */}
        <div className="mb-6">
          <div className="flex justify-between mb-1">
            <span className="font-mono text-xs text-terminal-dim uppercase tracking-widest">
              {activity}
            </span>
            <span className="font-mono text-xs text-matrix-400">{progress ?? 0}%</span>
          </div>
          <div className="progress-matrix">
            <motion.div
              className="progress-matrix-fill"
              animate={{ width: `${progress ?? 0}%` }}
              transition={{ duration: 0.5, ease: 'easeOut' }}
            />
          </div>
          {/* Phase indicator bubbles */}
          {phase && (
            <div className="flex items-center gap-1.5 mt-2">
              <span className="w-1.5 h-1.5 rounded-full bg-matrix-400 animate-pulse" />
              <span className="font-mono text-xs text-matrix-400">{phase}</span>
            </div>
          )}
        </div>

        {/* ── Terminal output ─────────────────────────────────── */}
        <TerminalCard title={t('scan.terminal')}>
          <div
            ref={logRef}
            className="p-3 sm:p-4 h-64 sm:h-96 4k:h-[36rem] overflow-y-auto font-mono text-xs sm:text-sm leading-relaxed"
            style={{ scrollbarWidth: 'thin' }}
          >
            <AnimatePresence initial={false}>
              {logs.length === 0 ? (
                <p className="text-terminal-ghost">
                  {t('scan.connecting')}
                  <span className="animate-blink">_</span>
                </p>
              ) : (
                logs.map(line => (
                  <motion.div
                    key={line.id}
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.15 }}
                    className="flex gap-2 py-0.5"
                  >
                    <span className="text-terminal-ghost flex-shrink-0 w-16">{line.time}</span>
                    <span className="text-terminal-ghost flex-shrink-0 w-16 hidden sm:block truncate">
                      {line.phase || 'SYSTEM'}
                    </span>
                    <span className={`flex-shrink-0 w-14 ${lineColor(line.type)}`}>
                      {linePrefix(line.type)}
                    </span>
                    <span className="text-matrix-400 break-all">{line.activity}</span>
                  </motion.div>
                ))
              )}
            </AnimatePresence>

            {/* Blinking cursor */}
            {!done && !failed && (
              <div className="flex items-center gap-2 mt-1">
                <span className="text-terminal-ghost">{'>'}</span>
                <span className="w-2 h-4 bg-matrix-400 animate-blink" />
              </div>
            )}
          </div>
        </TerminalCard>

        {/* ── Done overlay ───────────────────────────────────── */}
        <AnimatePresence>
          {(done || failed) && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className={`mt-4 p-4 rounded-sm border font-mono text-sm text-center ${
                done
                  ? 'border-matrix-400/50 bg-matrix-400/5 text-matrix-400'
                  : 'border-red-800 bg-red-950/30 text-red-400'
              }`}
            >
              {done ? (
                <>
                  <p className="text-lg font-bold mb-2 neon-text">{t('scan.completed')}</p>
                  <p className="text-terminal-dim mb-4">{findings ?? 0} findings detected</p>
                  <button
                    onClick={() => navigate(`/report/${scanId}`)}
                    className="btn-ghost-scan inline-flex items-center gap-2"
                  >
                    <FileText size={14} />
                    {t('scan.viewReport')}
                  </button>
                </>
              ) : (
                <>
                  <p className="text-lg font-bold mb-2">{t('scan.failed')}</p>
                  <button
                    onClick={() => navigate('/')}
                    className="font-mono text-xs text-terminal-dim hover:text-matrix-400 underline"
                  >
                    Return to Dashboard
                  </button>
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
