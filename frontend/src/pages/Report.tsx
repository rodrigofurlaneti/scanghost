import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
} from 'recharts'
import {
  ChevronLeft, ChevronDown, ChevronUp, Shield, Globe,
  Search, Zap, Brain, Target, AlertTriangle, CheckCircle,
  ExternalLink, Terminal, Lock, Wifi, Download,
} from 'lucide-react'

import { TerminalCard } from '@/components/shared/TerminalCard'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { CopyButton } from '@/components/shared/CopyButton'
import { getScanReport } from '@/api/client'
import { severityColor, formatDate, formatDuration } from '@/lib/utils'
import type { FindingDto, Severity } from '@/types'

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

// ── Custom tooltip ───────────────────────────────────────────────────────────

function MatrixTooltip({ active, payload }: { active?: boolean; payload?: Array<{ name: string; value: number; fill: string }> }) {
  if (!active || !payload?.length) return null
  const d = payload[0]
  return (
    <div className="terminal-card px-3 py-2 font-mono text-xs border border-terminal-border">
      <p className="text-terminal-dim mb-0.5">{d.name}</p>
      <p style={{ color: d.fill }} className="font-bold">{d.value}</p>
    </div>
  )
}

// ── Finding row ──────────────────────────────────────────────────────────────

function FindingRow({ finding }: { finding: FindingDto }) {
  const [open, setOpen] = useState(false)
  const { t } = useTranslation()

  return (
    <div className="border-b border-terminal-border last:border-0">
      <button
        className="w-full flex items-start gap-3 px-4 py-3 hover:bg-terminal-muted/30 transition-colors text-left"
        onClick={() => setOpen(v => !v)}
      >
        <SeverityBadge severity={finding.severity} className="flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="font-mono text-sm text-matrix-400">{finding.title}</p>
          <p className="font-mono text-xs text-terminal-dim mt-0.5">{finding.category}</p>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <span
            className="font-mono text-sm font-bold"
            style={{ color: severityColor(finding.severity) }}
          >
            {finding.finalScore.toFixed(1)}
          </span>
          {open ? (
            <ChevronUp size={14} className="text-terminal-dim" />
          ) : (
            <ChevronDown size={14} className="text-terminal-dim" />
          )}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-3 bg-terminal-bg/50">
              {finding.url && (
                <div>
                  <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">
                    {t('report.finding.url')}
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-xs text-blue-400 break-all">{finding.url}</code>
                    <CopyButton text={finding.url} />
                  </div>
                </div>
              )}
              {finding.detail && (
                <div>
                  <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">
                    {t('report.finding.detail')}
                  </p>
                  <p className="font-mono text-xs text-terminal-dim leading-relaxed">{finding.detail}</p>
                </div>
              )}
              {finding.evidence && (
                <div>
                  <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">
                    {t('report.finding.evidence')}
                  </p>
                  <pre className="font-mono text-xs text-yellow-400/80 bg-terminal-bg rounded-sm p-2 overflow-x-auto border border-terminal-border">
                    {finding.evidence}
                  </pre>
                </div>
              )}
              {finding.remediation && (
                <div>
                  <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">
                    {t('report.finding.remediation')}
                  </p>
                  <p className="font-mono text-xs text-matrix-400 leading-relaxed">{finding.remediation}</p>
                </div>
              )}
              {finding.attackPath && (
                <div>
                  <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">
                    {t('report.finding.attackPath')}
                  </p>
                  <p className="font-mono text-xs text-orange-400 leading-relaxed">{finding.attackPath}</p>
                </div>
              )}
              <div className="flex flex-wrap gap-4 pt-1">
                {[
                  { label: 'Impact',         v: finding.impact },
                  { label: 'Confidence',     v: finding.confidence },
                  { label: 'Exploitability', v: finding.exploitability },
                  { label: 'Biz Impact',     v: finding.businessImpact },
                ].map(({ label, v }) => (
                  <div key={label} className="text-center">
                    <p className="font-mono text-xs text-terminal-ghost">{label}</p>
                    <p className="font-mono text-sm font-bold text-matrix-400">{v.toFixed(1)}</p>
                  </div>
                ))}
                {finding.isConfirmed && (
                  <div className="flex items-center gap-1 text-matrix-400">
                    <CheckCircle size={12} />
                    <span className="font-mono text-xs">Confirmed</span>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Main Report page ─────────────────────────────────────────────────────────

export function Report() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const { t } = useTranslation()

  const [activeTab, setActiveTab] = useState<
    'findings' | 'recon' | 'web' | 'intel' | 'correlations'
  >('findings')
  const [minSeverity, setMinSeverity] = useState<Severity | ''>('')

  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', scanId, minSeverity],
    queryFn: () => getScanReport(scanId!, minSeverity as Severity || undefined),
    enabled: !!scanId,
  })

  if (isLoading) {
    return (
      <div className="min-h-full flex items-center justify-center">
        <div className="text-center space-y-3">
          <div className="w-8 h-8 border-2 border-matrix-400 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="font-mono text-sm text-terminal-dim">{t('common.loading')}</p>
        </div>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="min-h-full flex items-center justify-center">
        <div className="text-center space-y-3">
          <AlertTriangle size={32} className="text-red-400 mx-auto" />
          <p className="font-mono text-sm text-red-400">{t('common.error')}</p>
          <button onClick={() => navigate(-1)} className="font-mono text-xs text-terminal-dim hover:text-matrix-400 underline">
            {t('common.back')}
          </button>
        </div>
      </div>
    )
  }

  // ── JSON export ─────────────────────────────────────────────────────────────
  const handleExportJson = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      scanId,
      target:     report.target,
      profile:    report.profile,
      startedAt:  report.startedAt,
      completedAt: report.completedAt,
      summary:    report.summary,
      findings:   report.findings,
      reconResults:         report.reconResults        ?? null,
      webResults:           report.webResults          ?? null,
      intelligenceResults:  report.intelligenceResults ?? null,
      correlations:         report.correlations,
      recommendations:      report.recommendations,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    const safe = report.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()
    a.href     = url
    a.download = `ghostscan_${safe}_${scanId?.slice(0, 8)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Chart data
  const barData = SEVERITY_ORDER
    .filter(s => (report.summary.bySeverity[s] ?? 0) > 0)
    .map(s => ({
      name: s,
      value: report.summary.bySeverity[s] ?? 0,
      fill: severityColor(s),
    }))

  const radarData = [
    { subject: 'Impact',         A: report.findings[0]?.impact ?? 0 },
    { subject: 'Confidence',     A: report.findings[0]?.confidence ?? 0 },
    { subject: 'Exploitability', A: report.findings[0]?.exploitability ?? 0 },
    { subject: 'Biz Impact',     A: report.findings[0]?.businessImpact ?? 0 },
  ]

  const TABS = [
    { key: 'findings',     label: t('report.findings'),     icon: Shield,        count: report.summary.total },
    { key: 'recon',        label: t('report.recon.title'),  icon: Search,        count: report.reconResults?.subdomains.length },
    { key: 'web',          label: t('report.web.title'),    icon: Globe,         count: report.webResults?.endpoints.length },
    { key: 'intel',        label: t('report.intelligence'), icon: Brain,         count: report.intelligenceResults?.totalScored },
    { key: 'correlations', label: t('report.correlations'), icon: Zap,           count: report.correlations.length },
  ] as const

  return (
    <div className="min-h-full overflow-auto bg-scan">
      <div className="max-w-7xl mx-auto px-3 sm:px-6 py-6 sm:py-8">

        {/* ── Header ────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4 mb-6">
          <div>
            <button
              onClick={() => navigate(-1)}
              className="flex items-center gap-1 font-mono text-xs text-terminal-dim hover:text-matrix-400 mb-3 transition-colors"
            >
              <ChevronLeft size={13} /> {t('common.back')}
            </button>
            <h1 className="font-mono font-bold text-xl sm:text-2xl text-matrix-400 flex items-center gap-2">
              <Terminal size={20} />
              {t('report.title')}
            </h1>
            <p className="font-mono text-xs text-terminal-ghost mt-0.5">
              {report.target} • {report.profile} • {formatDate(report.startedAt)}
            </p>
          </div>

          {/* Export button */}
          <button
            onClick={handleExportJson}
            className="
              flex items-center gap-2 px-3 py-2 mt-8
              font-mono text-xs uppercase tracking-widest
              border border-terminal-border text-terminal-dim
              hover:border-matrix-400 hover:text-matrix-400
              transition-all duration-200 rounded-sm flex-shrink-0
            "
            title="Export full report as JSON"
          >
            <Download size={13} />
            <span className="hidden sm:inline">Export JSON</span>
          </button>
        </div>

        {/* ── Summary cards ─────────────────────────────────── */}
        <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-6 gap-2 mb-6">
          {[
            { label: 'Total',    value: report.summary.total,    color: '#00FF41' },
            { label: 'Critical', value: report.summary.critical, color: '#ff0033' },
            { label: 'High',     value: report.summary.high,     color: '#ff6600' },
            { label: 'Medium',   value: report.summary.medium,   color: '#ffcc00' },
            { label: 'Low',      value: report.summary.low,      color: '#00aaff' },
            { label: 'Info',     value: report.summary.info,     color: '#888888' },
          ].map(({ label, value, color }, i) => (
            <motion.div
              key={label}
              className="terminal-card p-3 text-center"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.04 }}
            >
              <p className="font-mono text-xs text-terminal-ghost mb-1">{label}</p>
              <p className="font-mono text-xl sm:text-2xl font-bold" style={{ color }}>
                {value}
              </p>
            </motion.div>
          ))}
        </div>

        {/* ── Charts ────────────────────────────────────────── */}
        {barData.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
            <TerminalCard title="Findings by Severity">
              <div className="p-4 h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={barData} barSize={28}>
                    <XAxis
                      dataKey="name"
                      tick={{ fill: '#00aa2a', fontFamily: 'JetBrains Mono', fontSize: 11 }}
                      axisLine={{ stroke: '#0d2b0d' }}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fill: '#00aa2a', fontFamily: 'JetBrains Mono', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip content={<MatrixTooltip />} />
                    <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                      {barData.map((entry, i) => (
                        <Cell key={i} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </TerminalCard>

            <TerminalCard title="Top Finding Profile">
              <div className="p-4 h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="#0d2b0d" />
                    <PolarAngleAxis
                      dataKey="subject"
                      tick={{ fill: '#00aa2a', fontFamily: 'JetBrains Mono', fontSize: 10 }}
                    />
                    <Radar name="Score" dataKey="A" stroke="#00FF41" fill="#00FF41" fillOpacity={0.15} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </TerminalCard>
          </div>
        )}

        {/* ── Tabs ──────────────────────────────────────────── */}
        <div className="flex overflow-x-auto gap-1 mb-4 pb-1">
          {TABS.map(({ key, label, icon: Icon, count }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key as typeof activeTab)}
              className={`
                flex items-center gap-1.5 px-3 py-2 rounded-sm font-mono text-xs uppercase tracking-widest whitespace-nowrap
                border transition-all duration-200 flex-shrink-0
                ${activeTab === key
                  ? 'border-matrix-400 text-matrix-400 bg-matrix-400/10'
                  : 'border-terminal-border text-terminal-dim hover:text-matrix-400'
                }
              `}
            >
              <Icon size={11} />
              {label}
              {count !== undefined && count > 0 && (
                <span className="ml-1 px-1 rounded-sm bg-terminal-muted text-terminal-dim text-xs">
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ── Tab content ───────────────────────────────────── */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2 }}
          >

            {/* FINDINGS ────────────────────────────────────── */}
            {activeTab === 'findings' && (
              <TerminalCard
                title={`${t('report.findings')} (${report.summary.total})`}
                titleRight={
                  <select
                    value={minSeverity}
                    onChange={e => setMinSeverity(e.target.value as Severity)}
                    className="font-mono text-xs bg-terminal-bg border border-terminal-border text-terminal-dim rounded-sm px-2 py-1 focus:outline-none focus:border-matrix-400"
                  >
                    <option value="">{t('report.filter.all')}</option>
                    {SEVERITY_ORDER.map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                }
              >
                {report.findings.length === 0 ? (
                  <p className="p-6 text-center font-mono text-sm text-terminal-ghost">
                    {t('report.noFindings')}
                  </p>
                ) : (
                  <div>
                    {report.findings.map(f => (
                      <FindingRow key={f.id} finding={f} />
                    ))}
                  </div>
                )}
              </TerminalCard>
            )}

            {/* RECON ───────────────────────────────────────── */}
            {activeTab === 'recon' && (
              <div className="space-y-4">
                {!report.reconResults ? (
                  <p className="font-mono text-sm text-terminal-ghost p-4">{t('common.notAvailable')}</p>
                ) : (
                  <>
                    {/* Subdomains */}
                    {report.reconResults.subdomains.length > 0 && (
                      <TerminalCard title={t('report.recon.subdomains')}>
                        <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                          {report.reconResults.subdomains.map(s => (
                            <div key={s} className="flex items-center gap-2 font-mono text-xs text-matrix-400">
                              <Globe size={10} className="text-terminal-ghost flex-shrink-0" />
                              <span className="truncate">{s}</span>
                            </div>
                          ))}
                        </div>
                      </TerminalCard>
                    )}

                    {/* DNS Records */}
                    {Object.keys(report.reconResults.dnsRecords).length > 0 && (
                      <TerminalCard title={t('report.recon.dns')}>
                        <div className="p-4 space-y-3">
                          {Object.entries(report.reconResults.dnsRecords).map(([type, records]) => (
                            <div key={type}>
                              <p className="font-mono text-xs text-terminal-dim uppercase tracking-widest mb-1.5">{type}</p>
                              <div className="space-y-1">
                                {records.map((r, i) => (
                                  <div key={i} className="flex items-start gap-2">
                                    <span className="text-terminal-ghost text-xs mt-0.5">›</span>
                                    <code className="font-mono text-xs text-matrix-400 break-all">{r}</code>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </TerminalCard>
                    )}

                    {/* Open Ports */}
                    {Object.keys(report.reconResults.openPorts).length > 0 && (
                      <TerminalCard title={t('report.recon.ports')}>
                        <div className="p-4 space-y-4">
                          {Object.entries(report.reconResults.openPorts).map(([host, ports]) => (
                            <div key={host}>
                              <p className="font-mono text-xs text-terminal-dim mb-2">{host}</p>
                              <div className="flex flex-wrap gap-2">
                                {ports.map(p => (
                                  <span key={p.port} className="px-2 py-1 rounded-sm border border-matrix-400/30 bg-matrix-400/5 font-mono text-xs text-matrix-400">
                                    {p.port}/{p.state}
                                    {p.service && <span className="text-terminal-ghost ml-1">({p.service})</span>}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </TerminalCard>
                    )}

                    {/* Emails */}
                    {report.reconResults.emails.length > 0 && (
                      <TerminalCard title={t('report.recon.emails')}>
                        <div className="p-4 flex flex-wrap gap-2">
                          {report.reconResults.emails.map(e => (
                            <span key={e} className="font-mono text-xs text-matrix-400 border border-terminal-border px-2 py-1 rounded-sm">
                              {e}
                            </span>
                          ))}
                        </div>
                      </TerminalCard>
                    )}

                    {/* Zone Transfer */}
                    <TerminalCard title={t('report.recon.zoneTransfer')}>
                      <div className="p-4 flex items-center gap-2">
                        {report.reconResults.zoneTransferSucceeded ? (
                          <>
                            <AlertTriangle size={14} className="text-red-400" />
                            <span className="font-mono text-sm text-red-400">{t('report.recon.succeeded')}</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle size={14} className="text-matrix-400" />
                            <span className="font-mono text-sm text-matrix-400">{t('report.recon.failed')}</span>
                          </>
                        )}
                      </div>
                    </TerminalCard>
                  </>
                )}
              </div>
            )}

            {/* WEB ANALYSIS ────────────────────────────────── */}
            {activeTab === 'web' && (
              <div className="space-y-4">
                {!report.webResults ? (
                  <p className="font-mono text-sm text-terminal-ghost p-4">{t('common.notAvailable')}</p>
                ) : (
                  <>
                    {/* Technologies */}
                    {Object.keys(report.webResults.technologies).length > 0 && (
                      <TerminalCard title={t('report.web.technologies')}>
                        <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
                          {Object.entries(report.webResults.technologies).map(([cat, techs]) => (
                            techs.length > 0 && (
                              <div key={cat}>
                                <p className="font-mono text-xs text-terminal-ghost uppercase tracking-widest mb-2">{cat}</p>
                                <div className="flex flex-wrap gap-1.5">
                                  {techs.map(t2 => (
                                    <span key={t2} className="font-mono text-xs px-2 py-0.5 rounded-sm border border-terminal-border text-matrix-400">
                                      {t2}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )
                          ))}
                        </div>
                      </TerminalCard>
                    )}

                    {/* WAF */}
                    <TerminalCard title={t('report.web.waf')}>
                      <div className="p-4 flex items-center gap-3">
                        {report.webResults.waf?.detected ? (
                          <>
                            <Lock size={16} className="text-yellow-400" />
                            <div>
                              <p className="font-mono text-sm text-yellow-400">
                                {t('report.web.detected')}: {report.webResults.waf.wafName || 'Unknown WAF'}
                              </p>
                              <p className="font-mono text-xs text-terminal-dim">
                                {t('report.web.confidence')}: {(report.webResults.waf.confidence * 100).toFixed(0)}%
                              </p>
                            </div>
                          </>
                        ) : (
                          <>
                            <Wifi size={16} className="text-matrix-400" />
                            <p className="font-mono text-sm text-matrix-400">{t('report.web.notDetected')}</p>
                          </>
                        )}
                      </div>
                    </TerminalCard>

                    {/* Header Audit */}
                    {report.webResults.headerAudit && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {report.webResults.headerAudit.missingHeaders.length > 0 && (
                          <TerminalCard title={t('report.web.missingHeaders')}>
                            <div className="p-4 space-y-1">
                              {report.webResults.headerAudit.missingHeaders.map(h => (
                                <div key={h} className="flex items-center gap-2">
                                  <AlertTriangle size={11} className="text-yellow-400 flex-shrink-0" />
                                  <code className="font-mono text-xs text-yellow-400">{h}</code>
                                </div>
                              ))}
                            </div>
                          </TerminalCard>
                        )}
                        {report.webResults.headerAudit.dangerousHeaders.length > 0 && (
                          <TerminalCard title={t('report.web.dangerousHeaders')}>
                            <div className="p-4 space-y-1">
                              {report.webResults.headerAudit.dangerousHeaders.map(h => (
                                <div key={h} className="flex items-center gap-2">
                                  <AlertTriangle size={11} className="text-red-400 flex-shrink-0" />
                                  <code className="font-mono text-xs text-red-400">{h}</code>
                                </div>
                              ))}
                            </div>
                          </TerminalCard>
                        )}
                      </div>
                    )}

                    {/* JS Secrets */}
                    {report.webResults.jsSecrets.length > 0 && (
                      <TerminalCard title={t('report.web.jsSecrets')}>
                        <div className="p-4 space-y-3">
                          {report.webResults.jsSecrets.map((s, i) => (
                            <div key={i} className="border border-terminal-border rounded-sm p-3">
                              <div className="flex items-center gap-2 mb-1">
                                <SeverityBadge severity="HIGH" />
                                <span className="font-mono text-xs text-terminal-dim">{s.type}</span>
                              </div>
                              <code className="font-mono text-xs text-red-400 break-all">{s.value}</code>
                              {s.url && (
                                <p className="font-mono text-xs text-terminal-ghost mt-1 truncate">{s.url}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </TerminalCard>
                    )}

                    {/* Endpoints */}
                    {report.webResults.endpoints.length > 0 && (
                      <TerminalCard title={`${t('report.web.endpoints')} (${report.webResults.endpoints.length})`}>
                        <div className="p-4 space-y-1 max-h-64 overflow-y-auto">
                          {report.webResults.endpoints.map(ep => (
                            <div key={ep} className="flex items-center gap-2">
                              <ExternalLink size={10} className="text-terminal-ghost flex-shrink-0" />
                              <code className="font-mono text-xs text-blue-400 truncate">{ep}</code>
                            </div>
                          ))}
                        </div>
                      </TerminalCard>
                    )}
                  </>
                )}
              </div>
            )}

            {/* INTELLIGENCE ────────────────────────────────── */}
            {activeTab === 'intel' && (
              <div className="space-y-4">
                {report.intelligenceResults && (
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    {[
                      { label: t('report.intel.totalRaw'),     value: report.intelligenceResults.totalRaw },
                      { label: t('report.intel.totalScored'),  value: report.intelligenceResults.totalScored },
                      { label: t('report.intel.deduplicated'), value: report.intelligenceResults.afterDedup },
                      { label: t('report.intel.correlations'), value: report.intelligenceResults.totalCorrelations },
                      { label: t('report.intel.attackSurface'), value: report.intelligenceResults.attackSurface },
                    ].map(({ label, value }) => (
                      <div key={label} className="terminal-card p-4">
                        <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">{label}</p>
                        <p className="font-mono text-2xl font-bold text-matrix-400">{value}</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Recommendations */}
                {report.recommendations.length > 0 && (
                  <TerminalCard title={t('report.recommendations')}>
                    <div className="divide-y divide-terminal-border">
                      {report.recommendations.map(rec => (
                        <div key={rec.priority} className="p-4 flex gap-3">
                          <div className="flex-shrink-0 w-7 h-7 rounded-sm border border-matrix-400/40 bg-matrix-400/10 flex items-center justify-center">
                            <span className="font-mono text-xs font-bold text-matrix-400">{rec.priority}</span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <SeverityBadge severity={rec.severity} />
                            </div>
                            <p className="font-mono text-sm text-matrix-400">{rec.action}</p>
                            {rec.command && (
                              <div className="flex items-center gap-2 mt-2">
                                <code className="font-mono text-xs text-terminal-dim bg-terminal-bg border border-terminal-border rounded-sm px-2 py-1 flex-1 overflow-x-auto">
                                  {rec.command}
                                </code>
                                <CopyButton text={rec.command} />
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </TerminalCard>
                )}

                {/* Ranked Targets */}
                {report.rankedTargets.length > 0 && (
                  <TerminalCard title={t('report.rankedTargets')}>
                    <div className="divide-y divide-terminal-border">
                      {report.rankedTargets.map((rt, i) => (
                        <div key={i} className="p-4 flex items-start gap-3">
                          <div className="flex-shrink-0 text-center">
                            <span className="font-mono text-xs text-terminal-dim">#{i + 1}</span>
                            <p className="font-mono text-sm font-bold text-matrix-400">{rt.score.toFixed(1)}</p>
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="font-mono text-sm text-blue-400 truncate">{rt.url}</p>
                            <p className="font-mono text-xs text-terminal-dim mt-0.5">{rt.priority}</p>
                            {rt.reasons.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-1.5">
                                {rt.reasons.map((r, j) => (
                                  <span key={j} className="font-mono text-xs px-1.5 py-0.5 rounded-sm bg-terminal-muted text-terminal-dim">
                                    {r}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </TerminalCard>
                )}
              </div>
            )}

            {/* CORRELATIONS ───────────────────────────────── */}
            {activeTab === 'correlations' && (
              <TerminalCard title={t('report.correlations')}>
                {report.correlations.length === 0 ? (
                  <p className="p-6 text-center font-mono text-sm text-terminal-ghost">
                    No attack correlations detected.
                  </p>
                ) : (
                  <div className="divide-y divide-terminal-border">
                    {report.correlations.map((c, i) => (
                      <div key={i} className="p-4">
                        <div className="flex items-start gap-3 mb-2">
                          <SeverityBadge severity={c.severity} />
                          <div className="flex-1 min-w-0">
                            <p className="font-mono text-sm text-matrix-400">{c.title}</p>
                            <p className="font-mono text-xs text-terminal-ghost mt-0.5">Score: {c.score.toFixed(1)}</p>
                          </div>
                        </div>
                        <p className="font-mono text-xs text-terminal-dim leading-relaxed mb-2">
                          {c.description}
                        </p>
                        {c.attackPath && (
                          <div className="border border-orange-900/50 bg-orange-950/20 rounded-sm p-2">
                            <p className="font-mono text-xs text-terminal-ghost mb-1">Attack Path</p>
                            <p className="font-mono text-xs text-orange-400">{c.attackPath}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </TerminalCard>
            )}

          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  )
}
