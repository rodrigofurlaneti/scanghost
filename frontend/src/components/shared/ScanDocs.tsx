import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  HelpCircle, X, Zap, Shield, Target, ChevronRight,
  Terminal, FlaskConical, Clock, AlertTriangle, Lock,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

/* ─── Profile table data ─────────────────────────────────────────── */
const PROFILES = [
  {
    id: 'stealth',
    icon: Zap,
    color: '#00aaff',
    threads: 5,
    rate: '2 s',
    sqli: false,
    xss: false,
    brute: false,
    waf: false,
    label: { en: 'Passive recon only. Does not trigger IDS/WAF alerts.', pt: 'Só recon passivo. Não dispara alertas de IDS/WAF.' },
    useCases: {
      en: ['Production systems', 'Low-risk enumeration', 'Client environments'],
      pt: ['Sistemas em produção', 'Enumeração de baixo risco', 'Ambientes de clientes'],
    },
  },
  {
    id: 'standard',
    icon: Shield,
    color: '#00FF41',
    threads: 20,
    rate: '0.1 s',
    sqli: true,
    xss: true,
    brute: false,
    waf: true,
    label: { en: 'Full analysis. Balanced between coverage and noise.', pt: 'Análise completa. Equilibrado entre cobertura e ruído.' },
    useCases: {
      en: ['Staging environments', 'Internal audits', 'Bug bounty recon'],
      pt: ['Ambientes de staging', 'Auditorias internas', 'Recon de bug bounty'],
    },
  },
  {
    id: 'aggressive',
    icon: Target,
    color: '#ff4444',
    threads: 50,
    rate: '0.05 s',
    sqli: true,
    xss: true,
    brute: true,
    waf: true,
    label: { en: 'All modules. WAF bypass + brute force + parallel execution.', pt: 'Todos os módulos. Bypass de WAF + brute force + execução paralela.' },
    useCases: {
      en: ['Authorized pentests', 'Dev/test environments', 'CTF challenges'],
      pt: ['Pentests autorizados', 'Ambientes de dev/test', 'Desafios CTF'],
    },
  },
]

/* ─── Pipeline stages ─────────────────────────────────────────────── */
const PIPELINE = [
  { icon: '🔍', phase: 'Reconnaissance', en: 'DNS, WHOIS, subdomain enumeration, port scanning, banner grabbing.', pt: 'DNS, WHOIS, enumeração de subdomínios, port scan, banner grabbing.' },
  { icon: '🌐', phase: 'Web Analysis',   en: 'WAF detection, path probing, crawling, header audit, JS secrets, tech fingerprinting.', pt: 'Detecção de WAF, probing de paths, crawling, auditoria de headers, secrets em JS, fingerprinting de tecnologias.' },
  { icon: '⚠️',  phase: 'Vuln Detection', en: 'XSS, SQLi, open redirect, CSP audit, SSL/TLS, CVE correlation, brute force (aggressive).', pt: 'XSS, SQLi, open redirect, auditoria de CSP, SSL/TLS, correlação de CVE, brute force (aggressive).' },
  { icon: '🎭', phase: 'Browser/DOM',    en: 'Static DOM XSS analysis, WebSocket discovery, client-side storage, source maps.', pt: 'Análise estática de DOM XSS, descoberta de WebSocket, armazenamento do cliente, source maps.' },
  { icon: '🧠', phase: 'Intelligence',   en: 'Cross-module correlation, attack chain scoring, ranked target list, deduplication.', pt: 'Correlação entre módulos, pontuação de cadeias de ataque, lista ranqueada de alvos, deduplicação.' },
]

/* ─── Scoring breakdown ───────────────────────────────────────────── */
const SCORE_STEPS = [
  { label: 'impact',         weight: '× 0.6', color: '#ff4444', en: 'Technical severity of the vulnerability', pt: 'Severidade técnica da vulnerabilidade' },
  { label: 'confidence',     weight: '× 0.4', color: '#ffcc00', en: 'Certainty that the finding is real (0–1)', pt: 'Certeza de que o achado é real (0–1)' },
  { label: 'exploitability', weight: '× ...',  color: '#00aaff', en: 'Ease of exploitation (auth required, network, etc.)', pt: 'Facilidade de exploração (requer auth, rede, etc.)' },
  { label: 'businessImpact', weight: '× ...',  color: '#00FF41', en: 'Potential business damage if exploited', pt: 'Dano potencial ao negócio se explorado' },
]

/* ─── Bool indicator ──────────────────────────────────────────────── */
function Bool({ v }: { v: boolean }) {
  return v
    ? <span className="text-matrix-400 font-bold">✓</span>
    : <span className="text-terminal-ghost">✗</span>
}

/* ─── Main component ──────────────────────────────────────────────── */
export function ScanDocs() {
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState<'profiles' | 'pipeline' | 'scoring'>('profiles')
  const { i18n } = useTranslation()
  const lang = i18n.language.startsWith('pt') ? 'pt' : 'en'

  return (
    <>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(true)}
        title="Scan documentation"
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm border border-terminal-border
                   text-terminal-ghost hover:text-matrix-400 hover:border-matrix-400/50
                   font-mono text-xs uppercase tracking-widest transition-all duration-200"
      >
        <HelpCircle size={11} />
        <span className="hidden sm:inline">Docs</span>
      </button>

      {/* Modal backdrop + panel */}
      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <motion.div
              className="fixed inset-0 bg-black/70 z-40 backdrop-blur-sm"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setOpen(false)}
            />

            {/* Panel */}
            <motion.div
              className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl flex flex-col
                         bg-terminal-bg border-l border-terminal-border overflow-hidden"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', stiffness: 300, damping: 35 }}
            >
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b border-terminal-border flex-shrink-0">
                <div className="flex items-center gap-3">
                  <Terminal size={16} className="text-matrix-400" />
                  <span className="font-mono font-bold text-matrix-400 uppercase tracking-widest text-sm">
                    GhostScan Docs
                  </span>
                  <span className="font-mono text-xs text-terminal-ghost border border-terminal-border px-1.5 py-0.5 rounded-sm">v3</span>
                </div>
                <button
                  onClick={() => setOpen(false)}
                  className="text-terminal-ghost hover:text-matrix-400 transition-colors"
                >
                  <X size={16} />
                </button>
              </div>

              {/* Scanline decoration */}
              <div className="h-px bg-gradient-to-r from-transparent via-matrix-400/40 to-transparent flex-shrink-0" />

              {/* Tab bar */}
              <div className="flex border-b border-terminal-border flex-shrink-0">
                {(['profiles', 'pipeline', 'scoring'] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    className={`
                      flex-1 px-4 py-2.5 font-mono text-xs uppercase tracking-widest transition-all
                      border-b-2 ${tab === t
                        ? 'border-matrix-400 text-matrix-400 bg-matrix-400/5'
                        : 'border-transparent text-terminal-ghost hover:text-matrix-400'
                      }
                    `}
                  >
                    {t === 'profiles' ? '01 / Profiles' : t === 'pipeline' ? '02 / Pipeline' : '03 / Scoring'}
                  </button>
                ))}
              </div>

              {/* Scrollable content */}
              <div className="flex-1 overflow-y-auto p-5 space-y-4" style={{ scrollbarWidth: 'thin' }}>

                {/* ── TAB: PROFILES ── */}
                {tab === 'profiles' && (
                  <div className="space-y-4">
                    <p className="font-mono text-xs text-terminal-ghost leading-relaxed">
                      {lang === 'pt'
                        ? 'Cada perfil configura threads, rate limiting, e quais módulos de ataque são ativados. Escolha com base no ambiente alvo.'
                        : 'Each profile configures threads, rate limiting, and which attack modules are active. Choose based on the target environment.'}
                    </p>

                    {/* Quick comparison table */}
                    <div className="terminal-card overflow-x-auto">
                      <table className="w-full font-mono text-xs">
                        <thead>
                          <tr className="border-b border-terminal-border">
                            {['Profile', 'Threads', 'Rate', 'SQLi', 'XSS', 'Brute', 'WAF bypass'].map(h => (
                              <th key={h} className="px-3 py-2 text-left text-terminal-ghost uppercase tracking-wider font-normal whitespace-nowrap">
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {PROFILES.map(p => (
                            <tr key={p.id} className="border-b border-terminal-border/50 hover:bg-terminal-muted/20">
                              <td className="px-3 py-2">
                                <span className="flex items-center gap-1.5" style={{ color: p.color }}>
                                  <p.icon size={11} />
                                  {p.id}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-terminal-dim">{p.threads}</td>
                              <td className="px-3 py-2 text-terminal-dim">{p.rate}</td>
                              <td className="px-3 py-2"><Bool v={p.sqli} /></td>
                              <td className="px-3 py-2"><Bool v={p.xss} /></td>
                              <td className="px-3 py-2"><Bool v={p.brute} /></td>
                              <td className="px-3 py-2"><Bool v={p.waf} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Profile cards */}
                    {PROFILES.map(p => (
                      <div key={p.id} className="terminal-card p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <p.icon size={14} style={{ color: p.color }} />
                          <span className="font-mono font-bold uppercase tracking-widest text-sm" style={{ color: p.color }}>
                            {p.id}
                          </span>
                        </div>
                        <p className="font-mono text-xs text-terminal-dim mb-3">
                          {p.label[lang]}
                        </p>
                        <div className="flex flex-col gap-1">
                          <span className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-1">
                            {lang === 'pt' ? 'Quando usar:' : 'When to use:'}
                          </span>
                          {p.useCases[lang].map(uc => (
                            <div key={uc} className="flex items-center gap-2">
                              <ChevronRight size={10} style={{ color: p.color }} />
                              <span className="font-mono text-xs text-terminal-dim">{uc}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}

                    {/* Warning */}
                    <div className="border border-yellow-800/60 bg-yellow-950/20 rounded-sm p-3 flex gap-2">
                      <Lock size={13} className="text-yellow-500 flex-shrink-0 mt-0.5" />
                      <p className="font-mono text-xs text-yellow-400 leading-relaxed">
                        {lang === 'pt'
                          ? 'Use apenas em sistemas que você está autorizado a testar. Testes de segurança não autorizados são ilegais.'
                          : 'Only use on systems you are authorized to test. Unauthorized security testing is illegal.'}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── TAB: PIPELINE ── */}
                {tab === 'pipeline' && (
                  <div className="space-y-4">
                    <p className="font-mono text-xs text-terminal-ghost leading-relaxed">
                      {lang === 'pt'
                        ? 'O GhostScan executa 5 módulos em sequência (ou em paralelo no modo aggressive). Cada módulo alimenta o próximo via contexto compartilhado.'
                        : 'GhostScan runs 5 modules in sequence (or in parallel in aggressive mode). Each module feeds the next via shared context.'}
                    </p>

                    {/* Pipeline flow */}
                    <div className="space-y-2">
                      {PIPELINE.map((stage, i) => (
                        <div key={stage.phase}>
                          <div className="terminal-card p-4">
                            <div className="flex items-start gap-3">
                              <div className="flex-shrink-0 w-7 h-7 rounded-sm border border-matrix-400/30 bg-matrix-400/5
                                            flex items-center justify-center font-mono text-xs text-matrix-400">
                                {String(i + 1).padStart(2, '0')}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="text-base leading-none">{stage.icon}</span>
                                  <span className="font-mono font-bold text-sm text-matrix-400">{stage.phase}</span>
                                </div>
                                <p className="font-mono text-xs text-terminal-dim leading-relaxed">
                                  {stage[lang]}
                                </p>
                              </div>
                            </div>
                          </div>
                          {i < PIPELINE.length - 1 && (
                            <div className="flex justify-center my-1">
                              <div className="w-px h-4 bg-matrix-400/30" />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>

                    {/* Parallel note */}
                    <div className="terminal-card p-3 border-matrix-400/30 bg-matrix-400/5">
                      <div className="flex items-start gap-2">
                        <FlaskConical size={13} className="text-matrix-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <p className="font-mono text-xs text-matrix-400 font-bold mb-1">
                            {lang === 'pt' ? 'Modo Paralelo (Aggressive)' : 'Parallel Mode (Aggressive)'}
                          </p>
                          <p className="font-mono text-xs text-terminal-dim leading-relaxed">
                            {lang === 'pt'
                              ? 'Com perfil aggressive, Web Analysis, Vuln Detection e Browser/DOM rodam simultaneamente após o Recon. Isso reduz o tempo total de scan em até 50%, mas aumenta a carga no servidor alvo.'
                              : 'With aggressive profile, Web Analysis, Vuln Detection and Browser/DOM run simultaneously after Recon. This reduces total scan time by up to 50%, but increases load on the target server.'}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Quick start */}
                    <div className="terminal-card p-4">
                      <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-3">
                        {lang === 'pt' ? 'Fluxo via API' : 'API Flow'}
                      </p>
                      {[
                        { method: 'POST', path: '/api/scans', desc: lang === 'pt' ? 'Inicia o scan — retorna scanId' : 'Start scan — returns scanId' },
                        { method: 'WS',   path: '/hubs/scan', desc: lang === 'pt' ? 'Progresso em tempo real via SignalR' : 'Real-time progress via SignalR' },
                        { method: 'GET',  path: '/api/scans/{id}/status', desc: lang === 'pt' ? 'Polling de fallback (se WS falhar)' : 'Fallback polling (if WS fails)' },
                        { method: 'GET',  path: '/api/scans/{id}/report', desc: lang === 'pt' ? 'Relatório completo após conclusão' : 'Full report after completion' },
                      ].map(({ method, path, desc }) => (
                        <div key={path} className="flex items-start gap-3 py-2 border-b border-terminal-border/40 last:border-0">
                          <span className={`font-mono text-xs font-bold flex-shrink-0 w-10 ${
                            method === 'POST' ? 'text-yellow-400'
                            : method === 'WS'  ? 'text-[#00aaff]'
                            : 'text-matrix-400'
                          }`}>{method}</span>
                          <code className="font-mono text-xs text-terminal-dim flex-shrink-0">{path}</code>
                          <span className="font-mono text-xs text-terminal-ghost">{desc}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── TAB: SCORING ── */}
                {tab === 'scoring' && (
                  <div className="space-y-4">
                    <p className="font-mono text-xs text-terminal-ghost leading-relaxed">
                      {lang === 'pt'
                        ? 'Cada finding recebe um score que representa o risco real combinando impacto técnico, certeza da detecção, explorabilidade e impacto ao negócio.'
                        : 'Each finding receives a score representing real risk by combining technical impact, detection certainty, exploitability, and business impact.'}
                    </p>

                    {/* Formula */}
                    <div className="terminal-card p-4">
                      <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-3">
                        {lang === 'pt' ? 'Fórmula de pontuação' : 'Scoring formula'}
                      </p>
                      <div className="bg-black/40 border border-terminal-border rounded-sm p-3 overflow-x-auto">
                        <code className="font-mono text-xs text-matrix-400 whitespace-nowrap">
                          score = (impact × 0.6) + (confidence × 0.4) × exploitability × businessImpact
                        </code>
                      </div>
                    </div>

                    {/* Factor breakdown */}
                    <div className="terminal-card p-4">
                      <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-3">
                        {lang === 'pt' ? 'Fatores' : 'Factors'}
                      </p>
                      <div className="space-y-3">
                        {SCORE_STEPS.map(s => (
                          <div key={s.label} className="flex items-start gap-3">
                            <div className="flex-shrink-0 w-1.5 h-full mt-1.5">
                              <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: s.color }} />
                            </div>
                            <div>
                              <div className="flex items-center gap-2 mb-0.5">
                                <code className="font-mono text-xs font-bold" style={{ color: s.color }}>{s.label}</code>
                                <span className="font-mono text-xs text-terminal-ghost">{s.weight}</span>
                              </div>
                              <p className="font-mono text-xs text-terminal-dim">{s[lang]}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Severity mapping */}
                    <div className="terminal-card p-4">
                      <p className="font-mono text-xs text-terminal-ghost uppercase tracking-wider mb-3">
                        {lang === 'pt' ? 'Mapeamento de severidade' : 'Severity mapping'}
                      </p>
                      <div className="space-y-2">
                        {[
                          { label: 'CRITICAL', range: '9.0 – 10.0', color: '#ff0033', desc: lang === 'pt' ? 'Exploração imediata possível, alto impacto' : 'Immediate exploitation possible, high impact' },
                          { label: 'HIGH',     range: '7.0 – 8.9',  color: '#ff6600', desc: lang === 'pt' ? 'Facilmente explorável, impacto significativo' : 'Easily exploitable, significant impact' },
                          { label: 'MEDIUM',   range: '4.0 – 6.9',  color: '#ffcc00', desc: lang === 'pt' ? 'Explorável com condições, impacto moderado' : 'Exploitable with conditions, moderate impact' },
                          { label: 'LOW',      range: '1.0 – 3.9',  color: '#00aaff', desc: lang === 'pt' ? 'Difícil de explorar, impacto baixo' : 'Hard to exploit, low impact' },
                          { label: 'INFO',     range: '0.0 – 0.9',  color: '#888888', desc: lang === 'pt' ? 'Informativo, sem risco direto' : 'Informational, no direct risk' },
                        ].map(s => (
                          <div key={s.label} className="flex items-center gap-3">
                            <span className="font-mono text-xs font-bold w-16 flex-shrink-0" style={{ color: s.color }}>
                              {s.label}
                            </span>
                            <span className="font-mono text-xs text-terminal-ghost w-20 flex-shrink-0">{s.range}</span>
                            <span className="font-mono text-xs text-terminal-dim">{s.desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Intelligence correlation note */}
                    <div className="terminal-card p-3 border-matrix-400/30 bg-matrix-400/5">
                      <div className="flex items-start gap-2">
                        <AlertTriangle size={13} className="text-matrix-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <p className="font-mono text-xs text-matrix-400 font-bold mb-1">
                            {lang === 'pt' ? 'Correlações de ataque' : 'Attack correlations'}
                          </p>
                          <p className="font-mono text-xs text-terminal-dim leading-relaxed">
                            {lang === 'pt'
                              ? 'O módulo Intelligence combina múltiplos findings em cadeias de ataque. Por exemplo: XSS + missing CSP + cookie sem HttpOnly = cadeia de roubo de sessão com score amplificado.'
                              : 'The Intelligence module combines multiple findings into attack chains. E.g.: XSS + missing CSP + cookie without HttpOnly = session hijack chain with amplified score.'}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Timing note */}
                    <div className="flex items-start gap-2 px-1">
                      <Clock size={12} className="text-terminal-ghost flex-shrink-0 mt-0.5" />
                      <p className="font-mono text-xs text-terminal-ghost leading-relaxed">
                        {lang === 'pt'
                          ? 'Tempo médio: stealth ~3 min · standard ~5 min · aggressive ~3 min (paralelo). Varia com o tamanho do alvo.'
                          : 'Average time: stealth ~3 min · standard ~5 min · aggressive ~3 min (parallel). Varies with target size.'}
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="px-5 py-3 border-t border-terminal-border flex-shrink-0 flex items-center justify-between">
                <span className="font-mono text-xs text-terminal-ghost">GhostScan v3 — MIT License</span>
                <button
                  onClick={() => setOpen(false)}
                  className="font-mono text-xs text-terminal-dim hover:text-matrix-400 transition-colors uppercase tracking-widest"
                >
                  {lang === 'pt' ? 'Fechar' : 'Close'} ×
                </button>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
