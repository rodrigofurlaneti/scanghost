import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard, Search, History,
  Globe, Menu, X, Terminal, ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { GlitchText } from '@/components/shared/GlitchText'
import { ThemeSwitcher } from '@/components/shared/ThemeSwitcher'
import { useTheme } from '@/contexts/ThemeContext'

const NAV_ITEMS = [
  { to: '/',        icon: LayoutDashboard, key: 'dashboard' },
  { to: '/scan',    icon: Search,          key: 'scan' },
  { to: '/history', icon: History,         key: 'history' },
]

// Language cycle: EN → PT → ES → EN
const LANGS = [
  { code: 'en',    label: 'EN', full: 'English' },
  { code: 'pt-BR', label: 'PT', full: 'Português BR' },
  { code: 'es',    label: 'ES', full: 'Español' },
]

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { t, i18n } = useTranslation()
  const location = useLocation()
  const { isDark } = useTheme()
  const [mobileOpen, setMobileOpen] = useState(false)

  const currentLangIdx = LANGS.findIndex(l => l.code === i18n.language) ?? 0
  const currentLang = LANGS[Math.max(0, currentLangIdx)]
  const nextLang = LANGS[(Math.max(0, currentLangIdx) + 1) % LANGS.length]

  const cycleLang = () => i18n.changeLanguage(nextLang.code)

  return (
    <div className={cn('min-h-screen bg-scan flex flex-col', isDark && 'scanlines')}>
      {/* ── Top bar ────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-terminal-border bg-terminal-bg/90 backdrop-blur-sm">
        <div className="flex items-center justify-between px-2 xs:px-3 sm:px-6 h-10 sm:h-14 watch:h-8">

          {/* Logo */}
          <Link to="/" className="flex items-center gap-1.5 group flex-shrink-0">
            <Terminal
              size={16}
              className="text-matrix-400 group-hover:opacity-80 transition-opacity sm:w-5 sm:h-5"
            />
            <GlitchText
              text="GHOSTSCAN"
              className="neon-text font-mono font-bold text-xs sm:text-sm lg:text-base tracking-[0.15em] sm:tracking-[0.2em] watch:text-[9px] watch:tracking-tight"
              glitchInterval={isDark ? 5000 : 999999}
            />
          </Link>

          {/* Desktop nav */}
          <nav className="hidden sm:flex items-center gap-1">
            {NAV_ITEMS.map(({ to, icon: Icon, key }) => {
              const active = location.pathname === to ||
                (to !== '/' && location.pathname.startsWith(to))
              return (
                <Link
                  key={key}
                  to={to}
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded-sm font-mono text-xs uppercase tracking-widest transition-all duration-200',
                    active
                      ? 'bg-terminal-muted text-matrix-400 border border-terminal-border'
                      : 'text-terminal-dim hover:text-matrix-400 hover:bg-terminal-surface'
                  )}
                >
                  <Icon size={13} />
                  <span className="hidden lg:inline">{t(`nav.${key}`)}</span>
                  {active && <ChevronRight size={10} className="opacity-50 hidden lg:block" />}
                </Link>
              )
            })}
          </nav>

          {/* Actions row */}
          <div className="flex items-center gap-1.5 sm:gap-2">
            {/* Theme switcher — desktop */}
            <div className="hidden xs:flex items-center">
              <ThemeSwitcher />
            </div>

            {/* Language cycle — desktop */}
            <div className="relative group hidden xs:block">
              <button
                onClick={cycleLang}
                aria-label={`Switch to ${nextLang.full}`}
                className="flex items-center gap-1 px-2 py-1 rounded-sm border border-terminal-border
                           text-terminal-dim hover:text-matrix-400 hover:border-matrix-400
                           font-mono text-xs transition-all duration-200"
              >
                <Globe size={11} />
                <span>{currentLang.label}</span>
              </button>
              {/* Tooltip showing next language */}
              <div className="theme-tooltip">→ {nextLang.full}</div>
            </div>

            {/* Mobile menu button */}
            <button
              className="sm:hidden text-terminal-dim hover:text-matrix-400 p-1 transition-colors"
              onClick={() => setMobileOpen(v => !v)}
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        <AnimatePresence>
          {mobileOpen && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="sm:hidden border-t border-terminal-border bg-terminal-bg overflow-hidden"
            >
              <div className="flex flex-col p-3 gap-1">
                {NAV_ITEMS.map(({ to, icon: Icon, key }) => {
                  const active = location.pathname === to
                  return (
                    <Link
                      key={key}
                      to={to}
                      onClick={() => setMobileOpen(false)}
                      className={cn(
                        'flex items-center gap-2 px-3 py-2.5 rounded-sm font-mono text-sm uppercase tracking-widest',
                        active
                          ? 'bg-terminal-muted text-matrix-400 border border-terminal-border'
                          : 'text-terminal-dim hover:text-matrix-400'
                      )}
                    >
                      <Icon size={16} />
                      {t(`nav.${key}`)}
                    </Link>
                  )
                })}

                {/* Mobile: theme row + lang */}
                <div className="flex items-center justify-between px-3 py-2 border-t border-terminal-border mt-1 pt-2">
                  <ThemeSwitcher />
                  <button
                    onClick={cycleLang}
                    className="flex items-center gap-2 text-terminal-dim hover:text-matrix-400 font-mono text-sm"
                  >
                    <Globe size={16} />
                    {currentLang.full} → {nextLang.label}
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </header>

      {/* ── Main ────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-hidden">
        {children}
      </main>

      {/* ── Footer ──────────────────────────────────────────────── */}
      <footer className="border-t border-terminal-border px-4 py-2 text-center font-mono text-xs text-terminal-ghost">
        <span className="neon-text opacity-50">GHOSTSCAN</span>
        <span className="mx-2 text-terminal-ghost">|</span>
        <span className="text-terminal-ghost hidden xs:inline">Advanced Web Vulnerability Scanner</span>
      </footer>
    </div>
  )
}
