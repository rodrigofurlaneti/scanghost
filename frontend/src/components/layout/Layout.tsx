import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard,
  Search,
  History,
  Globe,
  Menu,
  X,
  Terminal,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { GlitchText } from '@/components/shared/GlitchText'

const NAV_ITEMS = [
  { to: '/',        icon: LayoutDashboard, key: 'dashboard' },
  { to: '/scan',    icon: Search,          key: 'scan' },
  { to: '/history', icon: History,         key: 'history' },
]

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { t, i18n } = useTranslation()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  const toggleLang = () => {
    i18n.changeLanguage(i18n.language === 'en' ? 'pt-BR' : 'en')
  }

  return (
    <div className="min-h-screen bg-scan scanlines flex flex-col">
      {/* ── Top bar ── */}
      <header className="sticky top-0 z-50 border-b border-terminal-border bg-terminal-bg/90 backdrop-blur-sm">
        <div className="flex items-center justify-between px-3 sm:px-6 h-12 sm:h-14">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 group">
            <Terminal
              size={20}
              className="text-matrix-400 group-hover:text-white transition-colors"
            />
            <GlitchText
              text="GHOSTSCAN"
              className="neon-text font-mono font-bold text-sm sm:text-base tracking-[0.2em]"
              glitchInterval={5000}
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
                  {t(`nav.${key}`)}
                  {active && <ChevronRight size={10} className="opacity-50" />}
                </Link>
              )
            })}
          </nav>

          {/* Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={toggleLang}
              className="hidden xs:flex items-center gap-1 px-2 py-1 rounded-sm border border-terminal-border text-terminal-dim hover:text-matrix-400 hover:border-matrix-400 font-mono text-xs transition-all"
            >
              <Globe size={12} />
              {i18n.language === 'pt-BR' ? 'PT' : 'EN'}
            </button>

            {/* Mobile menu button */}
            <button
              className="sm:hidden text-terminal-dim hover:text-matrix-400 p-1"
              onClick={() => setMobileOpen(v => !v)}
            >
              {mobileOpen ? <X size={20} /> : <Menu size={20} />}
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
                <button
                  onClick={toggleLang}
                  className="flex items-center gap-2 px-3 py-2.5 text-terminal-dim hover:text-matrix-400 font-mono text-sm"
                >
                  <Globe size={16} />
                  {i18n.language === 'pt-BR' ? 'English' : 'Português BR'}
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </header>

      {/* ── Main ── */}
      <main className="flex-1 overflow-hidden">
        {children}
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-terminal-border px-4 py-2 text-center font-mono text-xs text-terminal-ghost">
        <span className="neon-text opacity-50">GHOSTSCAN</span>
        <span className="mx-2 text-terminal-ghost">|</span>
        <span className="text-terminal-ghost">Advanced Web Vulnerability Scanner</span>
      </footer>
    </div>
  )
}
