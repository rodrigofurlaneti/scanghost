import { Terminal, Building2, Zap, Cloud } from 'lucide-react'
import { useTheme, THEMES, type Theme } from '@/contexts/ThemeContext'
import { cn } from '@/lib/utils'

/** Icon that visually correlates to each theme's identity */
const THEME_ICON: Record<Theme, React.ElementType> = {
  'matrix':       Terminal,   // Hacker terminal — the OG
  'bluesky-pro':  Building2,  // Corporate / enterprise
  'cyber-day':    Zap,        // Electric energy — cyber noon
  'bluesky-soft': Cloud,      // Soft floating sky
}

export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme()

  return (
    <div className="flex items-center gap-0.5" role="group" aria-label="Select theme">
      {THEMES.map(({ id, label, accent }) => {
        const Icon = THEME_ICON[id]
        const active = theme === id

        return (
          <div key={id} className="relative group">
            <button
              onClick={() => setTheme(id)}
              aria-label={label}
              aria-pressed={active}
              className={cn(
                'p-1.5 rounded-sm transition-all duration-200 focus:outline-none',
                'focus-visible:ring-1 focus-visible:ring-current',
                active
                  ? 'border border-current opacity-100'
                  : 'border border-transparent opacity-35 hover:opacity-70'
              )}
              style={{ color: active ? accent : undefined }}
            >
              <Icon size={13} strokeWidth={active ? 2.5 : 1.8} />
            </button>

            {/* Tooltip — CSS-only, no JS needed */}
            <div className="theme-tooltip" role="tooltip">
              {label}
            </div>
          </div>
        )
      })}
    </div>
  )
}
