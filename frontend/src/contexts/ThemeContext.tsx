import { createContext, useContext, useEffect, useState } from 'react'

export type Theme = 'matrix' | 'bluesky-pro' | 'cyber-day' | 'bluesky-soft'

export interface ThemeConfig {
  id: Theme
  label: string
  accent: string   // hex for icon color
}

export const THEMES: ThemeConfig[] = [
  { id: 'matrix',       label: 'Matrix Dark',  accent: '#00FF41' },
  { id: 'bluesky-pro',  label: 'BlueSky Pro',  accent: '#0057CC' },
  { id: 'cyber-day',    label: 'Cyber Day',    accent: '#0099FF' },
  { id: 'bluesky-soft', label: 'BlueSky Soft', accent: '#2563EB' },
]

interface ThemeContextValue {
  theme: Theme
  setTheme: (t: Theme) => void
  isDark: boolean
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'matrix',
  setTheme: () => {},
  isDark: true,
})

const STORAGE_KEY = 'ghostscan-theme'

function applyTheme(t: Theme) {
  document.documentElement.setAttribute('data-theme', t)
  // Update meta theme-color for mobile chrome
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) {
    meta.setAttribute('content', t === 'matrix' ? '#030a03' : '#f0f6ff')
  }
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    // Synchronous read so we know the starting state
    return (localStorage.getItem(STORAGE_KEY) as Theme) ?? 'matrix'
  })

  const setTheme = (t: Theme) => {
    setThemeState(t)
    localStorage.setItem(STORAGE_KEY, t)
    applyTheme(t)
  }

  // Apply on mount (catches cases where index.html script didn't run)
  useEffect(() => {
    applyTheme(theme)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const isDark = theme === 'matrix'

  return (
    <ThemeContext.Provider value={{ theme, setTheme, isDark }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
