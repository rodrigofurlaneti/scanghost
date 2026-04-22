import type { Config } from 'tailwindcss'
import animate from 'tailwindcss-animate'

const config: Config = {
  darkMode: ['class'],
  content: [
    './index.html',
    './src/**/*.{ts,tsx,js,jsx}',
  ],
  theme: {
    extend: {
      colors: {
        // All terminal/* and matrix.400 are CSS-variable-driven so themes auto-adapt
        matrix: {
          50:  '#e6fff0',
          100: '#b3ffd0',
          200: '#66ffaa',
          300: '#33ff8c',
          // PRIMARY accent — resolved from CSS variable per theme
          400: 'rgb(var(--color-accent) / <alpha-value>)',
          500: '#00cc34',
          600: '#009927',
          700: '#006619',
          800: '#00330d',
          900: '#001a06',
        },
        terminal: {
          bg:      'rgb(var(--color-bg)      / <alpha-value>)',
          surface: 'rgb(var(--color-surface) / <alpha-value>)',
          border:  'rgb(var(--color-border)  / <alpha-value>)',
          muted:   'rgb(var(--color-muted)   / <alpha-value>)',
          text:    'rgb(var(--color-accent)  / <alpha-value>)',
          dim:     'rgb(var(--color-dim)     / <alpha-value>)',
          ghost:   'rgb(var(--color-ghost)   / <alpha-value>)',
        },
        severity: {
          critical: '#ff0033',
          high:     '#ff6600',
          medium:   '#ffcc00',
          low:      '#00aaff',
          info:     '#888888',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
        sans: ['"Inter"', 'system-ui', 'sans-serif'],
      },
      fontSize: {
        'xs':   ['0.64rem',  { lineHeight: '1rem' }],
        'sm':   ['0.8rem',   { lineHeight: '1.25rem' }],
        'base': ['1rem',     { lineHeight: '1.5rem' }],
        'lg':   ['1.25rem',  { lineHeight: '1.75rem' }],
        'xl':   ['1.563rem', { lineHeight: '2rem' }],
        '2xl':  ['1.953rem', { lineHeight: '2.25rem' }],
        '3xl':  ['2.441rem', { lineHeight: '2.75rem' }],
        '4xl':  ['3.052rem', { lineHeight: '3.25rem' }],
        '5xl':  ['3.815rem', { lineHeight: '4rem' }],
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      keyframes: {
        'blink': {
          '0%, 100%': { opacity: '1' },
          '50%':      { opacity: '0' },
        },
        'scan-line': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'glitch-1': {
          '0%, 100%': { clip: 'rect(0px, 9999px, 0px, 0px)', transform: 'none' },
          '20%':      { clip: 'rect(10px, 9999px, 30px, 0px)', transform: 'skewX(-2deg)' },
          '40%':      { clip: 'rect(50px, 9999px, 60px, 0px)', transform: 'skewX(1deg)' },
          '60%':      { clip: 'rect(20px, 9999px, 35px, 0px)', transform: 'skewX(-1deg)' },
          '80%':      { clip: 'rect(5px, 9999px, 15px, 0px)', transform: 'skewX(2deg)' },
        },
        'glitch-2': {
          '0%, 100%': { clip: 'rect(0px, 9999px, 0px, 0px)', transform: 'none' },
          '20%':      { clip: 'rect(40px, 9999px, 55px, 0px)', transform: 'skewX(2deg)' },
          '40%':      { clip: 'rect(15px, 9999px, 25px, 0px)', transform: 'skewX(-1deg)' },
          '60%':      { clip: 'rect(60px, 9999px, 80px, 0px)', transform: 'skewX(1deg)' },
          '80%':      { clip: 'rect(30px, 9999px, 45px, 0px)', transform: 'skewX(-2deg)' },
        },
        'pulse-green': {
          '0%, 100%': { boxShadow: '0 0 5px rgb(var(--color-accent)), 0 0 10px rgb(var(--color-accent))' },
          '50%':      { boxShadow: '0 0 20px rgb(var(--color-accent)), 0 0 40px rgb(var(--color-accent))' },
        },
        'flicker': {
          '0%, 19%, 21%, 23%, 25%, 54%, 56%, 100%': { opacity: '1' },
          '20%, 24%, 55%': { opacity: '0.4' },
        },
        'typing': {
          'from': { width: '0' },
          'to':   { width: '100%' },
        },
        'accordion-down': {
          from: { height: '0' },
          to:   { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to:   { height: '0' },
        },
        'theme-fade': {
          'from': { opacity: '0' },
          'to':   { opacity: '1' },
        },
      },
      animation: {
        'blink':          'blink 1s step-end infinite',
        'scan-line':      'scan-line 4s linear infinite',
        'glitch-1':       'glitch-1 0.3s linear infinite',
        'glitch-2':       'glitch-2 0.3s linear infinite',
        'pulse-green':    'pulse-green 2s ease-in-out infinite',
        'flicker':        'flicker 3s linear infinite',
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up':   'accordion-up 0.2s ease-out',
        'theme-fade':     'theme-fade 0.3s ease-out',
      },
      screens: {
        'watch': '160px',
        'xs':    '320px',
        'sm':    '640px',
        'md':    '768px',
        'lg':    '1024px',
        'xl':    '1280px',
        '2xl':   '1536px',
        '4k':    '2560px',
      },
    },
  },
  plugins: [animate],
}

export default config
