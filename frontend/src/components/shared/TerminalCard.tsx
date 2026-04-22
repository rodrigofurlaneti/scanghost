import { cn } from '@/lib/utils'
import { motion } from 'framer-motion'

interface TerminalCardProps {
  children: React.ReactNode
  className?: string
  title?: string
  titleRight?: React.ReactNode
  animate?: boolean
  neon?: boolean
}

export function TerminalCard({
  children,
  className,
  title,
  titleRight,
  animate = false,
  neon = false,
}: TerminalCardProps) {
  const Wrapper = animate ? motion.div : 'div'
  const motionProps = animate
    ? {
        initial: { opacity: 0, y: 12 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.3, ease: 'easeOut' },
      }
    : {}

  return (
    <Wrapper
      className={cn('terminal-card', neon && 'neon-border', className)}
      {...motionProps}
    >
      {title && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-terminal-border">
          <div className="flex items-center gap-2">
            {/* Window chrome dots */}
            <span className="w-2.5 h-2.5 rounded-full bg-red-600 opacity-70" />
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 opacity-70" />
            <span className="w-2.5 h-2.5 rounded-full bg-matrix-400 opacity-70" />
            <span className="ml-2 font-mono text-xs text-terminal-dim uppercase tracking-widest">
              {title}
            </span>
          </div>
          {titleRight && <div>{titleRight}</div>}
        </div>
      )}
      {children}
    </Wrapper>
  )
}
