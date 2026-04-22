import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  label: string
  value: string | number
  icon: LucideIcon
  color?: string
  trend?: string
  delay?: number
}

export function StatCard({ label, value, icon: Icon, color = '#00FF41', trend, delay = 0 }: StatCardProps) {
  return (
    <motion.div
      className="terminal-card p-4 flex items-start justify-between gap-3"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut', delay }}
    >
      <div className="flex-1 min-w-0">
        <p className="font-mono text-xs text-terminal-dim uppercase tracking-widest mb-1 truncate">
          {label}
        </p>
        <p
          className="font-mono text-2xl sm:text-3xl font-bold tracking-tight"
          style={{ color, textShadow: `0 0 10px ${color}60` }}
        >
          {value}
        </p>
        {trend && (
          <p className="font-mono text-xs text-terminal-dim mt-1">{trend}</p>
        )}
      </div>
      <div
        className="flex-shrink-0 w-10 h-10 rounded-sm flex items-center justify-center border"
        style={{
          borderColor: `${color}40`,
          backgroundColor: `${color}10`,
        }}
      >
        <Icon size={18} style={{ color }} />
      </div>
    </motion.div>
  )
}
