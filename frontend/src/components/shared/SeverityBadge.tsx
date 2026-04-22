import { cn } from '@/lib/utils'
import type { Severity } from '@/types'

interface SeverityBadgeProps {
  severity: string
  className?: string
}

const severityMap: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH:     'badge-high',
  MEDIUM:   'badge-medium',
  LOW:      'badge-low',
  INFO:     'badge-info',
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const cls = severityMap[severity.toUpperCase()] ?? 'badge-info'
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-mono font-semibold uppercase tracking-wide',
        cls,
        className
      )}
    >
      {severity}
    </span>
  )
}
