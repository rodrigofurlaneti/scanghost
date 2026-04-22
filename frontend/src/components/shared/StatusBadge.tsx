import { cn, statusVariant } from '@/lib/utils'
import { useTranslation } from 'react-i18next'

interface StatusBadgeProps {
  status: string
  className?: string
  pulse?: boolean
}

export function StatusBadge({ status, className, pulse }: StatusBadgeProps) {
  const { t } = useTranslation()
  const cls = statusVariant(status)

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-xs font-mono uppercase tracking-wide bg-transparent',
        cls,
        className
      )}
    >
      {pulse && status === 'Running' && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-matrix-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-matrix-400" />
        </span>
      )}
      {t(`status.${status}`, status)}
    </span>
  )
}
