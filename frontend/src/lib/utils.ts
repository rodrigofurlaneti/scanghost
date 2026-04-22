import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDuration(duration: string | null): string {
  if (!duration) return '--'
  // ISO 8601 duration or HH:MM:SS
  const match = duration.match(/(\d+):(\d+):(\d+)/)
  if (match) {
    const [, h, m, s] = match
    const parts: string[] = []
    if (parseInt(h) > 0) parts.push(`${h}h`)
    if (parseInt(m) > 0) parts.push(`${m}m`)
    parts.push(`${s}s`)
    return parts.join(' ')
  }
  return duration
}

export function formatDate(iso: string | null): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

export function severityColor(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL': return '#ff0033'
    case 'HIGH':     return '#ff6600'
    case 'MEDIUM':   return '#ffcc00'
    case 'LOW':      return '#00aaff'
    default:         return '#888888'
  }
}

export function severityOrder(severity: string): number {
  switch (severity.toUpperCase()) {
    case 'CRITICAL': return 0
    case 'HIGH':     return 1
    case 'MEDIUM':   return 2
    case 'LOW':      return 3
    default:         return 4
  }
}

export function statusVariant(status: string): string {
  switch (status) {
    case 'Running':   return 'status-running'
    case 'Completed': return 'status-completed'
    case 'Failed':    return 'status-failed'
    case 'Pending':   return 'status-pending'
    case 'Cancelled': return 'status-cancelled'
    default:          return 'status-pending'
  }
}
