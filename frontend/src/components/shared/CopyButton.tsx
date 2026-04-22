import { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

interface CopyButtonProps {
  text: string
  className?: string
}

export function CopyButton({ text, className }: CopyButtonProps) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {}
  }

  return (
    <button
      onClick={handleCopy}
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded-sm text-xs font-mono',
        'border border-terminal-border text-terminal-dim',
        'hover:border-matrix-400 hover:text-matrix-400 transition-all duration-200',
        className
      )}
      title={t('common.copy')}
    >
      {copied ? (
        <>
          <Check size={11} className="text-matrix-400" />
          {t('common.copied')}
        </>
      ) : (
        <>
          <Copy size={11} />
          {t('common.copy')}
        </>
      )}
    </button>
  )
}
