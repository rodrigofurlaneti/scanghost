import { useState, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface GlitchTextProps {
  text: string
  className?: string
  glitchInterval?: number
  glitchDuration?: number
  tag?: 'h1' | 'h2' | 'h3' | 'h4' | 'p' | 'span' | 'div'
}

const GLITCH_CHARS = '!<>-_\\/[]{}—=+*^?#@$%&'

export function GlitchText({
  text,
  className = '',
  glitchInterval = 3000,
  glitchDuration = 400,
  tag: Tag = 'span',
}: GlitchTextProps) {
  const [displayed, setDisplayed] = useState(text)
  const [isGlitching, setIsGlitching] = useState(false)
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>()

  useEffect(() => {
    const trigger = () => {
      setIsGlitching(true)
      let iterations = 0
      const totalIterations = glitchDuration / 50

      const interval = setInterval(() => {
        setDisplayed(
          text
            .split('')
            .map((char, idx) => {
              if (idx < iterations) return char
              if (char === ' ') return ' '
              return GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)]
            })
            .join('')
        )
        iterations += text.length / totalIterations
        if (iterations >= text.length) {
          clearInterval(interval)
          setDisplayed(text)
          setIsGlitching(false)
        }
      }, 50)
    }

    timeoutRef.current = setInterval(trigger, glitchInterval)
    return () => clearInterval(timeoutRef.current)
  }, [text, glitchInterval, glitchDuration])

  return (
    <Tag
      className={cn('glitch', isGlitching && 'active', className)}
      data-text={text}
    >
      {displayed}
    </Tag>
  )
}
