import { useEffect, useRef } from 'react'

interface MatrixRainProps {
  opacity?: number
  speed?: number
  density?: number
  className?: string
}

const CHARS = 'GHOSTSCAN01アイウエオカキクケコサシスセソタチツテトナニヌネノ'.split('')

export function MatrixRain({
  opacity = 0.15,
  speed = 1,
  density = 0.03,
  className = '',
}: MatrixRainProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animId: number
    let columns: number[] = []
    const fontSize = 14

    const resize = () => {
      canvas.width  = canvas.offsetWidth
      canvas.height = canvas.offsetHeight
      const cols = Math.floor(canvas.width / fontSize)
      columns = Array.from({ length: cols }, () =>
        Math.floor(Math.random() * canvas.height / fontSize) * -1
      )
    }

    const draw = () => {
      ctx.fillStyle = `rgba(3, 10, 3, 0.05)`
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      ctx.font = `${fontSize}px 'JetBrains Mono', monospace`

      columns.forEach((y, i) => {
        const char = CHARS[Math.floor(Math.random() * CHARS.length)]
        const x = i * fontSize

        // Brightest char (head)
        if (y > 0) {
          ctx.fillStyle = '#ffffff'
          ctx.shadowColor = '#00FF41'
          ctx.shadowBlur = 8
          ctx.fillText(char, x, y * fontSize)
        }

        // Trail
        const trailGradient = Math.floor(Math.random() * 3)
        if (trailGradient === 0) {
          ctx.fillStyle = '#00FF41'
          ctx.shadowColor = '#00FF41'
          ctx.shadowBlur = 4
        } else if (trailGradient === 1) {
          ctx.fillStyle = '#00cc34'
          ctx.shadowBlur = 2
        } else {
          ctx.fillStyle = '#006619'
          ctx.shadowBlur = 0
        }

        if (y > 0) {
          ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], x, (y - 1) * fontSize)
        }

        // Reset column at bottom with random chance
        if (y * fontSize > canvas.height && Math.random() > (1 - density)) {
          columns[i] = 0
        }
        columns[i] += speed
      })

      ctx.shadowBlur = 0
    }

    let last = 0
    const interval = 60

    const loop = (time: number) => {
      if (time - last > interval) {
        draw()
        last = time
      }
      animId = requestAnimationFrame(loop)
    }

    resize()
    window.addEventListener('resize', resize)
    animId = requestAnimationFrame(loop)

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resize)
    }
  }, [speed, density])

  return (
    <canvas
      ref={canvasRef}
      className={`absolute inset-0 w-full h-full pointer-events-none ${className}`}
      style={{ opacity }}
    />
  )
}
