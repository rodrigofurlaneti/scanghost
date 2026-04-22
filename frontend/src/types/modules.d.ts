// Ambient declarations for packages whose .d.ts wasn't unpacked in this environment.
// On a full npm install the real types will take precedence.

declare module 'framer-motion' {
  import type { ComponentType, CSSProperties, ReactNode, Ref } from 'react'

  export type Variant = Record<string, unknown>
  export interface MotionProps {
    initial?: Record<string, unknown> | string
    animate?: Record<string, unknown> | string
    exit?: Record<string, unknown> | string
    transition?: Record<string, unknown>
    variants?: Record<string, Variant>
    className?: string
    style?: CSSProperties
    children?: ReactNode
    key?: string | number
    onClick?: React.MouseEventHandler
    ref?: Ref<unknown>
    layout?: boolean
    layoutId?: string
    whileHover?: Record<string, unknown>
    whileTap?: Record<string, unknown>
    [key: string]: unknown
  }

  export const motion: {
    div: ComponentType<MotionProps & React.HTMLAttributes<HTMLDivElement>>
    span: ComponentType<MotionProps & React.HTMLAttributes<HTMLSpanElement>>
    p: ComponentType<MotionProps & React.HTMLAttributes<HTMLParagraphElement>>
    section: ComponentType<MotionProps & React.HTMLAttributes<HTMLElement>>
    ul: ComponentType<MotionProps & React.HTMLAttributes<HTMLUListElement>>
    li: ComponentType<MotionProps & React.HTMLAttributes<HTMLLIElement>>
    button: ComponentType<MotionProps & React.ButtonHTMLAttributes<HTMLButtonElement>>
    h1: ComponentType<MotionProps & React.HTMLAttributes<HTMLHeadingElement>>
    h2: ComponentType<MotionProps & React.HTMLAttributes<HTMLHeadingElement>>
    h3: ComponentType<MotionProps & React.HTMLAttributes<HTMLHeadingElement>>
    img: ComponentType<MotionProps & React.ImgHTMLAttributes<HTMLImageElement>>
    [key: string]: ComponentType<MotionProps & Record<string, unknown>>
  }

  export const AnimatePresence: ComponentType<{
    children?: ReactNode
    mode?: 'wait' | 'sync' | 'popLayout'
    initial?: boolean
    onExitComplete?: () => void
  }>

  export const useAnimation: () => unknown
  export const useMotionValue: (initial: number) => unknown
  export const useTransform: (...args: unknown[]) => unknown
  export const useSpring: (...args: unknown[]) => unknown
  export const useInView: (ref: Ref<unknown>, options?: unknown) => boolean
  export const useReducedMotion: () => boolean | null
}

declare module 'recharts' {
  import type { ComponentType, ReactNode, CSSProperties } from 'react'

  export type DataKey = string | number | ((obj: unknown) => unknown)

  export interface BaseAxisProps {
    dataKey?: DataKey
    tick?: boolean | ComponentType | Record<string, unknown>
    axisLine?: boolean | Record<string, unknown>
    tickLine?: boolean | Record<string, unknown>
    label?: string | number | ReactNode | Record<string, unknown>
    [key: string]: unknown
  }

  export const ResponsiveContainer: ComponentType<{
    width?: string | number
    height?: string | number
    children?: ReactNode
    [key: string]: unknown
  }>

  export const BarChart: ComponentType<{
    data?: unknown[]
    barSize?: number
    children?: ReactNode
    [key: string]: unknown
  }>

  export const Bar: ComponentType<{
    dataKey: DataKey
    fill?: string
    radius?: number | [number, number, number, number]
    children?: ReactNode
    [key: string]: unknown
  }>

  export const XAxis: ComponentType<BaseAxisProps>
  export const YAxis: ComponentType<BaseAxisProps>

  export const Tooltip: ComponentType<{
    content?: ComponentType<{
      active?: boolean
      payload?: Array<{ name: string; value: number; fill: string }>
    }> | ReactNode
    [key: string]: unknown
  }>

  export const Cell: ComponentType<{
    fill?: string
    stroke?: string
    key?: string | number
    [key: string]: unknown
  }>

  export const RadarChart: ComponentType<{
    data?: unknown[]
    children?: ReactNode
    [key: string]: unknown
  }>

  export const Radar: ComponentType<{
    name?: string
    dataKey: DataKey
    stroke?: string
    fill?: string
    fillOpacity?: number
    [key: string]: unknown
  }>

  export const PolarGrid: ComponentType<{
    stroke?: string
    [key: string]: unknown
  }>

  export const PolarAngleAxis: ComponentType<BaseAxisProps>

  export const LineChart: ComponentType<{
    data?: unknown[]
    children?: ReactNode
    [key: string]: unknown
  }>

  export const Line: ComponentType<{
    dataKey: DataKey
    stroke?: string
    type?: string
    dot?: boolean
    [key: string]: unknown
  }>

  export const PieChart: ComponentType<{ children?: ReactNode; [key: string]: unknown }>
  export const Pie: ComponentType<{ data?: unknown[]; children?: ReactNode; [key: string]: unknown }>
  export const Legend: ComponentType<Record<string, unknown>>
}
