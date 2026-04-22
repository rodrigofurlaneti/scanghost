import { Component, type ReactNode, type ErrorInfo } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[GhostScan] Render error:', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return this.props.fallback ?? (
        <div className="min-h-full flex items-center justify-center bg-terminal-bg">
          <div className="terminal-card p-8 max-w-lg w-full mx-4">
            <div className="flex items-center gap-3 mb-4">
              <span className="w-3 h-3 rounded-full bg-red-500" />
              <span className="w-3 h-3 rounded-full bg-yellow-500" />
              <span className="w-3 h-3 rounded-full bg-matrix-400" />
              <span className="font-mono text-xs text-terminal-dim ml-2 uppercase tracking-widest">
                runtime error
              </span>
            </div>
            <p className="font-mono text-sm text-red-400 mb-2">
              {this.state.error.message}
            </p>
            <p className="font-mono text-xs text-terminal-ghost mb-6">
              {this.state.error.stack?.split('\n')[1]?.trim()}
            </p>
            <button
              onClick={() => {
                this.setState({ error: null })
                window.location.href = '/'
              }}
              className="btn-ghost-scan text-sm"
            >
              Return to Dashboard
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
