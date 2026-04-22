import { useEffect, useRef, useCallback, useState } from 'react'
import * as signalR from '@microsoft/signalr'
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from '@/types'

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error'

interface UseSignalROptions {
  scanId: string | null
  onProgress?: (e: ScanProgressEvent) => void
  onCompleted?: (e: ScanCompletedEvent) => void
  onFailed?: (e: ScanFailedEvent) => void
}

export function useSignalR({ scanId, onProgress, onCompleted, onFailed }: UseSignalROptions) {
  const connectionRef = useRef<signalR.HubConnection | null>(null)
  const [state, setState] = useState<ConnectionState>('disconnected')

  const onProgressRef = useRef(onProgress)
  const onCompletedRef = useRef(onCompleted)
  const onFailedRef = useRef(onFailed)

  useEffect(() => { onProgressRef.current = onProgress }, [onProgress])
  useEffect(() => { onCompletedRef.current = onCompleted }, [onCompleted])
  useEffect(() => { onFailedRef.current = onFailed }, [onFailed])

  useEffect(() => {
    if (!scanId) return

    const hubBase = import.meta.env.VITE_API_BASE_URL ?? ''
    const connection = new signalR.HubConnectionBuilder()
      .withUrl(`${hubBase}/hubs/scan`)
      .withAutomaticReconnect([2000, 5000, 10000, 30000])
      // Suppress verbose SignalR console noise — backend may not be up yet
      .configureLogging(signalR.LogLevel.None)
      .build()

    connectionRef.current = connection

    connection.on('ScanProgress', (e: ScanProgressEvent) => {
      onProgressRef.current?.(e)
    })
    connection.on('ScanCompleted', (e: ScanCompletedEvent) => {
      onCompletedRef.current?.(e)
    })
    connection.on('ScanFailed', (e: ScanFailedEvent) => {
      onFailedRef.current?.(e)
    })

    connection.onreconnecting(() => setState('connecting'))
    connection.onreconnected(() => setState('connected'))
    connection.onclose(() => setState('disconnected'))

    setState('connecting')

    connection
      .start()
      .then(() => {
        setState('connected')
        return connection.invoke('SubscribeToScan', scanId)
      })
      .catch(() => {
        // Backend not available — silently fall back to HTTP polling
        setState('error')
      })

    return () => {
      const conn = connectionRef.current
      if (conn && conn.state !== signalR.HubConnectionState.Disconnected) {
        conn.invoke('UnsubscribeFromScan', scanId).catch(() => {})
        conn.stop().catch(() => {})
      }
      connectionRef.current = null
    }
  }, [scanId])

  const disconnect = useCallback(() => {
    connectionRef.current?.stop().catch(() => {})
  }, [])

  return { state, disconnect }
}
