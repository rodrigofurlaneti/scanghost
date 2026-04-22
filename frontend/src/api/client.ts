import axios from 'axios'
import type {
  StartScanRequest,
  ScanListItem,
  ScanStatusResponse,
  VulnerabilityReportDto,
  PagedResult,
  Severity,
} from '@/types'

// Em desenvolvimento: usa proxy Vite (/api → localhost:5000)
// Em produção (Azure): define VITE_API_BASE_URL no App Service → Application Settings
const BASE_URL = import.meta.env.VITE_API_BASE_URL
  ? `${import.meta.env.VITE_API_BASE_URL}/api`
  : '/api'

const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// ── Scans ─────────────────────────────────────────────────────────────────────

export const startScan = async (req: StartScanRequest): Promise<{ scanId: string }> => {
  const { data } = await api.post<{ scanId: string }>('/scans', req)
  return data
}

export const getScanStatus = async (scanId: string): Promise<ScanStatusResponse> => {
  const { data } = await api.get<ScanStatusResponse>(`/scans/${scanId}/status`)
  return data
}

export const getScanReport = async (
  scanId: string,
  minSeverity?: Severity
): Promise<VulnerabilityReportDto> => {
  const params = minSeverity ? { minSeverity } : {}
  const { data } = await api.get<VulnerabilityReportDto>(`/scans/${scanId}/report`, { params })
  return data
}

export const cancelScan = async (scanId: string): Promise<void> => {
  await api.delete(`/scans/${scanId}`)
}

export const getScans = async (
  page = 1,
  pageSize = 20
): Promise<PagedResult<ScanListItem>> => {
  const { data } = await api.get<PagedResult<ScanListItem>>('/scans', {
    params: { page, pageSize },
  })
  return data
}

export const quickScan = async (req: StartScanRequest): Promise<VulnerabilityReportDto> => {
  const { data } = await api.post<VulnerabilityReportDto>('/scans/quick', req, {
    timeout: 360_000,
  })
  return data
}

export default api
