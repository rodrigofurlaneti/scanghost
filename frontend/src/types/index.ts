// ── Scan types ──────────────────────────────────────────────────────────────

export type ScanStatus =
  | 'Pending'
  | 'Running'
  | 'Completed'
  | 'Failed'
  | 'Cancelled';

export type ScanProfile = 'stealth' | 'standard' | 'aggressive' | 'ghost';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

// ── API request/response types ───────────────────────────────────────────────

export interface StartScanRequest {
  target: string;
  profile?: ScanProfile;
}

export interface ScanListItem {
  id: string;
  target: string;
  profile: string;
  status: ScanStatus;
  startedAt: string | null;
  completedAt: string | null;
  duration: string | null;
  findingsCount: number;
}

export interface ScanStatusResponse {
  scanId: string;
  status: ScanStatus;
  percentComplete: number;
  phase: string;
  activity: string;
  findingsCount: number;
  startedAt: string | null;
  completedAt: string | null;
  duration: string | null;
}

// ── Report types ─────────────────────────────────────────────────────────────

export interface FindingDto {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  detail: string | null;
  url: string | null;
  evidence: string | null;
  remediation: string | null;
  attackPath: string | null;
  finalScore: number;
  impact: number;
  confidence: number;
  exploitability: number;
  businessImpact: number;
  vulnType: string | null;
  isConfirmed: boolean;
  contextBoost: number;
  discoveredAt: string;
}

export interface SummaryDto {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  bySeverity: Record<string, number>;
}

export interface PortInfoDto {
  port: number;
  state: string;
  service: string;
}

export interface ReconResultDto {
  subdomains: string[];
  dnsRecords: Record<string, string[]>;
  openPorts: Record<string, PortInfoDto[]>;
  zoneTransferSucceeded: boolean;
  emails: string[];
}

export interface WafDetectionDto {
  detected: boolean;
  wafName: string | null;
  confidence: number;
}

export interface JsSecretDto {
  type: string;
  pattern: string;
  url: string | null;
  value: string;
}

export interface HeaderAuditDto {
  missingHeaders: string[];
  dangerousHeaders: string[];
}

export interface WebAnalysisResultDto {
  endpoints: string[];
  baseUrls: string[];
  waf: WafDetectionDto | null;
  technologies: Record<string, string[]>;
  jsSecrets: JsSecretDto[];
  headerAudit: HeaderAuditDto | null;
}

export interface CorrelationDto {
  title: string;
  severity: string;
  score: number;
  description: string;
  attackPath: string | null;
  remediation: string | null;
  multiplier: number;
}

export interface RankedTargetDto {
  url: string;
  score: number;
  priority: string;
  reasons: string[];
}

export interface RecommendationDto {
  priority: number;
  severity: string;
  action: string;
  command: string | null;
}

export interface IntelligenceResultDto {
  totalRaw: number;
  totalScored: number;
  totalCorrelations: number;
  afterDedup: number;
  afterFilter: number;
  attackSurface: number;
}

export interface VulnerabilityReportDto {
  scanId: string;
  target: string;
  profile: string;
  status: ScanStatus;
  startedAt: string | null;
  completedAt: string | null;
  duration: string | null;
  summary: SummaryDto;
  findings: FindingDto[];
  correlations: CorrelationDto[];
  rankedTargets: RankedTargetDto[];
  recommendations: RecommendationDto[];
  reconResults: ReconResultDto | null;
  webResults: WebAnalysisResultDto | null;
  intelligenceResults: IntelligenceResultDto | null;
}

export interface PagedResult<T> {
  items: T[];
  totalCount: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ── SignalR event types ───────────────────────────────────────────────────────

export interface ScanProgressEvent {
  scanId: string;
  percentComplete: number;
  phase: string;
  activity: string;
  findingsCount: number;
}

export interface ScanCompletedEvent {
  scanId: string;
  findingsCount: number;
  duration: string;
}

export interface ScanFailedEvent {
  scanId: string;
  error: string;
}
