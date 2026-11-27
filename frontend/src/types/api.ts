export type Classification = "safe" | "suspicious" | "phishing";
export type RiskLevel = "low" | "suspicious" | "high" | "critical";
export type Severity = "low" | "medium" | "high" | "critical";
export type ScanType = "email" | "url";
export type ComponentStatus =
  | "ok"
  | "degraded"
  | "no_data"
  | "unavailable"
  | "error"
  | "skipped";

export interface Indicator {
  name: string;
  severity: Severity;
  description: string;
  source: string;
}

export interface AnalysisComponent {
  name: string;
  label: string;
  status: ComponentStatus;
  score: number | null;
  confidence: number | null;
  weight: number | null;
  contribution: number | null;
  explanation: string;
  details: Record<string, unknown>;
}

export interface UrlResultSummary {
  url: string;
  domain: string;
  risk_score: number;
  classification: Classification;
  indicators: Indicator[];
  error: string | null;
}

export interface AnalysisResult {
  scan_id: number;
  scan_type: ScanType;
  input_summary: string;
  classification: Classification;
  risk_level: RiskLevel;
  risk_score: number;
  model_confidence: number | null;
  indicators: Indicator[];
  components: AnalysisComponent[];
  explanation: string;
  recommendation: string;
  llm_used: boolean;
  llm_sent_to_provider: boolean;
  created_at: string;
  details: Record<string, unknown>;
  url_results: UrlResultSummary[];
}

export interface EmailAnalysisRequest {
  subject: string;
  body: string;
  sender?: string | null;
  urls?: string[];
}

export interface UrlAnalysisRequest {
  url: string;
}

export interface ScanListItem {
  id: number;
  scan_type: ScanType;
  input_summary: string;
  classification: Classification;
  risk_level: RiskLevel;
  risk_score: number;
  model_confidence: number | null;
  llm_used: boolean;
  indicator_count: number;
  created_at: string;
}

export interface ScanPage {
  items: ScanListItem[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface DistributionPoint {
  name: string;
  value: number;
}

export interface IndicatorCount {
  name: string;
  count: number;
}

export interface RecentScan {
  id: number;
  scan_type: ScanType;
  input_summary: string;
  classification: Classification;
  risk_level: RiskLevel;
  risk_score: number;
  created_at: string;
}

export interface DashboardStats {
  total_scans: number;
  phishing_detections: number;
  suspicious_detections: number;
  safe_detections: number;
  critical_detections: number;
  average_risk_score: number;
  email_scans: number;
  url_scans: number;
  llm_assisted_scans: number;
  recent_scans: RecentScan[];
  distribution: DistributionPoint[];
  top_indicators: IndicatorCount[];
}

export interface TrendPoint {
  date: string;
  scans: number;
  phishing: number;
  average_risk_score: number;
}

export interface TrendResponse {
  days: number;
  points: TrendPoint[];
}

export interface ArtifactStatus {
  name: string;
  available: boolean;
  path: string;
  algorithm: string | null;
  trained_at: string | null;
  metrics: Record<string, unknown>;
}

export interface ModelStatus {
  email_model: ArtifactStatus;
  url_model: ArtifactStatus;
  domain_graph: ArtifactStatus;
  inference_mode: string;
  llm_enabled: boolean;
  llm_configured: boolean;
  llm_model: string;
  local_llm: ArtifactStatus | null;
  local_llm_enabled: boolean;
  local_llm_available: boolean;
  local_llm_model: string | null;
  llm_backend: string | null;
  notes: string[];
}

export interface HealthStatus {
  status: string;
  version: string;
  database: string;
  artifacts_ready: boolean;
  llm_enabled: boolean;
  local_llm_available?: boolean;
  timestamp: string;
}

export interface ValidationIssue {
  field: string;
  message: string;
}
