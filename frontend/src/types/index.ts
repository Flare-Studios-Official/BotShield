export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type RiskLevel = 'low' | 'moderate' | 'high' | 'critical';

export interface WebsiteFinding {
  id: string;
  category: string;
  name: string;
  severity: Severity;
  observed_value: string;
  description: string;
  implication: string;
  recommendation: string;
  confidence: string;
}

export interface RedirectHop {
  step: number;
  url: string;
  status_code: number;
  resolved_ip: string;
}

export interface WebsiteScanResponse {
  id: string;
  target_url: string;
  final_url: string;
  resolved_ip: string;
  status_code: number;
  response_time_ms: number;
  https_enforced: boolean;
  tls_version: string;
  tls_cert_issuer: string;
  tls_cert_expiry: string;
  content_type: string;
  content_length: number;
  server_header: string;
  redirect_count: number;
  redirect_chain: RedirectHop[];
  security_score: number;
  findings: WebsiteFinding[];
  created_at: string;
  disclaimer: string;
}

export interface WebsiteScanSummary {
  id: string;
  target_url: string;
  status_code: number;
  security_score: number;
  finding_count: number;
  created_at: string;
}

export interface ThreatSignal {
  category: string;
  indicator: string;
  severity: Severity;
  confidence: string;
  source: string;
  details: string;
}

export interface IPAnalysisResponse {
  id: string;
  ip_address: string;
  ip_version: number;
  is_routable: boolean;
  classification: string;
  asn: string;
  as_org: string;
  reverse_dns: string;
  country_code: string;
  country_name: string;
  city: string;
  is_datacenter: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  reputation_score: number;
  threat_level: RiskLevel;
  provider_sources: Record<string, string>;
  signals: ThreatSignal[];
  created_at: string;
  disclaimer: string;
}

export interface BotEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  http_method: string;
  path: string;
  user_agent: string;
  response_status: number;
  duration_ms: number;
  session_id: string;
  is_lab_traffic: boolean;
  lab_scenario: string;
}

export interface TriggeredRule {
  rule_id: string;
  rule_name: string;
  points_awarded: number;
  threshold: number;
  observed_value: number;
  explanation: string;
}

export interface BotDetectionResult {
  id: string;
  source_ip: string;
  risk_score: number;
  risk_level: RiskLevel;
  window_start: string;
  window_end: string;
  total_requests: number;
  status_404_count: number;
  unique_paths_count: number;
  triggered_rules: TriggeredRule[];
  evidence: string[];
  reviewed: boolean;
  reviewed_by: string;
  review_notes: string;
  is_false_positive: boolean;
  created_at: string;
}

export interface TopSuspiciousIP {
  source_ip: string;
  risk_score: number;
  risk_level: RiskLevel;
  request_count: number;
  last_seen: string;
  top_trigger: string;
}

export interface BotDashboardSummary {
  total_events: number;
  unique_ips: number;
  suspicious_count: number;
  requests_per_minute: number;
  risk_distribution: Record<string, number>;
  top_suspicious_ips: TopSuspiciousIP[];
  top_paths: { path: string; count: number }[];
  status_distribution: { status_code: number; count: number }[];
  recent_detections: BotDetectionResult[];
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  weight: number;
  threshold_value: number;
  enabled: boolean;
  updated_at: string;
}

export interface ProxyTestResponse {
  id: string;
  proxy_scheme: string;
  proxy_host: string;
  proxy_port: number;
  target_tested: string;
  success: boolean;
  latency_ms: number;
  egress_ip: string;
  egress_classification: string;
  error_message: string;
  created_at: string;
  disclaimer: string;
}

export interface LabSimulationResult {
  scenario: string;
  simulated_ip: string;
  events_generated: number;
  risk_score: number;
  risk_level: RiskLevel;
  triggered_rules: string[];
  evaluation: BotDetectionResult;
}
