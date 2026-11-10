import {
  BotDashboardSummary,
  BotDetectionResult,
  BotEvent,
  DetectionRule,
  IPAnalysisResponse,
  LabSimulationResult,
  ProxyTestResponse,
  WebsiteScanResponse,
  WebsiteScanSummary,
} from '../types';

const API_BASE = '/api';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errMsg = `Request failed (${res.status})`;
    try {
      const errJson = await res.json();
      errMsg = errJson.detail || errJson.error || errMsg;
    } catch {
      // Non-JSON error
    }
    throw new Error(errMsg);
  }
  return res.json();
}

export const api = {
  // Health
  getHealth: () => fetch(`${API_BASE}/health`).then(handleResponse<{ status: string; app: string; version: string; database: string }>),

  // Website Security
  scanWebsite: (targetUrl: string) =>
    fetch(`${API_BASE}/websites/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: targetUrl }),
    }).then(handleResponse<WebsiteScanResponse>),

  listWebsiteScans: (limit = 20, offset = 0) =>
    fetch(`${API_BASE}/websites/scans?limit=${limit}&offset=${offset}`).then(handleResponse<WebsiteScanSummary[]>),

  getWebsiteScan: (id: string) =>
    fetch(`${API_BASE}/websites/scans/${id}`).then(handleResponse<WebsiteScanResponse>),

  // IP Intelligence
  analyzeIp: (ipAddress: string) =>
    fetch(`${API_BASE}/ips/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ipAddress }),
    }).then(handleResponse<IPAnalysisResponse>),

  getIpHistory: (limit = 20) =>
    fetch(`${API_BASE}/ips/history?limit=${limit}`).then(handleResponse<IPAnalysisResponse[]>),

  // Bot Detection
  getBotSummary: () =>
    fetch(`${API_BASE}/bots/summary`).then(handleResponse<BotDashboardSummary>),

  listBotEvents: (limit = 50, sourceIp?: string) => {
    const url = sourceIp
      ? `${API_BASE}/bots/events?limit=${limit}&source_ip=${encodeURIComponent(sourceIp)}`
      : `${API_BASE}/bots/events?limit=${limit}`;
    return fetch(url).then(handleResponse<BotEvent[]>);
  },

  listRules: () =>
    fetch(`${API_BASE}/bots/rules`).then(handleResponse<DetectionRule[]>),

  updateRule: (ruleId: string, payload: Partial<DetectionRule>) =>
    fetch(`${API_BASE}/bots/rules/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(handleResponse<DetectionRule>),

  reviewDetection: (detectionId: string, reviewedBy: string, notes: string, isFalsePositive: boolean) =>
    fetch(`${API_BASE}/bots/detections/${detectionId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reviewed_by: reviewedBy,
        review_notes: notes,
        is_false_positive: isFalsePositive,
      }),
    }).then(handleResponse<BotDetectionResult>),

  // Proxy Intelligence
  testProxy: (proxyUrl: string, targetUrl?: string) =>
    fetch(`${API_BASE}/proxies/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy_url: proxyUrl, target_url: targetUrl }),
    }).then(handleResponse<ProxyTestResponse>),

  getProxyHistory: (limit = 20) =>
    fetch(`${API_BASE}/proxies/history?limit=${limit}`).then(handleResponse<ProxyTestResponse[]>),

  // Detection Lab
  runLabScenario: (scenario: string, count = 25, intervalMs = 50) =>
    fetch(`${API_BASE}/lab/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario, request_count: count, interval_ms: intervalMs }),
    }).then(handleResponse<LabSimulationResult>),

  resetLab: () =>
    fetch(`${API_BASE}/lab/reset`, { method: 'POST' }).then(handleResponse<{ status: string; message: string; deleted_count: number }>),

  // Reports
  getWebsiteReportJsonUrl: (scanId: string) => `${API_BASE}/reports/website/${scanId}/json`,
  getWebsiteReportPdfUrl: (scanId: string) => `${API_BASE}/reports/website/${scanId}/pdf`,
  getIpReportJsonUrl: (recordId: string) => `${API_BASE}/reports/ip/${recordId}/json`,
  getIpReportPdfUrl: (recordId: string) => `${API_BASE}/reports/ip/${recordId}/pdf`,
};
