const API_BASE = '/api/v1';

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const token = localStorage.getItem('cereberus_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...getHeaders(), ...options.headers as Record<string, string> },
  });

  if (response.status === 401) {
    localStorage.removeItem('cereberus_token');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(error.detail || 'Request failed');
  }

  return response.json();
}

export const api = {
  // Auth
  login: (username: string, password: string) =>
    request<{ access_token: string; token_type: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  register: (username: string, password: string) =>
    request<{ access_token: string; token_type: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getMe: () => request<{ sub: string; role: string }>('/auth/me'),

  // Dashboard
  getDashboardSummary: () => request<{
    alerts: Record<string, number>;
    events_today: number;
    modules: Array<{ name: string; enabled: boolean; health: string }>;
    vpn: { connected: boolean; protocol: string | null; provider: string | null; vpn_ip: string | null };
  }>('/dashboard/summary'),

  // VPN
  getVpnStatus: () => request('/vpn/status'),
  runLeakCheck: () => request('/vpn/leak-check'),
  runConfigAudit: () => request('/vpn/config-audit'),
  setKillSwitchMode: (mode: string) =>
    request('/vpn/kill-switch/mode', {
      method: 'POST',
      body: JSON.stringify({ mode }),
    }),
  getKillSwitchStatus: () => request('/vpn/kill-switch/status'),
  getRoutes: () => request('/vpn/routes'),

  // Alerts
  getAlerts: (params?: { limit?: number; severity?: string; unacknowledged_only?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.unacknowledged_only) searchParams.set('unacknowledged_only', 'true');
    const query = searchParams.toString();
    return request(`/alerts/${query ? '?' + query : ''}`);
  },
  acknowledgeAlerts: (alertIds: number[]) =>
    request('/alerts/acknowledge', {
      method: 'POST',
      body: JSON.stringify({ alert_ids: alertIds }),
    }),

  // Modules
  getModules: () => request('/modules/'),
  toggleModule: (name: string, enabled: boolean) =>
    request(`/modules/${name}/toggle`, {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),

  // Settings
  getSettings: (category?: string) => {
    const query = category ? `?category=${category}` : '';
    return request(`/settings/${query}`);
  },
  updateSetting: (key: string, value: string) =>
    request(`/settings/${key}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    }),

  // Network Sentinel
  getConnections: () => request('/network/connections'),
  getNetworkStats: () => request('/network/stats'),
  getFlaggedConnections: () => request('/network/flagged'),
  getAnomalyResult: () => request('/network/anomaly'),
  getAnomalyHistory: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/network/anomaly/history${query}`);
  },

  // Brute Force Shield
  getBruteForceEvents: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/security/brute-force/events${query}`);
  },
  getBruteForceBlocked: () => request('/security/brute-force/blocked'),
  unblockIp: (ip: string) =>
    request(`/security/brute-force/unblock/${ip}`, { method: 'POST' }),

  // File Integrity
  getIntegrityBaselines: () => request('/integrity/baselines'),
  triggerIntegrityScan: () => request('/integrity/scan', { method: 'POST' }),
  getIntegrityChanges: () => request('/integrity/changes'),

  // Process Analyzer
  getProcesses: () => request('/processes/'),
  getSuspiciousProcesses: () => request('/processes/suspicious'),
  getProcessTree: (pid: number) => request(`/processes/${pid}/tree`),

  // Vulnerability Scanner
  getVulnerabilities: () => request('/vulnerabilities/'),
  triggerVulnerabilityScan: () => request('/vulnerabilities/scan', { method: 'POST' }),
  getVulnerabilityReport: () => request('/vulnerabilities/report'),

  // Email Analyzer
  analyzeEmail: (text: string, urls: string[] = []) =>
    request('/email/analyze', {
      method: 'POST',
      body: JSON.stringify({ text, urls }),
    }),
  getRecentEmailAnalyses: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/email/recent${query}`);
  },

  // Resource Monitor
  getResourceCurrent: () => request('/resources/current'),
  getResourceHistory: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/resources/history${query}`);
  },
  getResourceAlerts: () => request('/resources/alerts'),

  // Persistence Scanner
  getPersistenceEntries: () => request('/persistence/entries'),
  getPersistenceChanges: () => request('/persistence/changes'),
  triggerPersistenceScan: () => request('/persistence/scan', { method: 'POST' }),
  getPersistenceStatus: () => request('/persistence/status'),

  // Analytics
  getAlertTrend: (hours?: number) => {
    const query = hours ? `?hours=${hours}` : '';
    return request(`/analytics/alert-trend${query}`);
  },
  getSeverityDistribution: () => request('/analytics/severity-distribution'),
  getModuleActivity: () => request('/analytics/module-activity'),
  getThreatHistory: (hours?: number) => {
    const query = hours ? `?hours=${hours}` : '';
    return request(`/analytics/threat-history${query}`);
  },

  // Reports
  generateReport: async () => {
    const response = await fetch(`${API_BASE}/reports/generate`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Report generation failed');
    return response.blob();
  },

  // Audit Log
  getAuditLogs: (params?: { limit?: number; username?: string; action?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.username) searchParams.set('username', params.username);
    if (params?.action) searchParams.set('action', params.action);
    const query = searchParams.toString();
    return request(`/audit/logs${query ? '?' + query : ''}`);
  },
  getAuditLog: (id: number) => request(`/audit/logs/${id}`),

  // Search
  search: (query: string, limit?: number) => {
    const searchParams = new URLSearchParams({ q: query });
    if (limit) searchParams.set('limit', String(limit));
    return request(`/search?${searchParams.toString()}`);
  },

  // Threat Intelligence
  getThreatLevel: () => request('/threats/level'),
  getThreatFeed: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/threats/feed${query}`);
  },
  getCorrelations: () => request('/threats/correlations'),

  // AI Operations
  getAiStatus: () => request('/ai/status'),
  trainAnomalyModels: (epochs?: number) => {
    const query = epochs ? `?epochs=${epochs}` : '';
    return request(`/ai/train/anomaly${query}`, { method: 'POST' });
  },
  trainResourceForecaster: (epochs?: number) => {
    const query = epochs ? `?epochs=${epochs}` : '';
    return request(`/ai/train/resource${query}`, { method: 'POST' });
  },
  trainBaseline: () => request('/ai/train/baseline', { method: 'POST' }),
  getAiModels: () => request('/ai/models'),
  rollbackModel: (modelName: string, version: number) =>
    request(`/ai/models/${modelName}/rollback/${version}`, { method: 'POST' }),
  getAnomalyEvents: (params?: { limit?: number; detector_type?: string; is_anomaly_only?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.detector_type) searchParams.set('detector_type', params.detector_type);
    if (params?.is_anomaly_only) searchParams.set('is_anomaly_only', 'true');
    const query = searchParams.toString();
    return request(`/ai/anomaly-events${query ? '?' + query : ''}`);
  },
  getAiPredictions: () => request('/ai/predictions'),
  getAiBaselines: () => request('/ai/baselines'),
  getAiDrift: () => request('/ai/drift'),
  getFeedbackStats: () => request('/ai/feedback-stats'),
  submitAlertFeedback: (alertId: number, feedback: 'true_positive' | 'false_positive') =>
    request(`/alerts/${alertId}/feedback`, {
      method: 'PATCH',
      body: JSON.stringify({ feedback }),
    }),
};
