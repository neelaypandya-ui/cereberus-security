import { validateResponse } from '../bridge/validators';

const API_BASE = '/api/v1';

let _refreshPromise: Promise<string | null> | null = null;

// CSRF token received from login — stored in memory only (not localStorage)
let _csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  _csrfToken = token;
}

export function getCsrfToken(): string | null {
  return _csrfToken;
}

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  // Include CSRF token on state-changing requests
  if (_csrfToken) {
    headers['X-CSRF-Token'] = _csrfToken;
  }
  return headers;
}

async function _attemptTokenRefresh(): Promise<string | null> {
  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: getHeaders(),
    });

    if (!response.ok) return null;

    const data = await response.json();
    if (data.csrf_token) {
      _csrfToken = data.csrf_token;
    }
    return data.access_token || null;
  } catch {
    return null;
  }
}

async function _refreshAndRetry<T>(path: string, options: RequestInit): Promise<T | null> {
  if (!_refreshPromise) {
    _refreshPromise = _attemptTokenRefresh().finally(() => { _refreshPromise = null; });
  }
  const newToken = await _refreshPromise;
  if (newToken) {
    const retryResponse = await fetch(`${API_BASE}${path}`, {
      ...options,
      credentials: 'include',
      headers: { ...getHeaders(), ...options.headers as Record<string, string> },
    });
    if (retryResponse.ok) {
      return retryResponse.json();
    }
  }
  return null;
}

// Bridge validation registry: path pattern → [contractName, requiredKeys]
const _bridgeValidationMap: Record<string, [string, string[]]> = {
  '/bond/status': ['BondStatusResponse', ['state', 'threat_count', 'scan_interval_seconds']],
  '/bond/guardian': ['GuardianStatusResponse', ['containment_level', 'level_name', 'lockdown_active']],
  '/bond/overwatch/status': ['OverwatchStatus', ['status', 'files_baselined', 'tamper_count']],
  '/network/connections': ['NetworkConnectionResponse', ['local_addr', 'remote_addr', 'protocol']],
  '/yara/rules': ['YaraRuleResponse', ['id', 'name', 'enabled']],
  '/yara/results': ['YaraScanResultResponse', ['id', 'scan_type', 'rule_name']],
  '/memory/results': ['MemoryScanResultResponse', ['id', 'pid', 'process_name']],
  '/bond/sword/policies': ['SwordPolicyResponse', ['id', 'codename', 'name']],
  '/bond/sword/logs': ['SwordLogResponse', ['id', 'policy_id', 'codename']],
};

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: 'include',
    headers: { ...getHeaders(), ...options.headers as Record<string, string> },
  });

  // Handle 401 (expired token) or 403 (missing/invalid CSRF) by refreshing
  if (response.status === 401 || response.status === 403) {
    const isAuthEndpoint = path.startsWith('/auth/');
    if (!isAuthEndpoint) {
      const result = await _refreshAndRetry<T>(path, options);
      if (result !== null) return result;
    }

    // Session expired — clear CSRF and redirect
    _csrfToken = null;
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(error.detail || 'Request failed');
  }

  const data = await response.json();

  // Bridge validation — console.warn only, never blocks
  const entry = _bridgeValidationMap[path];
  if (entry) {
    validateResponse(data, entry[0], entry[1]);
  }

  return data;
}

export const api = {
  // Auth
  login: async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(error.detail || 'Login failed');
    }
    const data = await response.json();
    // Store CSRF token in memory (JWT is in httpOnly cookie)
    if (data.csrf_token) {
      _csrfToken = data.csrf_token;
    }
    return data;
  },

  register: (username: string, password: string) =>
    request<{ access_token: string; token_type: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getMe: () => request<{ sub: string; role: string }>('/auth/me'),

  refreshToken: () => request('/auth/refresh', { method: 'POST' }),

  logout: async () => {
    try {
      await request('/auth/logout', { method: 'POST' });
    } catch { /* ignore */ }
    _csrfToken = null;
  },

  changePassword: (currentPassword: string, newPassword: string) =>
    request('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),

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
  getAlerts: (params?: { limit?: number; offset?: number; severity?: string; unacknowledged_only?: boolean; show_dismissed?: boolean; show_snoozed?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.unacknowledged_only) searchParams.set('unacknowledged_only', 'true');
    if (params?.show_dismissed) searchParams.set('show_dismissed', 'true');
    if (params?.show_snoozed) searchParams.set('show_snoozed', 'true');
    const query = searchParams.toString();
    return request(`/alerts/${query ? '?' + query : ''}`);
  },
  acknowledgeAlerts: (alertIds: number[]) =>
    request('/alerts/acknowledge', {
      method: 'POST',
      body: JSON.stringify({ alert_ids: alertIds }),
    }),
  dismissAlert: (id: number) => request(`/alerts/${id}/dismiss`, { method: 'POST' }),
  dismissAlerts: (alertIds: number[]) =>
    request('/alerts/dismiss', { method: 'POST', body: JSON.stringify({ alert_ids: alertIds }) }),
  dismissAllAlerts: () => request('/alerts/dismiss-all', { method: 'POST' }),
  acknowledgeAllAlerts: () => request('/alerts/acknowledge-all', { method: 'POST' }),
  escalateAlert: (id: number) => request(`/alerts/${id}/escalate`, { method: 'POST' }),
  snoozeAlert: (id: number, hours: number = 1) =>
    request(`/alerts/${id}/snooze?hours=${hours}`, { method: 'POST' }),

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
  getBruteForceEvents: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    const query = searchParams.toString();
    return request(`/security/brute-force/events${query ? '?' + query : ''}`);
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

  // Vulnerability Remediation
  remediateVulnerability: (data: { category: string; port?: number; service?: string }) =>
    request('/vulnerabilities/remediate', { method: 'POST', body: JSON.stringify(data) }),

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
    let response = await fetch(`${API_BASE}/reports/generate`, {
      method: 'POST',
      credentials: 'include',
      headers: getHeaders(),
    });
    // Handle missing CSRF token (e.g. after page refresh)
    if (response.status === 403 || response.status === 401) {
      const refreshed = await _attemptTokenRefresh();
      if (refreshed) {
        response = await fetch(`${API_BASE}/reports/generate`, {
          method: 'POST',
          credentials: 'include',
          headers: getHeaders(),
        });
      }
    }
    if (!response.ok) throw new Error('Report generation failed');
    return response.blob();
  },

  // Audit Log
  getAuditLogs: (params?: { limit?: number; offset?: number; username?: string; action?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
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
  getAnomalyEvents: (params?: { limit?: number; offset?: number; detector_type?: string; is_anomaly_only?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
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

  // === Phase 7: Incidents ===
  getIncidents: (params?: { status?: string; severity?: string; assigned_to?: string; limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.assigned_to) searchParams.set('assigned_to', params.assigned_to);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    const query = searchParams.toString();
    return request(`/incidents/${query ? '?' + query : ''}`);
  },
  createIncident: (data: { title: string; severity: string; description?: string; category?: string; source_alert_ids?: number[] }) =>
    request('/incidents/', { method: 'POST', body: JSON.stringify(data) }),
  getIncident: (id: number) => request(`/incidents/${id}`),
  updateIncidentStatus: (id: number, newStatus: string, note?: string) =>
    request(`/incidents/${id}/status`, { method: 'PATCH', body: JSON.stringify({ new_status: newStatus, note }) }),
  assignIncident: (id: number, username: string) =>
    request(`/incidents/${id}/assign`, { method: 'PATCH', body: JSON.stringify({ username }) }),
  addIncidentNote: (id: number, note: string) =>
    request(`/incidents/${id}/note`, { method: 'POST', body: JSON.stringify({ note }) }),
  addIncidentTimeline: (id: number, event: string, details?: string) =>
    request(`/incidents/${id}/timeline`, { method: 'POST', body: JSON.stringify({ event, details }) }),
  getIncidentActions: (id: number) => request(`/incidents/${id}/actions`),
  getIncidentStats: () => request('/incidents/stats'),

  // === Phase 7: Playbooks ===
  getPlaybooks: () => request('/playbooks/'),
  createPlaybook: (data: { name: string; description?: string; trigger_type: string; trigger_conditions: unknown; actions: unknown[]; cooldown_seconds?: number; requires_confirmation?: boolean }) =>
    request('/playbooks/', { method: 'POST', body: JSON.stringify(data) }),
  getPlaybook: (id: number) => request(`/playbooks/${id}`),
  updatePlaybook: (id: number, data: Record<string, unknown>) =>
    request(`/playbooks/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deletePlaybook: (id: number) => request(`/playbooks/${id}`, { method: 'DELETE' }),
  togglePlaybook: (id: number) => request(`/playbooks/${id}/toggle`, { method: 'PATCH' }),
  executePlaybook: (id: number, context: Record<string, unknown>) =>
    request(`/playbooks/${id}/execute`, { method: 'POST', body: JSON.stringify({ event_context: context }) }),
  dryRunPlaybook: (id: number, context: Record<string, unknown>) =>
    request(`/playbooks/${id}/dry-run`, { method: 'POST', body: JSON.stringify({ event_context: context }) }),
  getPlaybookHistory: (id: number) => request(`/playbooks/${id}/history`),

  // === Phase 7: Remediation ===
  executeRemediation: (data: { action_type: string; target: string; parameters?: Record<string, unknown>; incident_id?: number }) =>
    request('/remediation/execute', { method: 'POST', body: JSON.stringify(data) }),
  getRemediationActions: (params?: { limit?: number; offset?: number; status?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    if (params?.status) searchParams.set('status', params.status);
    const query = searchParams.toString();
    return request(`/remediation/actions${query ? '?' + query : ''}`);
  },
  getRemediationAction: (id: number) => request(`/remediation/actions/${id}`),
  rollbackRemediation: (id: number) => request(`/remediation/actions/${id}/rollback`, { method: 'POST' }),
  getQuarantine: () => request('/remediation/quarantine'),
  restoreQuarantine: (id: number) => request(`/remediation/quarantine/${id}/restore`, { method: 'POST' }),
  deleteQuarantine: (id: number) => request(`/remediation/quarantine/${id}`, { method: 'DELETE' }),

  // === Phase 8: Feeds ===
  getFeeds: () => request('/feeds/'),
  createFeed: (data: { name: string; feed_type: string; url?: string; api_key?: string; enabled?: boolean; poll_interval_seconds?: number }) =>
    request('/feeds/', { method: 'POST', body: JSON.stringify(data) }),
  getFeed: (id: number) => request(`/feeds/${id}`),
  updateFeed: (id: number, data: Record<string, unknown>) =>
    request(`/feeds/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteFeed: (id: number) => request(`/feeds/${id}`, { method: 'DELETE' }),
  pollFeed: (id: number) => request(`/feeds/${id}/poll`, { method: 'POST' }),
  getFeedStatus: (id: number) => request(`/feeds/${id}/status`),

  // === Phase 8: IOC ===
  getIocs: (params?: { ioc_type?: string; active?: boolean; source?: string; limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.ioc_type) searchParams.set('ioc_type', params.ioc_type);
    if (params?.active !== undefined) searchParams.set('active', String(params.active));
    if (params?.source) searchParams.set('source', params.source);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    const query = searchParams.toString();
    return request(`/ioc/${query ? '?' + query : ''}`);
  },
  searchIocs: (q: string) => request(`/ioc/search?q=${encodeURIComponent(q)}`),
  addIoc: (data: { ioc_type: string; value: string; source?: string; severity?: string; tags?: string[]; context?: Record<string, unknown> }) =>
    request('/ioc/', { method: 'POST', body: JSON.stringify(data) }),
  bulkImportIocs: (iocs: Array<{ ioc_type: string; value: string; source?: string; severity?: string }>) =>
    request('/ioc/bulk', { method: 'POST', body: JSON.stringify({ iocs }) }),
  checkIocs: (values: string[], ioc_type?: string) =>
    request('/ioc/check', { method: 'POST', body: JSON.stringify({ values, ioc_type }) }),
  getIocStats: () => request('/ioc/stats'),

  // === Phase 8: Notifications ===
  getNotificationChannels: () => request('/notifications/channels'),
  createNotificationChannel: (data: { name: string; channel_type: string; config: Record<string, unknown>; enabled?: boolean; events?: string[] }) =>
    request('/notifications/channels', { method: 'POST', body: JSON.stringify(data) }),
  updateNotificationChannel: (id: number, data: Record<string, unknown>) =>
    request(`/notifications/channels/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteNotificationChannel: (id: number) => request(`/notifications/channels/${id}`, { method: 'DELETE' }),
  testNotificationChannel: (id: number) => request(`/notifications/channels/${id}/test`, { method: 'POST' }),
  getEventTypes: () => request('/notifications/event-types'),

  // === Phase 8: Export ===
  requestExport: (data: { export_type: string; format: string; filters?: Record<string, unknown> }) =>
    request('/export/', { method: 'POST', body: JSON.stringify(data) }),
  getExportJobs: () => request('/export/'),
  getExportJob: (id: number) => request(`/export/${id}`),
  downloadExport: async (id: number) => {
    const response = await fetch(`${API_BASE}/export/${id}/download`, {
      credentials: 'include',
      headers: getHeaders(),
    });
    if (!response.ok) throw new Error('Download failed');
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `export-${id}`;
    a.click();
    URL.revokeObjectURL(url);
  },
  deleteExport: (id: number) => request(`/export/${id}`, { method: 'DELETE' }),

  // === Phase 9: Users & RBAC ===
  getUsers: () => request('/users/'),
  createUser: (data: { username: string; password: string; role?: string }) =>
    request('/users/', { method: 'POST', body: JSON.stringify(data) }),
  getUser: (id: number) => request(`/users/${id}`),
  updateUser: (id: number, data: Record<string, unknown>) =>
    request(`/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteUser: (id: number) => request(`/users/${id}`, { method: 'DELETE' }),
  assignUserRole: (userId: number, roleId: number) =>
    request(`/users/${userId}/roles`, { method: 'POST', body: JSON.stringify({ role_id: roleId }) }),
  removeUserRole: (userId: number, roleId: number) =>
    request(`/users/${userId}/roles/${roleId}`, { method: 'DELETE' }),
  getUserRoles: (userId: number) => request(`/users/${userId}/roles`),
  generateApiKey: (data: { name: string; permissions?: string[] }) =>
    request('/users/api-keys', { method: 'POST', body: JSON.stringify(data) }),
  getApiKeys: () => request('/users/api-keys'),
  revokeApiKey: (keyId: number) => request(`/users/api-keys/${keyId}`, { method: 'DELETE' }),
  getRoles: () => request('/users/roles'),

  // === Phase 9: Comments ===
  getComments: (targetType: string, targetId: number) => request(`/comments/${targetType}/${targetId}`),
  addComment: (targetType: string, targetId: number, content: string) =>
    request(`/comments/${targetType}/${targetId}`, { method: 'POST', body: JSON.stringify({ content }) }),
  updateComment: (id: number, content: string) =>
    request(`/comments/${id}`, { method: 'PUT', body: JSON.stringify({ content }) }),
  deleteComment: (id: number) => request(`/comments/${id}`, { method: 'DELETE' }),

  // === Phase 9: Layouts ===
  getLayouts: () => request('/layouts/'),
  createLayout: (data: { name: string; layout_json: unknown; is_default?: boolean }) =>
    request('/layouts/', { method: 'POST', body: JSON.stringify(data) }),
  getDefaultLayout: () => request('/layouts/default'),
  updateLayout: (id: number, data: Record<string, unknown>) =>
    request(`/layouts/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteLayout: (id: number) => request(`/layouts/${id}`, { method: 'DELETE' }),

  // === Phase 9: Maintenance ===
  triggerBackup: () => request('/maintenance/backup', { method: 'POST' }),
  listBackups: () => request('/maintenance/backups'),
  triggerCleanup: () => request('/maintenance/cleanup', { method: 'POST' }),
  getRetentionConfig: () => request('/maintenance/retention'),

  // === Phase 11: Event Log ===
  getEventLogEntries: (params?: { limit?: number; offset?: number; event_type?: string; severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    if (params?.event_type) searchParams.set('event_type', params.event_type);
    if (params?.severity) searchParams.set('severity', params.severity);
    const query = searchParams.toString();
    return request(`/event-log/${query ? '?' + query : ''}`);
  },
  getEventLogStats: () => request('/event-log/stats'),

  // === Phase 11: Detection Rules ===
  getDetectionRules: () => request('/detection-rules/'),
  getDetectionRuleMatches: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.offset) searchParams.set('offset', String(params.offset));
    const query = searchParams.toString();
    return request(`/detection-rules/matches${query ? '?' + query : ''}`);
  },
  getDetectionRuleStats: () => request('/detection-rules/stats'),

  // === Disk Sanitation ===
  getDiskAnalysis: () => request('/disk-cleanup/analysis'),
  cleanDisk: (categories: string[]) =>
    request('/disk-cleanup/clean', { method: 'POST', body: JSON.stringify({ categories }) }),
  getLargeFiles: (minSizeMb?: number, limit?: number) => {
    const searchParams = new URLSearchParams();
    if (minSizeMb) searchParams.set('min_size_mb', String(minSizeMb));
    if (limit) searchParams.set('limit', String(limit));
    const query = searchParams.toString();
    return request(`/disk-cleanup/large-files${query ? '?' + query : ''}`);
  },
  deleteFile: (path: string) =>
    request('/disk-cleanup/file', { method: 'DELETE', body: JSON.stringify({ path }) }),

  // === Phase 12: Ransomware Detection ===
  getRansomwareStatus: () => request('/ransomware/status'),
  getRansomwareCanaries: () => request('/ransomware/canaries'),
  getRansomwareDetections: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/ransomware/detections${query}`);
  },

  // === Phase 12: Commander Bond ===
  getBondStatus: () => request('/bond/status'),
  getBondReports: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/bond/reports${query}`);
  },
  getBondReport: (reportId: string) => request(`/bond/reports/${reportId}`),
  getBondLatest: () => request('/bond/latest'),
  triggerBondScan: () => request('/bond/scan', { method: 'POST' }),
  getBondThreats: (params?: { category?: string; severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.category) searchParams.set('category', params.category);
    if (params?.severity) searchParams.set('severity', params.severity);
    const query = searchParams.toString();
    return request(`/bond/threats${query ? '?' + query : ''}`);
  },
  neutralizeBondThreat: (threatId: string) =>
    request(`/bond/threats/${encodeURIComponent(threatId)}/neutralize`, { method: 'POST' }),
  neutralizeAllBondThreats: () =>
    request('/bond/threats/neutralize-all', { method: 'POST' }),

  // === Phase 14: Bond Intelligence + Guardian ===
  getBondIntelligence: () => request('/bond/intelligence'),
  markBondThreatIrrelevant: (threatId: string) =>
    request(`/bond/threats/${encodeURIComponent(threatId)}/irrelevant`, { method: 'POST' }),
  getBondCorrelations: () => request('/bond/correlations'),
  getGuardianStatus: () => request('/bond/guardian'),
  clearGuardianLockdown: () => request('/bond/guardian/clear', { method: 'POST' }),

  // === Phase 12: Network Beaconing ===
  getBeaconingDetections: () => request('/network/beaconing'),
  getConnectionHistory: (limit?: number) => {
    const query = limit ? `?limit=${limit}` : '';
    return request(`/network/connection-history${query}`);
  },

  // === Phase 13: IOC Lifecycle ===
  markIocFalsePositive: (id: number, reason?: string) =>
    request(`/ioc/${id}/false-positive`, { method: 'POST', body: JSON.stringify({ reason }) }),
  unmarkIocFalsePositive: (id: number) =>
    request(`/ioc/${id}/false-positive`, { method: 'DELETE' }),
  bulkDeactivateIocs: (data: { source?: string; ioc_type?: string; older_than_days?: number }) =>
    request('/ioc/bulk-deactivate', { method: 'POST', body: JSON.stringify(data) }),
  getExpiringIocs: (days?: number) => {
    const query = days ? `?days=${days}` : '';
    return request(`/ioc/expiring${query}`);
  },
  updateIocConfidence: (id: number, confidence: number) =>
    request(`/ioc/${id}/confidence`, { method: 'PATCH', body: JSON.stringify({ confidence }) }),

  // === Phase 13: Thresholds ===
  getThresholds: (category?: string) => {
    const query = category ? `/${category}` : '/';
    return request(`/thresholds${query}`);
  },
  updateThreshold: (key: string, value: number) =>
    request(`/thresholds/${key}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    }),

  // === Phase 13: Timeline & Correlation ===
  getThreatTimeline: (lookbackMinutes?: number) => {
    const query = lookbackMinutes ? `?lookback_minutes=${lookbackMinutes}` : '';
    return request(`/threats/timeline${query}`);
  },
  getEventChain: (eventType: string, lookbackMinutes?: number) => {
    const query = lookbackMinutes ? `?lookback_minutes=${lookbackMinutes}` : '';
    return request(`/threats/event-chain/${encodeURIComponent(eventType)}${query}`);
  },
  getPatternStats: () => request('/threats/pattern-stats'),
  linkAlertsToIncident: (incidentId: number, alertIds: number[]) =>
    request(`/incidents/${incidentId}/link-alerts`, {
      method: 'POST',
      body: JSON.stringify({ alert_ids: alertIds }),
    }),
  getLinkedAlerts: (incidentId: number) =>
    request(`/incidents/${incidentId}/linked-alerts`),

  // === Phase 15: YARA Q-Branch ===
  getYaraRules: () => request('/yara/rules'),
  createYaraRule: (data: { name: string; description?: string; rule_source: string; tags?: string[] }) =>
    request('/yara/rules', { method: 'POST', body: JSON.stringify(data) }),
  getYaraRule: (id: number) => request(`/yara/rules/${id}`),
  updateYaraRule: (id: number, data: Record<string, unknown>) =>
    request(`/yara/rules/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteYaraRule: (id: number) =>
    request(`/yara/rules/${id}`, { method: 'DELETE' }),
  compileYaraRules: () =>
    request('/yara/rules/compile', { method: 'POST' }),
  scanYaraFile: (path: string) =>
    request('/yara/scan/file', { method: 'POST', body: JSON.stringify({ path }) }),
  scanYaraDirectory: (path: string) =>
    request('/yara/scan/directory', { method: 'POST', body: JSON.stringify({ path }) }),
  scanYaraProcess: (pid: number) =>
    request(`/yara/scan/process/${pid}`, { method: 'POST' }),
  getYaraResults: (limit = 50, offset = 0) =>
    request(`/yara/results?limit=${limit}&offset=${offset}`),
  getYaraStats: () => request('/yara/stats'),

  // === Phase 15: Memory Scanner ===
  getMemoryStatus: () => request('/memory/status'),
  getMemoryResults: (limit = 50, offset = 0) =>
    request(`/memory/results?limit=${limit}&offset=${offset}`),
  triggerMemoryScan: () =>
    request('/memory/scan', { method: 'POST' }),
  scanProcessMemory: (pid: number) =>
    request(`/memory/scan/${pid}`, { method: 'POST' }),
  getProcessMemoryRegions: (pid: number) =>
    request(`/memory/scan/${pid}/regions`),

  // === Phase 15: Sword Protocol ===
  getSwordPolicies: () => request('/bond/sword/policies'),
  createSwordPolicy: (data: Record<string, unknown>) =>
    request('/bond/sword/policies', { method: 'POST', body: JSON.stringify(data) }),
  getSwordPolicy: (id: number) => request(`/bond/sword/policies/${id}`),
  updateSwordPolicy: (id: number, data: Record<string, unknown>) =>
    request(`/bond/sword/policies/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteSwordPolicy: (id: number) =>
    request(`/bond/sword/policies/${id}`, { method: 'DELETE' }),
  toggleSwordPolicy: (id: number) =>
    request(`/bond/sword/policies/${id}/toggle`, { method: 'PATCH' }),
  getSwordLogs: (limit = 50, offset = 0) =>
    request(`/bond/sword/logs?limit=${limit}&offset=${offset}`),
  getSwordStats: () => request('/bond/sword/stats'),
  enableSword: () =>
    request('/bond/sword/enable', { method: 'POST' }),
  disableSword: () =>
    request('/bond/sword/disable', { method: 'POST' }),
  swordLockout: () =>
    request('/bond/sword/lockout', { method: 'POST' }),
  swordClearLockout: () =>
    request('/bond/sword/clear', { method: 'POST' }),
  testSwordPolicy: (id: number, data?: Record<string, unknown>) =>
    request(`/bond/sword/test/${id}`, { method: 'POST', body: JSON.stringify(data || {}) }),

  // === Phase 15: Overwatch ===
  getOverwatchStatus: () => request('/bond/overwatch/status'),
  getOverwatchIntegrity: () => request('/bond/overwatch/integrity'),
  triggerOverwatchCheck: () =>
    request('/bond/overwatch/check', { method: 'POST' }),

  // === Command Console: Security Protocol ===
  getChecklistVerification: () => request('/checklists/verify'),
};
