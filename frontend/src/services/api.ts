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
};
