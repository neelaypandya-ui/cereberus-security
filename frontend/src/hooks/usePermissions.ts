import { useMemo } from 'react';

interface JwtPayload {
  sub: string;
  role: string;
  permissions?: string[];
  exp?: number;
}

function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    return payload as JwtPayload;
  } catch {
    return null;
  }
}

const ROLE_PERMISSIONS: Record<string, string[]> = {
  admin: [
    'view_dashboard', 'manage_alerts', 'manage_incidents', 'execute_remediation',
    'manage_playbooks', 'manage_users', 'manage_settings', 'view_audit',
    'export_data', 'manage_feeds', 'manage_ai', 'manage_notifications', 'add_comments',
  ],
  analyst: [
    'view_dashboard', 'manage_alerts', 'manage_incidents', 'execute_remediation',
    'view_audit', 'export_data', 'add_comments', 'manage_feeds',
  ],
  operator: ['view_dashboard', 'execute_remediation', 'add_comments'],
  viewer: ['view_dashboard'],
};

export function usePermissions() {
  const permissions = useMemo(() => {
    const token = localStorage.getItem('cereberus_token');
    if (!token) return [];

    const payload = decodeJwt(token);
    if (!payload) return [];

    // Use permissions from JWT if present, otherwise fall back to role mapping
    if (payload.permissions && payload.permissions.length > 0) {
      return payload.permissions;
    }

    return ROLE_PERMISSIONS[payload.role] || ROLE_PERMISSIONS['viewer'];
  }, []);

  const hasPermission = (perm: string): boolean => permissions.includes(perm);

  const hasAnyPermission = (...perms: string[]): boolean =>
    perms.some(p => permissions.includes(p));

  const role = useMemo(() => {
    const token = localStorage.getItem('cereberus_token');
    if (!token) return 'viewer';
    const payload = decodeJwt(token);
    return payload?.role || 'viewer';
  }, []);

  return { permissions, hasPermission, hasAnyPermission, role };
}
