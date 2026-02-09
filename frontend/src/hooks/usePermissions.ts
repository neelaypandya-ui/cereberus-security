import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';

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
  const [permissions, setPermissions] = useState<string[]>([]);
  const [role, setRole] = useState<string>('viewer');

  useEffect(() => {
    api.getMe()
      .then((data: { sub: string; role: string; permissions?: string[] }) => {
        const userRole = data.role || 'viewer';
        setRole(userRole);
        if (data.permissions && data.permissions.length > 0) {
          setPermissions(data.permissions);
        } else {
          setPermissions(ROLE_PERMISSIONS[userRole] || ROLE_PERMISSIONS['viewer']);
        }
      })
      .catch(() => {
        setRole('viewer');
        setPermissions(ROLE_PERMISSIONS['viewer']);
      });
  }, []);

  const hasPermission = useCallback((perm: string): boolean => permissions.includes(perm), [permissions]);

  const hasAnyPermission = useCallback((...perms: string[]): boolean =>
    perms.some(p => permissions.includes(p)), [permissions]);

  return { permissions, hasPermission, hasAnyPermission, role };
}
