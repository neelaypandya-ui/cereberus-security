import { useEffect, useState } from 'react';
import { api } from '../services/api';

interface Alert {
  id: number;
  timestamp: string;
  severity: string;
  module_source: string;
  title: string;
  description: string;
  vpn_status: string | null;
  acknowledged: boolean;
}

const SEVERITY_LEVELS = ['all', 'critical', 'high', 'medium', 'low', 'info'];

export function AlertsPanel() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const load = () => {
    const params: { limit?: number; severity?: string; unacknowledged_only?: boolean } = { limit: 100 };
    if (filter !== 'all') params.severity = filter;
    api.getAlerts(params).then((d: unknown) => setAlerts(d as Alert[])).catch(() => {});
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [filter]);

  const handleAcknowledge = async (ids: number[]) => {
    try {
      await api.acknowledgeAlerts(ids);
      load();
    } catch { /* ignore */ }
  };

  const severityColor = (s: string) => {
    const map: Record<string, string> = {
      critical: 'var(--severity-critical)',
      high: 'var(--severity-high)',
      medium: '#f59e0b',
      low: '#3b82f6',
      info: 'var(--severity-info)',
    };
    return map[s] || 'var(--text-muted)';
  };

  return (
    <div>
      {/* Severity Filter Buttons */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '20px', flexWrap: 'wrap' }}>
        {SEVERITY_LEVELS.map((level) => (
          <button
            key={level}
            onClick={() => setFilter(level)}
            style={{
              padding: '6px 14px',
              fontSize: '11px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              background: filter === level ? (level === 'all' ? 'var(--red-primary)' : severityColor(level)) : 'var(--bg-tertiary)',
              color: filter === level ? '#fff' : 'var(--text-secondary)',
              border: '1px solid var(--border-default)',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            {level}
          </button>
        ))}
      </div>

      {/* Bulk Acknowledge */}
      {alerts.some((a) => !a.acknowledged) && (
        <div style={{ marginBottom: '16px' }}>
          <button
            onClick={() => handleAcknowledge(alerts.filter((a) => !a.acknowledged).map((a) => a.id))}
            style={{
              padding: '6px 14px',
              fontSize: '12px',
              background: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-default)',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            Acknowledge All Visible
          </button>
        </div>
      )}

      {/* Alert List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {alerts.length === 0 && (
          <div style={{
            padding: '40px',
            textAlign: 'center',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
          }}>
            No alerts matching filter
          </div>
        )}
        {alerts.map((a) => (
          <div
            key={a.id}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderLeft: `3px solid ${severityColor(a.severity)}`,
              borderRadius: '6px',
              padding: '12px 16px',
              opacity: a.acknowledged ? 0.6 : 1,
            }}
          >
            <div
              style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
              onClick={() => setExpandedId(expandedId === a.id ? null : a.id)}
            >
              <span style={{
                fontSize: '10px',
                fontWeight: 700,
                color: severityColor(a.severity),
                textTransform: 'uppercase',
                minWidth: '60px',
              }}>
                {a.severity}
              </span>
              <span style={{ fontSize: '13px', color: 'var(--text-primary)', flex: 1 }}>
                {a.title}
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {a.module_source}
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {new Date(a.timestamp).toLocaleString()}
              </span>
              {!a.acknowledged && (
                <button
                  onClick={(e) => { e.stopPropagation(); handleAcknowledge([a.id]); }}
                  style={{
                    padding: '2px 8px',
                    fontSize: '10px',
                    background: 'var(--bg-tertiary)',
                    color: 'var(--text-muted)',
                    border: '1px solid var(--border-default)',
                    borderRadius: '3px',
                    cursor: 'pointer',
                  }}
                >
                  ACK
                </button>
              )}
            </div>
            {expandedId === a.id && (
              <div style={{
                marginTop: '10px',
                paddingTop: '10px',
                borderTop: '1px solid var(--border-default)',
                fontSize: '12px',
                color: 'var(--text-secondary)',
                fontFamily: 'var(--font-mono)',
                lineHeight: 1.6,
              }}>
                {a.description}
                {a.vpn_status && (
                  <div style={{ marginTop: '6px', color: 'var(--text-muted)' }}>
                    VPN: {a.vpn_status}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
