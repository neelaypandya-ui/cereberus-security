import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

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

const MILITARY_LABELS: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

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
    <IntelCard title="THREAT BOARD" classification="SECRET" status={alerts.some((a) => !a.acknowledged && a.severity === 'critical') ? 'critical' : 'active'}>
      {/* Severity Filter Buttons */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {SEVERITY_LEVELS.map((level) => (
          <button
            key={level}
            onClick={() => setFilter(level)}
            style={{
              padding: '4px 12px',
              fontSize: '16px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '1px',
              textTransform: 'uppercase',
              background: filter === level ? (level === 'all' ? 'var(--red-dark)' : severityColor(level)) : 'var(--bg-tertiary)',
              color: filter === level ? '#fff' : 'var(--text-secondary)',
              border: `1px solid ${filter === level ? 'transparent' : 'var(--border-default)'}`,
              borderRadius: '2px',
              cursor: 'pointer',
            }}
          >
            {MILITARY_LABELS[level]?.label || 'ALL'}
          </button>
        ))}
      </div>

      {/* Bulk Acknowledge */}
      {alerts.some((a) => !a.acknowledged) && (
        <div style={{ marginBottom: '12px' }}>
          <button
            onClick={() => handleAcknowledge(alerts.filter((a) => !a.acknowledged).map((a) => a.id))}
            style={{
              padding: '5px 14px',
              fontSize: '16px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '1px',
              background: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-default)',
              borderRadius: '2px',
              cursor: 'pointer',
              textTransform: 'uppercase',
            }}
          >
            ACKNOWLEDGE ALL VISIBLE
          </button>
        </div>
      )}

      {/* Alert List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {alerts.length === 0 && (
          <div style={{
            padding: '40px',
            textAlign: 'center',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            fontSize: '17px',
            letterSpacing: '2px',
          }}>
            NO THREATS MATCHING FILTER
          </div>
        )}
        {alerts.map((a) => {
          const mil = MILITARY_LABELS[a.severity] || MILITARY_LABELS.info;
          return (
            <div
              key={a.id}
              className={!a.acknowledged ? 'alert-pulse' : ''}
              style={{
                background: 'var(--bg-tertiary)',
                border: `1px solid ${!a.acknowledged ? 'var(--amber-primary)' : 'var(--border-default)'}`,
                borderLeft: `3px solid ${severityColor(a.severity)}`,
                borderRadius: '2px',
                padding: '10px 14px',
                opacity: a.acknowledged ? 0.5 : 1,
              }}
            >
              <div
                style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
                onClick={() => setExpandedId(expandedId === a.id ? null : a.id)}
              >
                <span className={`stamp-badge ${mil.stampClass}`}>{mil.label}</span>
                <span style={{ fontSize: '18px', color: 'var(--text-primary)', flex: 1 }}>
                  {a.title}
                </span>
                <span style={{ fontSize: '16px', color: 'var(--cyan-primary)', fontFamily: 'var(--font-mono)' }}>
                  {a.module_source}
                </span>
                <span style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
                </span>
                {!a.acknowledged && (
                  <button
                    onClick={(e) => { e.stopPropagation(); handleAcknowledge([a.id]); }}
                    style={{
                      padding: '2px 8px',
                      fontSize: '15px',
                      fontFamily: 'var(--font-mono)',
                      letterSpacing: '1px',
                      background: 'var(--bg-elevated)',
                      color: 'var(--text-muted)',
                      border: '1px solid var(--border-default)',
                      borderRadius: '2px',
                      cursor: 'pointer',
                    }}
                  >
                    ACKNOWLEDGE
                  </button>
                )}
              </div>
              {expandedId === a.id && (
                <div style={{
                  marginTop: '10px',
                  paddingTop: '10px',
                  borderTop: '1px solid var(--border-default)',
                }}>
                  <div style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '15px',
                    letterSpacing: '2px',
                    color: 'var(--text-muted)',
                    marginBottom: '6px',
                  }}>
                    CLASSIFIED DETAILS
                  </div>
                  <div style={{
                    fontSize: '18px',
                    color: 'var(--text-secondary)',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 1.6,
                  }}>
                    {a.description}
                  </div>
                  {a.vpn_status && (
                    <div style={{ marginTop: '6px', fontSize: '17px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      VPN STATUS: {a.vpn_status}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </IntelCard>
  );
}
