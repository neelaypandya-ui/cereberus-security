import { useEffect, useState } from 'react';
import { api } from '../services/api';

interface OverviewPanelProps {
  alerts: Record<string, number>;
  eventsToday: number;
  modules: Array<{ name: string; enabled: boolean; health: string }>;
  networkStats: {
    total: number;
    established: number;
    suspicious: number;
  } | null;
}

export function OverviewPanel({ alerts, eventsToday, modules, networkStats }: OverviewPanelProps) {
  const alertTotal = Object.values(alerts).reduce((a, b) => a + b, 0);
  const [recentAlerts, setRecentAlerts] = useState<Array<{
    id: number; severity: string; title: string; timestamp: string; module_source: string;
  }>>([]);

  useEffect(() => {
    api.getAlerts({ limit: 5 }).then((data: unknown) => {
      setRecentAlerts(data as typeof recentAlerts);
    }).catch(() => {});
  }, []);

  const severityColor = (s: string) => {
    const map: Record<string, string> = {
      critical: 'var(--severity-critical)',
      high: 'var(--severity-high)',
      medium: 'var(--severity-medium, #f59e0b)',
      low: 'var(--severity-low, #3b82f6)',
      info: 'var(--severity-info)',
    };
    return map[s] || 'var(--text-muted)';
  };

  return (
    <div>
      {/* Stat Cards Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
        <StatCard label="Unacked Alerts" value={alertTotal} color="var(--red-primary)" />
        <StatCard label="Critical" value={alerts.critical ?? 0} color="var(--severity-critical)" />
        <StatCard label="High" value={alerts.high ?? 0} color="var(--severity-high)" />
        <StatCard label="Events Today" value={eventsToday} color="var(--severity-info)" />
        {networkStats && (
          <>
            <StatCard label="Connections" value={networkStats.total} color="var(--text-primary)" />
            <StatCard label="Suspicious" value={networkStats.suspicious} color="var(--severity-critical)" />
          </>
        )}
      </div>

      {/* Module Status Grid */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        padding: '20px',
        marginTop: '20px',
      }}>
        <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
          ACTIVE MODULES
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
          {modules.map((m) => (
            <div key={m.name} style={{
              padding: '12px',
              background: 'var(--bg-tertiary)',
              borderRadius: '6px',
              border: '1px solid var(--border-default)',
            }}>
              <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                {m.name}
              </div>
              <div style={{
                fontSize: '11px',
                marginTop: '4px',
                color: m.health === 'running' ? 'var(--status-online)' : 'var(--text-muted)',
              }}>
                {m.enabled ? m.health : 'disabled'}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Alerts */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        padding: '20px',
        marginTop: '20px',
      }}>
        <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
          RECENT ALERTS
        </h3>
        {recentAlerts.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
            No recent alerts
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {recentAlerts.map((a, i) => (
              <div key={i} style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '8px 12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '6px',
                borderLeft: `3px solid ${severityColor(a.severity)}`,
              }}>
                <span style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  color: severityColor(a.severity),
                  textTransform: 'uppercase',
                  minWidth: '60px',
                }}>
                  {a.severity}
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-primary)', flex: 1 }}>
                  {a.title}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {a.module_source}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-default)',
      borderRadius: '8px',
      padding: '20px',
    }}>
      <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
        {label.toUpperCase()}
      </div>
      <div style={{ fontSize: '28px', fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>
        {value}
      </div>
    </div>
  );
}
