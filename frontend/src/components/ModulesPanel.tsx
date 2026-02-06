import { useEffect, useState } from 'react';
import { api } from '../services/api';

interface Module {
  name: string;
  enabled: boolean;
  running: boolean;
  health_status: string;
  last_heartbeat: string | null;
}

export function ModulesPanel() {
  const [modules, setModules] = useState<Module[]>([]);

  const load = () => {
    api.getModules().then((d: unknown) => setModules(d as Module[])).catch(() => {});
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleToggle = async (name: string, enabled: boolean) => {
    try {
      await api.toggleModule(name, !enabled);
      load();
    } catch { /* ignore */ }
  };

  const healthColor = (status: string) => {
    const map: Record<string, string> = {
      running: 'var(--status-online)',
      starting: '#f59e0b',
      stopped: 'var(--text-muted)',
      error: 'var(--severity-critical)',
      initialized: 'var(--text-muted)',
    };
    return map[status] || 'var(--text-muted)';
  };

  return (
    <div>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '16px',
      }}>
        {modules.map((m) => (
          <div
            key={m.name}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: '8px',
              padding: '20px',
              opacity: m.enabled ? 1 : 0.6,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <div style={{
                fontSize: '13px',
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
                color: 'var(--text-primary)',
              }}>
                {m.name}
              </div>
              <button
                onClick={() => handleToggle(m.name, m.enabled)}
                style={{
                  padding: '4px 12px',
                  fontSize: '11px',
                  background: m.enabled ? 'rgba(34, 197, 94, 0.15)' : 'var(--bg-tertiary)',
                  color: m.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                  border: `1px solid ${m.enabled ? 'rgba(34, 197, 94, 0.3)' : 'var(--border-default)'}`,
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                {m.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <div style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: healthColor(m.health_status),
              }} />
              <span style={{ fontSize: '12px', color: healthColor(m.health_status) }}>
                {m.health_status}
              </span>
            </div>

            {m.last_heartbeat && (
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Last heartbeat: {new Date(m.last_heartbeat).toLocaleTimeString()}
              </div>
            )}
          </div>
        ))}
      </div>

      {modules.length === 0 && (
        <div style={{
          padding: '40px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
          fontSize: '13px',
        }}>
          No modules loaded
        </div>
      )}
    </div>
  );
}
