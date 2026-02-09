import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

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
    api.getModules().then((d: unknown) => setModules(d as Module[])).catch((err) => console.error('[CEREBERUS]', err));
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
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const healthColor = (status: string) => {
    const map: Record<string, string> = {
      running: 'var(--status-online)',
      starting: 'var(--amber-primary)',
      stopped: 'var(--text-muted)',
      error: 'var(--severity-critical)',
      initialized: 'var(--text-muted)',
    };
    return map[status] || 'var(--text-muted)';
  };

  return (
    <IntelCard title="OPERATIONS BOARD" classification="UNCLASSIFIED">
      <div className="schematic-bg" style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '12px',
        padding: '8px',
        borderRadius: '2px',
      }}>
        {modules.map((m) => (
          <div
            key={m.name}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: '2px',
              padding: '16px',
              opacity: m.enabled ? 1 : 0.5,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <div style={{
                fontSize: '17px',
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
                letterSpacing: '1px',
                color: 'var(--text-primary)',
              }}>
                {m.name.toUpperCase().replace(/_/g, ' ')}
              </div>
              <button
                onClick={() => handleToggle(m.name, m.enabled)}
                style={{
                  padding: '4px 12px',
                  fontSize: '15px',
                  fontFamily: 'var(--font-mono)',
                  letterSpacing: '1px',
                  background: m.enabled ? 'rgba(34, 197, 94, 0.1)' : 'var(--bg-tertiary)',
                  color: m.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                  border: `1px solid ${m.enabled ? 'rgba(34, 197, 94, 0.3)' : 'var(--border-default)'}`,
                  borderRadius: '2px',
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                {m.enabled ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              {/* Power LED */}
              <div
                className={m.health_status === 'running' ? 'status-dot-glow' : ''}
                style={{
                  width: '12px',
                  height: '12px',
                  borderRadius: '50%',
                  background: healthColor(m.health_status),
                  boxShadow: m.health_status === 'running' ? `0 0 8px ${healthColor(m.health_status)}` : 'none',
                  color: healthColor(m.health_status),
                }}
              />
              <span style={{
                fontSize: '17px',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '1px',
                color: healthColor(m.health_status),
              }}>
                {m.health_status === 'running' ? 'STATION ONLINE' : `STATION ${m.health_status.toUpperCase()}`}
              </span>
            </div>

            {m.last_heartbeat && (
              <div style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
                HEARTBEAT: {new Date(m.last_heartbeat).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
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
          fontSize: '17px',
          letterSpacing: '2px',
        }}>
          NO MODULES LOADED
        </div>
      )}
    </IntelCard>
  );
}
