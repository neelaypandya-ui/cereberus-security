import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface Connection {
  local_addr: string;
  local_port: number | null;
  remote_addr: string;
  remote_port: number | null;
  protocol: string;
  status: string;
  pid: number | null;
  suspicious: boolean;
}

interface Stats {
  total: number;
  established: number;
  listening: number;
  time_wait: number;
  close_wait: number;
  suspicious: number;
  tcp: number;
  udp: number;
  last_scan: string | null;
}

export function NetworkPanel() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [showFlaggedOnly, setShowFlaggedOnly] = useState(false);

  const load = () => {
    if (showFlaggedOnly) {
      api.getFlaggedConnections().then((d: unknown) => setConnections(d as Connection[])).catch(() => {});
    } else {
      api.getConnections().then((d: unknown) => setConnections(d as Connection[])).catch(() => {});
    }
    api.getNetworkStats().then((d: unknown) => setStats(d as Stats)).catch(() => {});
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [showFlaggedOnly]);

  const lastScanUtc = stats?.last_scan
    ? new Date(stats.last_scan).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })
    : '--:--:--';

  return (
    <IntelCard title="SIGNALS INTELLIGENCE" classification="TOP SECRET//SI" status={stats && stats.suspicious > 0 ? 'warning' : 'active'}>
      {/* Instrument Readouts Bar */}
      {stats && (
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
          <Readout label="TOTAL" value={stats.total} />
          <Readout label="ESTAB" value={stats.established} />
          <Readout label="LISTEN" value={stats.listening} />
          <Readout label="TCP" value={stats.tcp} />
          <Readout label="UDP" value={stats.udp} />
          <Readout label="FLAGGED" value={stats.suspicious} color="var(--severity-critical)" />
          <div style={{
            marginLeft: 'auto',
            display: 'flex',
            alignItems: 'center',
            fontFamily: 'var(--font-mono)',
            fontSize: '10px',
            color: 'var(--text-muted)',
            letterSpacing: '1px',
          }}>
            LAST SWEEP: {lastScanUtc} UTC
          </div>
        </div>
      )}

      {/* Filter Toggle */}
      <div style={{ marginBottom: '12px', display: 'flex', gap: '8px' }}>
        <button
          onClick={() => setShowFlaggedOnly(false)}
          style={filterBtnStyle(!showFlaggedOnly)}
        >
          ALL INTERCEPTS
        </button>
        <button
          onClick={() => setShowFlaggedOnly(true)}
          style={filterBtnStyle(showFlaggedOnly)}
        >
          FLAGGED ONLY
        </button>
      </div>

      {/* INTERCEPT LOG Header */}
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '9px',
        letterSpacing: '2px',
        color: 'var(--text-muted)',
        marginBottom: '8px',
      }}>
        INTERCEPT LOG — {connections.length} RECORDS
      </div>

      {/* Connections Table */}
      <div style={{
        border: '1px solid var(--border-default)',
        borderRadius: '2px',
        overflow: 'auto',
        maxHeight: 'calc(100vh - 400px)',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-default)', position: 'sticky', top: 0, background: 'var(--bg-secondary)' }}>
              <Th>PROTO</Th>
              <Th>LOCAL ADDRESS</Th>
              <Th>REMOTE ADDRESS</Th>
              <Th>STATUS</Th>
              <Th>PID</Th>
              <Th>FLAG</Th>
            </tr>
          </thead>
          <tbody>
            {connections.map((c, i) => (
              <tr
                key={i}
                className={c.suspicious ? 'alert-pulse' : ''}
                style={{
                  borderBottom: '1px solid var(--border-default)',
                  borderLeft: c.suspicious ? '3px solid var(--severity-critical)' : '3px solid transparent',
                  background: c.suspicious ? 'rgba(239, 68, 68, 0.06)' : 'transparent',
                }}
              >
                <Td>{c.protocol.toUpperCase()}</Td>
                <Td>{c.local_addr}:{c.local_port ?? '*'}</Td>
                <Td>{c.remote_addr ? `${c.remote_addr}:${c.remote_port ?? '*'}` : '--'}</Td>
                <Td>{c.status}</Td>
                <Td>{c.pid ?? '--'}</Td>
                <Td>
                  {c.suspicious && (
                    <span className="stamp-badge stamp-hostile">FLAGGED</span>
                  )}
                </Td>
              </tr>
            ))}
            {connections.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  No intercepts
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </IntelCard>
  );
}

function Readout({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="instrument-readout">
      <span className="readout-label">{label}</span>
      <span className="readout-value" style={{ color: color || 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th style={{
      padding: '8px 10px',
      textAlign: 'left',
      fontSize: '9px',
      color: 'var(--text-muted)',
      letterSpacing: '1px',
      fontWeight: 600,
      textTransform: 'uppercase',
    }}>
      {children}
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return (
    <td style={{ padding: '6px 10px', color: 'var(--text-secondary)' }}>
      {children}
    </td>
  );
}

function filterBtnStyle(active: boolean): React.CSSProperties {
  return {
    padding: '5px 12px',
    fontSize: '10px',
    fontFamily: 'var(--font-mono)',
    letterSpacing: '1px',
    background: active ? 'var(--red-dark)' : 'var(--bg-tertiary)',
    color: active ? '#fff' : 'var(--text-secondary)',
    border: `1px solid ${active ? 'var(--red-primary)' : 'var(--border-default)'}`,
    borderRadius: '2px',
    cursor: 'pointer',
    textTransform: 'uppercase',
  };
}
