import { useEffect, useState } from 'react';
import { api } from '../services/api';

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

  return (
    <div>
      {/* Stats Bar */}
      {stats && (
        <div style={{
          display: 'flex',
          gap: '16px',
          flexWrap: 'wrap',
          marginBottom: '20px',
          padding: '16px',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
        }}>
          <MiniStat label="Total" value={stats.total} />
          <MiniStat label="Established" value={stats.established} />
          <MiniStat label="Listening" value={stats.listening} />
          <MiniStat label="TCP" value={stats.tcp} />
          <MiniStat label="UDP" value={stats.udp} />
          <MiniStat label="Suspicious" value={stats.suspicious} color="var(--severity-critical)" />
          {stats.last_scan && (
            <div style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', alignSelf: 'center' }}>
              Last scan: {new Date(stats.last_scan).toLocaleTimeString()}
            </div>
          )}
        </div>
      )}

      {/* Filter Toggle */}
      <div style={{ marginBottom: '16px', display: 'flex', gap: '8px' }}>
        <button
          onClick={() => setShowFlaggedOnly(false)}
          style={{
            padding: '6px 14px',
            fontSize: '12px',
            background: !showFlaggedOnly ? 'var(--red-primary)' : 'var(--bg-tertiary)',
            color: !showFlaggedOnly ? '#fff' : 'var(--text-secondary)',
            border: '1px solid var(--border-default)',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          All
        </button>
        <button
          onClick={() => setShowFlaggedOnly(true)}
          style={{
            padding: '6px 14px',
            fontSize: '12px',
            background: showFlaggedOnly ? 'var(--red-primary)' : 'var(--bg-tertiary)',
            color: showFlaggedOnly ? '#fff' : 'var(--text-secondary)',
            border: '1px solid var(--border-default)',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          Flagged Only
        </button>
      </div>

      {/* Connections Table */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        overflow: 'auto',
        maxHeight: 'calc(100vh - 340px)',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-default)', position: 'sticky', top: 0, background: 'var(--bg-secondary)' }}>
              <Th>Proto</Th>
              <Th>Local Address</Th>
              <Th>Remote Address</Th>
              <Th>Status</Th>
              <Th>PID</Th>
              <Th>Flag</Th>
            </tr>
          </thead>
          <tbody>
            {connections.map((c, i) => (
              <tr
                key={i}
                style={{
                  borderBottom: '1px solid var(--border-default)',
                  background: c.suspicious ? 'rgba(239, 68, 68, 0.08)' : 'transparent',
                }}
              >
                <Td>{c.protocol.toUpperCase()}</Td>
                <Td>{c.local_addr}:{c.local_port ?? '*'}</Td>
                <Td>{c.remote_addr ? `${c.remote_addr}:${c.remote_port ?? '*'}` : '--'}</Td>
                <Td>{c.status}</Td>
                <Td>{c.pid ?? '--'}</Td>
                <Td>
                  {c.suspicious && (
                    <span style={{ color: 'var(--severity-critical)', fontWeight: 700 }}>!</span>
                  )}
                </Td>
              </tr>
            ))}
            {connections.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No connections
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MiniStat({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.5px', marginBottom: '2px' }}>
        {label.toUpperCase()}
      </div>
      <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: color || 'var(--text-primary)' }}>
        {value}
      </div>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th style={{
      padding: '10px 12px',
      textAlign: 'left',
      fontSize: '10px',
      color: 'var(--text-muted)',
      letterSpacing: '0.5px',
      fontWeight: 600,
    }}>
      {children}
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return (
    <td style={{
      padding: '8px 12px',
      color: 'var(--text-secondary)',
    }}>
      {children}
    </td>
  );
}
