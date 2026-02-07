import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface AuditLogEntry {
  id: number;
  timestamp: string;
  username: string | null;
  action: string;
  endpoint: string;
  target: string | null;
  details_json: string | null;
  ip_address: string | null;
  status_code: number | null;
}

const actionStamps: Record<string, { label: string; stampClass: string }> = {
  POST: { label: 'CREATE', stampClass: 'stamp-cleared' },
  PUT: { label: 'UPDATE', stampClass: 'stamp-priority' },
  DELETE: { label: 'DELETE', stampClass: 'stamp-hostile' },
  PATCH: { label: 'MODIFY', stampClass: 'stamp-advisory' },
};

export function AuditLogPanel() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [filterAction, setFilterAction] = useState<string>('');
  const [filterUser, setFilterUser] = useState<string>('');
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = () => {
    const params: { limit?: number; action?: string; username?: string } = { limit: 100 };
    if (filterAction) params.action = filterAction;
    if (filterUser) params.username = filterUser;
    api.getAuditLogs(params).then((d: unknown) => setLogs(d as AuditLogEntry[])).catch(() => {});
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, [filterAction, filterUser]);

  return (
    <IntelCard title="OPERATIONS LOG" classification="SECRET">
      {/* Filters */}
      <div style={{
        display: 'flex',
        gap: '10px',
        marginBottom: '14px',
        flexWrap: 'wrap',
        alignItems: 'center',
      }}>
        <select
          value={filterAction}
          onChange={(e) => setFilterAction(e.target.value)}
          style={{
            padding: '5px 10px',
            fontSize: '10px',
            fontFamily: 'var(--font-mono)',
            background: 'var(--bg-tertiary)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border-default)',
            borderRadius: '2px',
            letterSpacing: '1px',
          }}
        >
          <option value="">ALL ACTIONS</option>
          <option value="POST">CREATE (POST)</option>
          <option value="PUT">UPDATE (PUT)</option>
          <option value="DELETE">DELETE</option>
          <option value="PATCH">MODIFY (PATCH)</option>
        </select>
        <input
          type="text"
          placeholder="Filter by operator..."
          value={filterUser}
          onChange={(e) => setFilterUser(e.target.value)}
          className="terminal-input"
          style={{
            padding: '5px 10px',
            fontSize: '10px',
            borderRadius: '2px',
            width: '180px',
          }}
        />
        <div style={{ marginLeft: 'auto', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
          {logs.length} ENTRIES
        </div>
      </div>

      {/* CLASSIFIED ACTIVITY LEDGER */}
      <div style={{
        fontSize: '9px', fontFamily: 'var(--font-mono)',
        letterSpacing: '2px', color: 'var(--text-muted)', marginBottom: '8px',
      }}>
        CLASSIFIED ACTIVITY LEDGER
      </div>

      <div style={{
        border: '1px solid var(--border-default)',
        borderRadius: '2px',
        overflow: 'auto',
        maxHeight: 'calc(100vh - 340px)',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-default)', position: 'sticky', top: 0, background: 'var(--bg-secondary)' }}>
              <th style={thStyle}>LOG#</th>
              <th style={thStyle}>TIMESTAMP</th>
              <th style={thStyle}>OPERATOR</th>
              <th style={thStyle}>ACTION</th>
              <th style={thStyle}>ENDPOINT</th>
              <th style={thStyle}>STATUS</th>
              <th style={thStyle}>IP</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log, idx) => (
              <tr
                key={log.id}
                onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                style={{
                  borderBottom: '1px solid var(--border-default)',
                  cursor: 'pointer',
                  background: expanded === log.id ? 'var(--bg-hover)' : 'transparent',
                }}
              >
                <td style={{ ...tdStyle, color: 'var(--text-muted)' }}>
                  {String(idx + 1).padStart(4, '0')}
                </td>
                <td style={tdStyle}>
                  {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
                </td>
                <td style={tdStyle}>{log.username || '--'}</td>
                <td style={tdStyle}>
                  {actionStamps[log.action] ? (
                    <span className={`stamp-badge ${actionStamps[log.action].stampClass}`}>
                      {actionStamps[log.action].label}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>{log.action}</span>
                  )}
                </td>
                <td style={tdStyle}>{log.endpoint}</td>
                <td style={tdStyle}>
                  <span style={{
                    color: log.status_code && log.status_code < 400 ? 'var(--status-online)' : 'var(--severity-critical)',
                  }}>
                    {log.status_code || '--'}
                  </span>
                </td>
                <td style={tdStyle}>{log.ip_address || '--'}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', letterSpacing: '2px' }}>
                  NO AUDIT RECORDS
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Expanded details */}
      {expanded && (() => {
        const log = logs.find((l) => l.id === expanded);
        if (!log?.details_json) return null;
        return (
          <div style={{
            marginTop: '12px',
            padding: '14px',
            background: 'var(--bg-tertiary)',
            border: '1px solid var(--border-default)',
            borderRadius: '2px',
          }}>
            <div style={{
              fontSize: '9px', fontFamily: 'var(--font-mono)',
              letterSpacing: '2px', color: 'var(--text-muted)', marginBottom: '8px',
            }}>
              FULL OPERATIONAL REPORT
            </div>
            <pre style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
              {log.details_json}
            </pre>
          </div>
        );
      })()}
    </IntelCard>
  );
}

const thStyle: React.CSSProperties = {
  padding: '8px 10px',
  textAlign: 'left',
  fontSize: '9px',
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-muted)',
  letterSpacing: '1px',
  fontWeight: 600,
};

const tdStyle: React.CSSProperties = {
  padding: '6px 10px',
  color: 'var(--text-secondary)',
};
