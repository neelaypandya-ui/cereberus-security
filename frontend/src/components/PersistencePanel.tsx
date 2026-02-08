import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface PersistenceEntry {
  source: string;
  source_label: string;
  path: string;
  name: string;
  value: string;
  status?: string;
  old_value?: string;
}

const STATUS_LABELS: Record<string, { label: string; stampClass: string }> = {
  added: { label: 'NEW CONTACT', stampClass: 'stamp-hostile' },
  removed: { label: 'CONTACT LOST', stampClass: 'stamp-cleared' },
  changed: { label: 'STATUS CHANGE', stampClass: 'stamp-priority' },
};

export function PersistencePanel() {
  const [entries, setEntries] = useState<PersistenceEntry[]>([]);
  const [changes, setChanges] = useState<PersistenceEntry[]>([]);
  const [scanning, setScanning] = useState(false);
  const [tab, setTab] = useState<'entries' | 'changes'>('entries');

  const load = () => {
    api.getPersistenceEntries().then((d: unknown) => setEntries(d as PersistenceEntry[])).catch(() => {});
    api.getPersistenceChanges().then((d: unknown) => setChanges(d as PersistenceEntry[])).catch(() => {});
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      await api.triggerPersistenceScan();
      load();
    } catch { /* */ }
    setScanning(false);
  };

  const sourceIcon = (source: string) => {
    // Tactical SVG symbols
    if (source === 'registry') return (
      <svg width="12" height="12" viewBox="0 0 12 12" style={{ verticalAlign: 'middle' }}>
        <rect x="1" y="1" width="10" height="10" rx="1" fill="none" stroke="var(--cyan-primary)" strokeWidth="1" />
        <line x1="4" y1="3" x2="4" y2="9" stroke="var(--cyan-primary)" strokeWidth="0.8" />
        <line x1="4" y1="6" x2="9" y2="6" stroke="var(--cyan-primary)" strokeWidth="0.8" />
      </svg>
    );
    if (source === 'startup_folder') return (
      <svg width="12" height="12" viewBox="0 0 12 12" style={{ verticalAlign: 'middle' }}>
        <path d="M1 3 L6 1 L11 3 L11 9 L6 11 L1 9 Z" fill="none" stroke="var(--amber-primary)" strokeWidth="1" />
      </svg>
    );
    if (source === 'scheduled_task') return (
      <svg width="12" height="12" viewBox="0 0 12 12" style={{ verticalAlign: 'middle' }}>
        <circle cx="6" cy="6" r="5" fill="none" stroke="var(--severity-medium)" strokeWidth="1" />
        <line x1="6" y1="3" x2="6" y2="6" stroke="var(--severity-medium)" strokeWidth="1" />
        <line x1="6" y1="6" x2="9" y2="6" stroke="var(--severity-medium)" strokeWidth="1" />
      </svg>
    );
    return <span style={{ color: 'var(--text-muted)' }}>{'\u2022'}</span>;
  };

  const renderTable = (items: PersistenceEntry[], showStatus: boolean) => (
    <div style={{
      border: '1px solid var(--border-default)',
      borderRadius: '2px',
      overflow: 'auto',
      maxHeight: 'calc(100vh - 320px)',
    }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '17px', fontFamily: 'var(--font-mono)' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-default)', position: 'sticky', top: 0, background: 'var(--bg-secondary)' }}>
            <th style={thStyle}>SOURCE</th>
            <th style={thStyle}>NAME</th>
            <th style={thStyle}>PATH / VALUE</th>
            {showStatus && <th style={thStyle}>STATUS</th>}
          </tr>
        </thead>
        <tbody>
          {items.map((e, i) => (
            <tr key={i} style={{
              borderBottom: '1px solid var(--border-default)',
              background: e.status === 'added' ? 'rgba(255, 23, 68, 0.06)' : e.status === 'removed' ? 'rgba(76, 175, 80, 0.06)' : 'transparent',
            }}>
              <td style={tdStyle}>
                <span style={{ marginRight: '6px', display: 'inline-flex', alignItems: 'center' }}>{sourceIcon(e.source)}</span>
                {e.source_label}
              </td>
              <td style={tdStyle}>{e.name}</td>
              <td style={{ ...tdStyle, maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {e.value}
              </td>
              {showStatus && (
                <td style={tdStyle}>
                  {e.status && STATUS_LABELS[e.status] ? (
                    <span className={`stamp-badge ${STATUS_LABELS[e.status].stampClass}`}>
                      {STATUS_LABELS[e.status].label}
                    </span>
                  ) : (
                    <span style={{ fontSize: '16px', color: 'var(--text-muted)' }}>BASELINE</span>
                  )}
                </td>
              )}
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={showStatus ? 4 : 3} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', letterSpacing: '2px', fontSize: '17px' }}>
                NO ENTRIES FOUND
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );

  return (
    <IntelCard title="WATCHLIST" classification="SECRET">
      {/* Tabs + Scan */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <div style={{ display: 'flex', gap: '6px' }}>
          <button onClick={() => setTab('entries')} style={tabBtnStyle(tab === 'entries')}>
            MONITORED SUBJECTS ({entries.length})
          </button>
          <button onClick={() => setTab('changes')} style={tabBtnStyle(tab === 'changes')}>
            WATCHLIST ALERTS ({changes.length})
          </button>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          style={{
            padding: '5px 14px',
            fontSize: '16px',
            fontFamily: 'var(--font-mono)',
            letterSpacing: '1px',
            background: scanning ? 'var(--bg-tertiary)' : 'var(--cyan-dark)',
            color: scanning ? 'var(--text-muted)' : '#fff',
            border: 'none',
            borderRadius: '2px',
            cursor: scanning ? 'wait' : 'pointer',
            opacity: scanning ? 0.6 : 1,
          }}
        >
          {scanning ? 'SCANNING...' : 'SCAN NOW'}
        </button>
      </div>

      {/* New subject detected banner */}
      {tab === 'changes' && changes.some((c) => c.status === 'added') && (
        <div className="critical-pulse" style={{
          padding: '8px 14px',
          background: 'rgba(255, 23, 68, 0.06)',
          border: '1px solid var(--severity-critical)',
          borderRadius: '2px',
          marginBottom: '10px',
          fontSize: '16px',
          fontFamily: 'var(--font-mono)',
          letterSpacing: '2px',
          color: 'var(--severity-critical)',
        }}>
          NEW SUBJECT DETECTED
        </div>
      )}

      {tab === 'entries' && renderTable(entries, false)}
      {tab === 'changes' && renderTable(changes, true)}
    </IntelCard>
  );
}

const thStyle: React.CSSProperties = {
  padding: '8px 10px',
  textAlign: 'left',
  fontSize: '15px',
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-muted)',
  letterSpacing: '1px',
  fontWeight: 600,
};

const tdStyle: React.CSSProperties = {
  padding: '6px 10px',
  color: 'var(--text-secondary)',
};

function tabBtnStyle(active: boolean): React.CSSProperties {
  return {
    padding: '5px 12px',
    fontSize: '16px',
    fontFamily: 'var(--font-mono)',
    letterSpacing: '1px',
    background: active ? 'var(--red-dark)' : 'var(--bg-tertiary)',
    color: active ? '#fff' : 'var(--text-secondary)',
    border: `1px solid ${active ? 'var(--red-primary)' : 'var(--border-default)'}`,
    borderRadius: '2px',
    cursor: 'pointer',
    textTransform: 'uppercase' as const,
  };
}
