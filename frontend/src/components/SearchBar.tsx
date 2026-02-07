import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../services/api';

interface SearchResult {
  query: string;
  results: {
    alerts: Array<{ id: number; severity: string; title: string; module_source: string; timestamp: string }>;
    processes: Array<{ name: string; pid: number; exe: string }>;
    connections: Array<{ remote_addr: string; remote_port: number; status: string; protocol: string }>;
    vulnerabilities: Array<{ title: string; severity: string; category: string }>;
  };
  total_count: number;
}

interface SearchBarProps {
  onNavigate: (panel: string) => void;
}

export function SearchBar({ onNavigate }: SearchBarProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult | null>(null);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<number | null>(null);

  const doSearch = useCallback((q: string) => {
    if (q.length < 2) {
      setResults(null);
      setOpen(false);
      return;
    }
    api.search(q, 10).then((d: unknown) => {
      setResults(d as SearchResult);
      setOpen(true);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = window.setTimeout(() => doSearch(query), 300);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [query, doSearch]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setOpen(false);
      setQuery('');
    }
  };

  const navigateTo = (panel: string) => {
    onNavigate(panel);
    setOpen(false);
    setQuery('');
  };

  const severityColor = (s: string) => {
    const map: Record<string, string> = {
      critical: '#ff1744', high: '#ff5722', medium: '#ff9800', low: '#ffc107', info: '#2196f3',
    };
    return map[s] || '#666';
  };

  const r = results?.results;

  return (
    <div ref={ref} style={{ position: 'relative', width: '280px' }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        background: 'var(--bg-tertiary)',
        border: '1px solid var(--border-default)',
        borderRadius: '6px',
        padding: '4px 10px',
      }}>
        <span style={{ color: 'var(--text-muted)', fontSize: '14px' }}>{'\u{1F50D}'}</span>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => { if (results && query.length >= 2) setOpen(true); }}
          placeholder="Search alerts, processes, IPs..."
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: 'var(--text-primary)',
            fontSize: '12px',
            fontFamily: 'var(--font-sans)',
          }}
        />
      </div>

      {open && r && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: 0,
          right: 0,
          marginTop: '4px',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          zIndex: 10001,
          maxHeight: '400px',
          overflow: 'auto',
        }}>
          {results.total_count === 0 ? (
            <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              No results found
            </div>
          ) : (
            <>
              {/* Alerts */}
              {r.alerts.length > 0 && (
                <div>
                  <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '1px', borderBottom: '1px solid var(--border-default)' }}>
                    ALERTS ({r.alerts.length})
                  </div>
                  {r.alerts.map((a) => (
                    <div key={a.id} onClick={() => navigateTo('alerts')} style={{
                      padding: '8px 12px',
                      cursor: 'pointer',
                      borderBottom: '1px solid var(--border-default)',
                    }}>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span style={{ fontSize: '10px', fontWeight: 700, color: severityColor(a.severity), textTransform: 'uppercase' }}>{a.severity}</span>
                        <span style={{ fontSize: '12px', color: 'var(--text-primary)' }}>{a.title}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Processes */}
              {r.processes.length > 0 && (
                <div>
                  <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '1px', borderBottom: '1px solid var(--border-default)' }}>
                    PROCESSES ({r.processes.length})
                  </div>
                  {r.processes.map((p, i) => (
                    <div key={i} onClick={() => navigateTo('processes')} style={{
                      padding: '8px 12px',
                      cursor: 'pointer',
                      borderBottom: '1px solid var(--border-default)',
                      fontSize: '12px',
                      color: 'var(--text-secondary)',
                    }}>
                      {p.name} (PID: {p.pid})
                    </div>
                  ))}
                </div>
              )}

              {/* Connections */}
              {r.connections.length > 0 && (
                <div>
                  <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '1px', borderBottom: '1px solid var(--border-default)' }}>
                    CONNECTIONS ({r.connections.length})
                  </div>
                  {r.connections.map((c, i) => (
                    <div key={i} onClick={() => navigateTo('network')} style={{
                      padding: '8px 12px',
                      cursor: 'pointer',
                      borderBottom: '1px solid var(--border-default)',
                      fontSize: '12px',
                      color: 'var(--text-secondary)',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      {c.remote_addr}:{c.remote_port} ({c.protocol.toUpperCase()})
                    </div>
                  ))}
                </div>
              )}

              {/* Vulnerabilities */}
              {r.vulnerabilities.length > 0 && (
                <div>
                  <div style={{ padding: '8px 12px', fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '1px', borderBottom: '1px solid var(--border-default)' }}>
                    VULNERABILITIES ({r.vulnerabilities.length})
                  </div>
                  {r.vulnerabilities.map((v, i) => (
                    <div key={i} onClick={() => navigateTo('vulnerabilities')} style={{
                      padding: '8px 12px',
                      cursor: 'pointer',
                      borderBottom: '1px solid var(--border-default)',
                    }}>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span style={{ fontSize: '10px', fontWeight: 700, color: severityColor(v.severity), textTransform: 'uppercase' }}>{v.severity}</span>
                        <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{v.title}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
