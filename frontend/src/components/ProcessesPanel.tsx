import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';
import { CopyButton } from './ui/CopyButton';
import { CsvExportButton } from './ui/CsvExportButton';

interface ProcessInfo {
  pid: number;
  name: string;
  exe: string;
  username: string;
  cpu_percent: number;
  memory_percent: number;
  status: string;
  create_time: string | null;
  ppid: number | null;
  suspicious: boolean;
  suspicious_reasons: string[];
  children?: ProcessInfo[];
}

export function ProcessesPanel() {
  const { showToast } = useToast();
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [suspicious, setSuspicious] = useState<ProcessInfo[]>([]);
  const [expandedPid, setExpandedPid] = useState<number | null>(null);
  const [processTree, setProcessTree] = useState<ProcessInfo | null>(null);
  const [view, setView] = useState<'all' | 'suspicious'>('suspicious');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [procs, sus] = await Promise.all([
        api.getProcesses(),
        api.getSuspiciousProcesses(),
      ]);
      setProcesses(procs as ProcessInfo[]);
      setSuspicious(sus as ProcessInfo[]);
    } catch (e: unknown) { showToast('error', 'Failed to load processes', (e as Error).message); }
  };

  const loadTree = async (pid: number) => {
    if (expandedPid === pid) {
      setExpandedPid(null);
      setProcessTree(null);
      return;
    }
    try {
      const tree = await api.getProcessTree(pid) as ProcessInfo;
      setProcessTree(tree);
      setExpandedPid(pid);
    } catch (e: unknown) { showToast('error', 'Failed to load process tree', (e as Error).message); }
  };

  const displayList = view === 'suspicious' ? suspicious : processes.slice(0, 100);

  return (
    <IntelCard title="ASSET TRACKER" classification="SECRET//NOFORN" status={suspicious.length > 0 ? 'warning' : 'active'}>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', alignItems: 'center' }}>
        <button onClick={() => setView('suspicious')} style={tabStyle(view === 'suspicious')}>
          HOSTILE ({suspicious.length})
        </button>
        <button onClick={() => setView('all')} style={tabStyle(view === 'all')}>
          ALL ASSETS ({processes.length})
        </button>
        <div style={{ marginLeft: 'auto' }}>
          <CsvExportButton
            data={displayList as unknown as Record<string, unknown>[]}
            filename="cereberus-processes"
            columns={[
              { key: 'pid', label: 'PID' },
              { key: 'name', label: 'Name' },
              { key: 'username', label: 'User' },
              { key: 'cpu_percent', label: 'CPU%' },
              { key: 'memory_percent', label: 'MEM%' },
              { key: 'status', label: 'Status' },
              { key: 'suspicious', label: 'Suspicious' },
            ]}
          />
        </div>
      </div>

      {suspicious.length > 0 && view === 'suspicious' && (
        <div className="critical-pulse" style={{
          padding: '10px 14px',
          background: 'rgba(255, 23, 68, 0.06)',
          border: '1px solid var(--severity-critical)',
          borderRadius: '2px',
          marginBottom: '12px',
          fontSize: '17px',
          fontFamily: 'var(--font-mono)',
          letterSpacing: '1px',
          color: 'var(--severity-critical)',
        }}>
          {suspicious.length} HOSTILE ASSET(S) DETECTED
        </div>
      )}

      <div style={{
        border: '1px solid var(--border-default)',
        borderRadius: '2px',
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '17px' }}>
          <thead>
            <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-default)' }}>
              <th style={thStyle}>PID</th>
              <th style={thStyle}>NAME</th>
              <th style={thStyle}>USER</th>
              <th style={thStyle}>CPU%</th>
              <th style={thStyle}>MEM%</th>
              <th style={thStyle}>STATUS</th>
              <th style={thStyle}>CLASS</th>
            </tr>
          </thead>
          <tbody>
            {displayList.map((p) => (
              <tr
                key={p.pid}
                onClick={() => loadTree(p.pid)}
                style={{
                  borderBottom: '1px solid var(--border-default)',
                  cursor: 'pointer',
                  background: p.suspicious ? 'rgba(255, 23, 68, 0.04)' : 'transparent',
                }}
              >
                <td style={tdStyle}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '2px' }} className="mono">
                    {p.pid}
                    <CopyButton value={String(p.pid)} label={`Copy PID ${p.pid}`} />
                  </span>
                </td>
                <td style={{ ...tdStyle, color: 'var(--text-primary)' }}>{p.name}</td>
                <td style={{ ...tdStyle, color: 'var(--text-secondary)' }}>{p.username}</td>
                <td style={tdStyle}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: p.cpu_percent > 80 ? 'var(--severity-critical)' : 'var(--text-secondary)', minWidth: '30px' }}>
                      {p.cpu_percent.toFixed(1)}
                    </span>
                    <MiniBar percent={p.cpu_percent} color={p.cpu_percent > 80 ? 'var(--severity-critical)' : 'var(--cyan-primary)'} />
                  </div>
                </td>
                <td style={tdStyle}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: p.memory_percent > 50 ? 'var(--severity-high)' : 'var(--text-secondary)', minWidth: '30px' }}>
                      {p.memory_percent.toFixed(1)}
                    </span>
                    <MiniBar percent={p.memory_percent} color={p.memory_percent > 50 ? 'var(--severity-high)' : 'var(--cyan-primary)'} />
                  </div>
                </td>
                <td style={tdStyle}>
                  <span style={{
                    fontSize: '15px',
                    padding: '2px 6px',
                    borderRadius: '2px',
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '1px',
                    background: p.status === 'running' ? 'rgba(76, 175, 80, 0.1)' : 'var(--bg-tertiary)',
                    color: p.status === 'running' ? 'var(--status-online)' : 'var(--text-muted)',
                  }}>
                    {p.status.toUpperCase()}
                  </span>
                </td>
                <td style={tdStyle}>
                  {p.suspicious ? (
                    <span className="stamp-badge stamp-hostile">HOSTILE</span>
                  ) : (
                    <span className="stamp-badge stamp-cleared">CLEARED</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {expandedPid && processTree && (
        <div style={{
          marginTop: '12px',
          padding: '14px',
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border-default)',
          borderRadius: '2px',
        }}>
          <div style={{
            fontSize: '16px', fontFamily: 'var(--font-mono)',
            letterSpacing: '2px', color: 'var(--text-muted)', marginBottom: '10px',
          }}>
            PROCESS TREE &#x2014; PID {expandedPid}
          </div>
          <TreeNode node={processTree} depth={0} />
        </div>
      )}
    </IntelCard>
  );
}

function MiniBar({ percent, color }: { percent: number; color: string }) {
  return (
    <div style={{ width: '40px', height: '4px', background: 'var(--bg-tertiary)', borderRadius: '1px', overflow: 'hidden' }}>
      <div style={{ width: `${Math.min(percent, 100)}%`, height: '100%', background: color, borderRadius: '1px' }} />
    </div>
  );
}

function TreeNode({ node, depth }: { node: ProcessInfo; depth: number }) {
  return (
    <div style={{ marginLeft: depth * 20 }}>
      <div style={{
        display: 'flex',
        gap: '8px',
        padding: '3px 8px',
        fontFamily: 'var(--font-mono)',
        fontSize: '17px',
        color: node.suspicious ? 'var(--severity-critical)' : 'var(--text-primary)',
        borderLeft: depth > 0 ? '1px dashed var(--border-default)' : 'none',
      }}>
        <span style={{ color: 'var(--text-muted)' }}>{node.pid}</span>
        <span>{node.name}</span>
        <span style={{ color: 'var(--text-muted)', fontSize: '16px' }}>{node.exe}</span>
      </div>
      {node.children?.map((child) => (
        <TreeNode key={child.pid} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: 'left',
  padding: '8px 10px',
  fontSize: '15px',
  fontWeight: 600,
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-muted)',
  letterSpacing: '1px',
  textTransform: 'uppercase',
};

const tdStyle: React.CSSProperties = {
  padding: '6px 10px',
  fontFamily: 'var(--font-mono)',
  fontSize: '17px',
};

function tabStyle(active: boolean): React.CSSProperties {
  return {
    padding: '6px 14px',
    background: active ? 'var(--bg-elevated)' : 'transparent',
    border: `1px solid ${active ? 'var(--border-active)' : 'var(--border-default)'}`,
    borderRadius: '2px',
    color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
    fontSize: '16px',
    fontFamily: 'var(--font-mono)',
    letterSpacing: '1px',
    cursor: 'pointer',
    textTransform: 'uppercase',
  };
}
