import { useEffect, useState } from 'react';
import { api } from '../services/api';

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
    } catch { /* ignore */ }
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
    } catch { /* ignore */ }
  };

  const displayList = view === 'suspicious' ? suspicious : processes.slice(0, 100);

  return (
    <div>
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px' }}>
        <button onClick={() => setView('suspicious')} style={tabStyle(view === 'suspicious')}>
          Suspicious ({suspicious.length})
        </button>
        <button onClick={() => setView('all')} style={tabStyle(view === 'all')}>
          All Processes ({processes.length})
        </button>
      </div>

      {suspicious.length > 0 && view === 'suspicious' && (
        <div style={{
          padding: '12px 16px',
          background: 'rgba(255, 23, 68, 0.08)',
          border: '1px solid var(--severity-critical)',
          borderRadius: '8px',
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--severity-critical)',
          fontFamily: 'var(--font-mono)',
        }}>
          {suspicious.length} suspicious process(es) detected
        </div>
      )}

      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
          <thead>
            <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-default)' }}>
              <th style={thStyle}>PID</th>
              <th style={thStyle}>Name</th>
              <th style={thStyle}>User</th>
              <th style={thStyle}>CPU%</th>
              <th style={thStyle}>MEM%</th>
              <th style={thStyle}>Status</th>
              <th style={thStyle}>Flags</th>
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
                <td style={tdStyle}><span className="mono">{p.pid}</span></td>
                <td style={{ ...tdStyle, color: p.suspicious ? 'var(--severity-critical)' : 'var(--text-primary)' }}>
                  {p.name}
                </td>
                <td style={{ ...tdStyle, color: 'var(--text-secondary)' }}>{p.username}</td>
                <td style={tdStyle}>
                  <span style={{ color: p.cpu_percent > 80 ? 'var(--severity-critical)' : 'var(--text-secondary)' }}>
                    {p.cpu_percent.toFixed(1)}
                  </span>
                </td>
                <td style={tdStyle}>
                  <span style={{ color: p.memory_percent > 50 ? 'var(--severity-high)' : 'var(--text-secondary)' }}>
                    {p.memory_percent.toFixed(1)}
                  </span>
                </td>
                <td style={tdStyle}>
                  <span style={{
                    fontSize: '10px',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    background: p.status === 'running' ? 'rgba(76, 175, 80, 0.1)' : 'var(--bg-tertiary)',
                    color: p.status === 'running' ? 'var(--status-online)' : 'var(--text-muted)',
                  }}>
                    {p.status}
                  </span>
                </td>
                <td style={tdStyle}>
                  {p.suspicious_reasons.map((r, i) => (
                    <span key={i} style={{
                      fontSize: '9px',
                      padding: '1px 4px',
                      marginRight: '4px',
                      borderRadius: '2px',
                      background: 'rgba(255, 87, 34, 0.15)',
                      color: 'var(--severity-high)',
                    }}>
                      {r}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {expandedPid && processTree && (
        <div style={{
          marginTop: '16px',
          padding: '16px',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
        }}>
          <h4 style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px', letterSpacing: '1px' }}>
            PROCESS TREE — PID {expandedPid}
          </h4>
          <TreeNode node={processTree} depth={0} />
        </div>
      )}
    </div>
  );
}

function TreeNode({ node, depth }: { node: ProcessInfo; depth: number }) {
  return (
    <div style={{ marginLeft: depth * 20 }}>
      <div style={{
        display: 'flex',
        gap: '8px',
        padding: '4px 8px',
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        color: node.suspicious ? 'var(--severity-critical)' : 'var(--text-primary)',
      }}>
        <span style={{ color: 'var(--text-muted)' }}>{node.pid}</span>
        <span>{node.name}</span>
        <span style={{ color: 'var(--text-muted)' }}>{node.exe}</span>
      </div>
      {node.children?.map((child) => (
        <TreeNode key={child.pid} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: 'left',
  padding: '10px 12px',
  fontSize: '10px',
  fontWeight: 600,
  color: 'var(--text-muted)',
  letterSpacing: '1px',
  textTransform: 'uppercase',
};

const tdStyle: React.CSSProperties = {
  padding: '8px 12px',
  fontFamily: 'var(--font-mono)',
  fontSize: '11px',
};

function tabStyle(active: boolean): React.CSSProperties {
  return {
    padding: '8px 16px',
    background: active ? 'var(--bg-elevated)' : 'transparent',
    border: `1px solid ${active ? 'var(--border-active)' : 'var(--border-default)'}`,
    borderRadius: '6px',
    color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
    fontSize: '12px',
    cursor: 'pointer',
    fontFamily: 'var(--font-sans)',
  };
}
