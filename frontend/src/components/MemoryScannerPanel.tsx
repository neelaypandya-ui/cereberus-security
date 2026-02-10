import { useEffect, useState, useCallback } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';
import { PanelSkeleton } from './ui/PanelSkeleton';
import { CopyButton } from './ui/CopyButton';
interface MemoryScanResultResponse {
  id: number;
  pid: number;
  process_name: string;
  finding_type: string;
  severity: string;
  details: Record<string, unknown>;
  scanned_at: string | null;
}

interface MemoryStatus {
  status: string;
  details: {
    total_scans: number;
    findings_count: number;
    scanned_at: string | null;
    [key: string]: unknown;
  };
}

const FINDING_COLORS: Record<string, string> = {
  rwx_region: '#ff1744',
  unbacked_exec: '#ff9100',
  injected_dll: '#ffd600',
  shellcode: '#ff1744',
  yara_match: '#b388ff',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: 'var(--text-muted)',
};

const PAGE_SIZES = [25, 50, 100];

export function MemoryScannerPanel() {
  const { showToast } = useToast();
  const [status, setStatus] = useState<MemoryStatus | null>(null);
  const [results, setResults] = useState<MemoryScanResultResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [pidInput, setPidInput] = useState('');
  const [scanningPid, setScanningPid] = useState(false);
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);

  const loadStatus = useCallback(async () => {
    try {
      const s = await api.getMemoryStatus() as MemoryStatus;
      setStatus(s);
    } catch (e: unknown) {
      showToast('error', 'Failed to load memory status', (e as Error).message);
    }
  }, []);

  const loadResults = useCallback(async () => {
    try {
      const r = await api.getMemoryResults(limit, offset) as MemoryScanResultResponse[];
      setResults(r);
    } catch (e: unknown) {
      showToast('error', 'Failed to load scan results', (e as Error).message);
    }
  }, [limit, offset]);

  useEffect(() => {
    Promise.all([loadStatus(), loadResults()]).finally(() => setLoading(false));
    const statusInterval = setInterval(loadStatus, 15000);
    const resultsInterval = setInterval(loadResults, 30000);
    return () => { clearInterval(statusInterval); clearInterval(resultsInterval); };
  }, [loadStatus, loadResults]);

  const handleFullScan = async () => {
    setScanning(true);
    try {
      await api.triggerMemoryScan();
      showToast('success', 'Memory scan initiated');
      setTimeout(() => { loadStatus(); loadResults(); }, 2000);
    } catch (e: unknown) {
      showToast('error', 'Failed to trigger scan', (e as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const handlePidScan = async () => {
    const pid = parseInt(pidInput, 10);
    if (isNaN(pid) || pid <= 0) {
      showToast('error', 'Invalid PID', 'Enter a valid process ID');
      return;
    }
    setScanningPid(true);
    try {
      await api.scanProcessMemory(pid);
      showToast('success', `Scan initiated for PID ${pid}`);
      setPidInput('');
      setTimeout(() => { loadStatus(); loadResults(); }, 2000);
    } catch (e: unknown) {
      showToast('error', `Failed to scan PID ${pid}`, (e as Error).message);
    } finally {
      setScanningPid(false);
    }
  };

  if (loading) return <PanelSkeleton />;

  const hasFindings = (status?.details?.findings_count ?? 0) > 0;
  const cardStatus = hasFindings ? 'warning' : 'active';

  return (
    <IntelCard title="MEMORY RECONNAISSANCE" classification="TOP SECRET//SCI" status={cardStatus}>
      {/* Stats Bar */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <StatBox label="TOTAL SCANS" value={status?.details?.total_scans ?? 0} />
        <StatBox label="FINDINGS" value={status?.details?.findings_count ?? 0} color={hasFindings ? '#ff1744' : undefined} />
        <StatBox label="LAST SCAN" value={status?.details?.scanned_at ? new Date(status.details.scanned_at).toLocaleTimeString('en-US', { hour12: false }) + 'Z' : 'NEVER'} />
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center' }}>
          <button onClick={handleFullScan} disabled={scanning} style={actionBtnStyle}>
            {scanning ? 'SCANNING...' : 'SCAN NOW'}
          </button>
        </div>
      </div>

      {/* PID Scanner */}
      <div style={{
        display: 'flex', gap: '8px', alignItems: 'center',
        marginBottom: '16px', padding: '10px 12px',
        background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', borderRadius: '2px',
      }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', letterSpacing: '1px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
          TARGET PID:
        </span>
        <input
          type="text"
          value={pidInput}
          onChange={(e) => setPidInput(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => e.key === 'Enter' && handlePidScan()}
          placeholder="e.g. 4820"
          style={{
            width: '100px', padding: '4px 8px',
            background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: '2px',
            color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '15px',
            outline: 'none',
          }}
        />
        <button onClick={handlePidScan} disabled={scanningPid || !pidInput} style={actionBtnStyle}>
          {scanningPid ? 'SCANNING...' : 'SCAN PROCESS'}
        </button>
      </div>

      {/* Results Table */}
      <div style={{ border: '1px solid var(--border-default)', borderRadius: '2px', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '16px' }}>
          <thead>
            <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-default)' }}>
              <th style={thStyle}>PID</th>
              <th style={thStyle}>PROCESS</th>
              <th style={thStyle}>FINDING</th>
              <th style={thStyle}>SEVERITY</th>
              <th style={thStyle}>SCANNED</th>
            </tr>
          </thead>
          <tbody>
            {results.length === 0 && (
              <tr>
                <td colSpan={5} style={{
                  padding: '40px', textAlign: 'center',
                  color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                  fontSize: '15px', letterSpacing: '2px',
                }}>
                  NO FINDINGS IN MEMORY SCAN
                </td>
              </tr>
            )}
            {results.map((r) => (
              <tr key={r.id} style={{ borderBottom: '1px solid var(--border-default)' }}>
                <td style={tdStyle}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '2px' }} className="mono">
                    {r.pid}
                    <CopyButton value={String(r.pid)} label={`Copy PID ${r.pid}`} />
                  </span>
                </td>
                <td style={{ ...tdStyle, color: 'var(--text-primary)' }}>{r.process_name}</td>
                <td style={tdStyle}>
                  <span style={{
                    padding: '2px 8px', borderRadius: '2px', fontSize: '13px',
                    fontFamily: 'var(--font-mono)', letterSpacing: '1px',
                    color: FINDING_COLORS[r.finding_type] || 'var(--text-secondary)',
                    background: `${FINDING_COLORS[r.finding_type] || 'var(--text-secondary)'}18`,
                    border: `1px solid ${FINDING_COLORS[r.finding_type] || 'var(--text-secondary)'}44`,
                  }}>
                    {r.finding_type.toUpperCase().replace(/_/g, ' ')}
                  </span>
                </td>
                <td style={tdStyle}>
                  <span style={{
                    padding: '2px 8px', borderRadius: '2px', fontSize: '13px',
                    fontFamily: 'var(--font-mono)', letterSpacing: '1px',
                    color: SEVERITY_COLORS[r.severity] || 'var(--text-muted)',
                    background: `${SEVERITY_COLORS[r.severity] || 'var(--text-muted)'}18`,
                  }}>
                    {r.severity.toUpperCase()}
                  </span>
                </td>
                <td style={{ ...tdStyle, color: 'var(--text-muted)', fontSize: '14px' }}>
                  {r.scanned_at ? new Date(r.scanned_at).toLocaleTimeString('en-US', { hour12: false }) + 'Z' : '--'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginTop: '12px', padding: '8px 0',
      }}>
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-muted)', letterSpacing: '1px' }}>
            SHOW:
          </span>
          {PAGE_SIZES.map((size) => (
            <button
              key={size}
              onClick={() => { setLimit(size); setOffset(0); }}
              style={{
                padding: '2px 8px', fontSize: '13px', fontFamily: 'var(--font-mono)',
                background: limit === size ? 'var(--bg-elevated)' : 'transparent',
                border: `1px solid ${limit === size ? 'var(--border-active)' : 'var(--border-default)'}`,
                color: limit === size ? 'var(--text-primary)' : 'var(--text-muted)',
                borderRadius: '2px', cursor: 'pointer',
              }}
            >
              {size}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          <button
            onClick={() => setOffset(Math.max(0, offset - limit))}
            disabled={offset === 0}
            style={{ ...pageBtnStyle, opacity: offset === 0 ? 0.3 : 1 }}
          >
            PREV
          </button>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-muted)', letterSpacing: '1px', minWidth: '80px', textAlign: 'center' }}>
            {offset + 1}-{offset + results.length}
          </span>
          <button
            onClick={() => setOffset(offset + limit)}
            disabled={results.length < limit}
            style={{ ...pageBtnStyle, opacity: results.length < limit ? 0.3 : 1 }}
          >
            NEXT
          </button>
        </div>
      </div>
    </IntelCard>
  );
}

function StatBox({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div style={{
      padding: '8px 16px', background: 'var(--bg-tertiary)',
      border: '1px solid var(--border-default)', borderRadius: '2px', minWidth: '120px',
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', letterSpacing: '2px', color: 'var(--text-muted)', marginBottom: '4px' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '20px', color: color || 'var(--cyan-primary)', letterSpacing: '1px' }}>
        {value}
      </div>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '8px 10px', fontSize: '13px', fontWeight: 600,
  fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px', textTransform: 'uppercase',
};

const tdStyle: React.CSSProperties = {
  padding: '6px 10px', fontFamily: 'var(--font-mono)', fontSize: '15px',
};

const actionBtnStyle: React.CSSProperties = {
  padding: '5px 14px', fontSize: '13px', fontFamily: 'var(--font-mono)', letterSpacing: '1px',
  background: 'var(--bg-elevated)', color: 'var(--cyan-primary)',
  border: '1px solid var(--cyan-primary)', borderRadius: '2px', cursor: 'pointer', textTransform: 'uppercase',
};

const pageBtnStyle: React.CSSProperties = {
  padding: '3px 10px', fontSize: '13px', fontFamily: 'var(--font-mono)', letterSpacing: '1px',
  background: 'var(--bg-tertiary)', color: 'var(--text-muted)',
  border: '1px solid var(--border-default)', borderRadius: '2px', cursor: 'pointer',
};
