import { useEffect, useState } from 'react';
import { api } from '../services/api';

interface VpnStatusData {
  vpn: {
    connected: boolean;
    protocol: string | null;
    provider: string | null;
    vpn_ip: string | null;
    interface_name: string | null;
  };
  kill_switch: {
    active: boolean;
    mode: string;
  };
  module: {
    name: string;
    running: boolean;
    health: string;
  };
}

interface LeakResult {
  ip_leak: boolean;
  dns_leak: boolean;
  ipv6_leak: boolean;
  public_ip: string | null;
  dns_servers: string[];
}

export function VpnDetailPanel() {
  const [status, setStatus] = useState<VpnStatusData | null>(null);
  const [leakResult, setLeakResult] = useState<LeakResult | null>(null);
  const [audit, setAudit] = useState<unknown>(null);
  const [routes, setRoutes] = useState<unknown[]>([]);
  const [loading, setLoading] = useState('');

  useEffect(() => {
    loadStatus();
    api.getRoutes().then((d: unknown) => setRoutes(d as unknown[])).catch(() => {});
  }, []);

  const loadStatus = () => {
    api.getVpnStatus().then((d: unknown) => setStatus(d as VpnStatusData)).catch(() => {});
  };

  const handleLeakCheck = async () => {
    setLoading('leak');
    try {
      const result = await api.runLeakCheck();
      setLeakResult(result as LeakResult);
    } catch { /* ignore */ }
    setLoading('');
  };

  const handleAudit = async () => {
    setLoading('audit');
    try {
      const result = await api.runConfigAudit();
      setAudit(result);
    } catch { /* ignore */ }
    setLoading('');
  };

  const handleModeChange = async (mode: string) => {
    try {
      await api.setKillSwitchMode(mode);
      loadStatus();
    } catch { /* ignore */ }
  };

  return (
    <div>
      {/* VPN Status Card */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '20px',
      }}>
        <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
          VPN STATUS
        </h3>
        {status ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <InfoRow label="Connected" value={status.vpn.connected ? 'Yes' : 'No'}
              color={status.vpn.connected ? 'var(--status-online)' : 'var(--severity-critical)'} />
            <InfoRow label="Protocol" value={status.vpn.protocol || '--'} />
            <InfoRow label="Provider" value={status.vpn.provider || '--'} />
            <InfoRow label="VPN IP" value={status.vpn.vpn_ip || '--'} />
            <InfoRow label="Interface" value={status.vpn.interface_name || '--'} />
            <InfoRow label="Module Health" value={status.module.health}
              color={status.module.health === 'running' ? 'var(--status-online)' : 'var(--text-muted)'} />
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Loading...</div>
        )}
      </div>

      {/* Kill Switch Controls */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '20px',
      }}>
        <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
          KILL SWITCH
        </h3>
        {status && (
          <>
            <div style={{ marginBottom: '12px', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Status: </span>
              <span style={{ color: status.kill_switch.active ? 'var(--severity-critical)' : 'var(--status-online)' }}>
                {status.kill_switch.active ? 'ACTIVE (blocking traffic)' : 'Inactive'}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              {['alert_only', 'app_specific', 'full'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => handleModeChange(mode)}
                  style={{
                    padding: '6px 14px',
                    fontSize: '11px',
                    background: status.kill_switch.mode === mode ? 'var(--red-primary)' : 'var(--bg-tertiary)',
                    color: status.kill_switch.mode === mode ? '#fff' : 'var(--text-secondary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                  }}
                >
                  {mode.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Actions Row */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px' }}>
        <button
          onClick={handleLeakCheck}
          disabled={loading === 'leak'}
          style={{
            padding: '10px 20px',
            fontSize: '12px',
            background: 'var(--bg-tertiary)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border-default)',
            borderRadius: '6px',
            cursor: 'pointer',
          }}
        >
          {loading === 'leak' ? 'Checking...' : 'Run Leak Check'}
        </button>
        <button
          onClick={handleAudit}
          disabled={loading === 'audit'}
          style={{
            padding: '10px 20px',
            fontSize: '12px',
            background: 'var(--bg-tertiary)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border-default)',
            borderRadius: '6px',
            cursor: 'pointer',
          }}
        >
          {loading === 'audit' ? 'Auditing...' : 'Run Config Audit'}
        </button>
      </div>

      {/* Leak Check Results */}
      {leakResult && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
          padding: '20px',
          marginBottom: '20px',
        }}>
          <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
            LEAK CHECK RESULTS
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
            <LeakIndicator label="IP Leak" detected={leakResult.ip_leak} />
            <LeakIndicator label="DNS Leak" detected={leakResult.dns_leak} />
            <LeakIndicator label="IPv6 Leak" detected={leakResult.ipv6_leak} />
          </div>
          {leakResult.public_ip && (
            <div style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Public IP: {leakResult.public_ip}
            </div>
          )}
        </div>
      )}

      {/* Config Audit Results */}
      {audit && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
          padding: '20px',
          marginBottom: '20px',
        }}>
          <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
            CONFIG AUDIT
          </h3>
          <pre style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(audit, null, 2)}
          </pre>
        </div>
      )}

      {/* Route Table */}
      {Array.isArray(routes) && routes.length > 0 && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
          padding: '20px',
        }}>
          <h3 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', letterSpacing: '1px' }}>
            ROUTE TABLE
          </h3>
          <pre style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(routes, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.5px', marginBottom: '2px' }}>
        {label.toUpperCase()}
      </div>
      <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: color || 'var(--text-primary)' }}>
        {value}
      </div>
    </div>
  );
}

function LeakIndicator({ label, detected }: { label: string; detected: boolean }) {
  return (
    <div style={{
      padding: '12px',
      background: detected ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
      borderRadius: '6px',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>{label}</div>
      <div style={{
        fontSize: '13px',
        fontWeight: 700,
        color: detected ? 'var(--severity-critical)' : 'var(--status-online)',
      }}>
        {detected ? 'DETECTED' : 'CLEAR'}
      </div>
    </div>
  );
}
