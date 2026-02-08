import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

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
  const [audit, setAudit] = useState<Record<string, unknown> | null>(null);
  const [routes, setRoutes] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState('');

  useEffect(() => {
    loadStatus();
    api.getRoutes().then((d: unknown) => setRoutes(d as Record<string, unknown>[])).catch(() => {});
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
      setAudit(result as Record<string, unknown>);
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Encrypted Tunnel Status */}
      <IntelCard title="ENCRYPTED TUNNEL STATUS" classification="SECRET" status={status?.vpn.connected ? 'active' : 'critical'}>
        {status ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '16px' }}>
              {/* Endpoint visualization */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
                <div style={{
                  width: '36px', height: '36px', borderRadius: '50%',
                  border: '2px solid var(--cyan-primary)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '20px',
                }}>
                  &#x1F5A5;
                </div>
                <div style={{
                  flex: 1, height: '2px',
                  background: status.vpn.connected
                    ? 'repeating-linear-gradient(90deg, var(--cyan-primary) 0px, var(--cyan-primary) 8px, transparent 8px, transparent 12px)'
                    : 'var(--border-default)',
                  position: 'relative',
                }}>
                  {status.vpn.connected && (
                    <div style={{
                      position: 'absolute', top: '-3px', left: '50%',
                      width: '8px', height: '8px', borderRadius: '50%',
                      background: 'var(--cyan-primary)',
                      boxShadow: '0 0 8px var(--cyan-primary)',
                    }} className="breathing" />
                  )}
                </div>
                <div style={{
                  width: '36px', height: '36px', borderRadius: '50%',
                  border: `2px solid ${status.vpn.connected ? 'var(--status-online)' : 'var(--text-muted)'}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '20px',
                }}>
                  &#x1F512;
                </div>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px' }}>
              <InfoRow label="CONNECTED" value={status.vpn.connected ? 'YES' : 'NO'}
                color={status.vpn.connected ? 'var(--status-online)' : 'var(--severity-critical)'} />
              <InfoRow label="PROTOCOL" value={status.vpn.protocol || '--'} />
              <InfoRow label="PROVIDER" value={status.vpn.provider || '--'} />
              <InfoRow label="VPN IP" value={status.vpn.vpn_ip || '--'} />
              <InfoRow label="INTERFACE" value={status.vpn.interface_name || '--'} />
              <InfoRow label="MODULE HEALTH" value={status.module.health.toUpperCase()}
                color={status.module.health === 'running' ? 'var(--status-online)' : 'var(--text-muted)'} />
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)' }}>Loading...</div>
        )}
      </IntelCard>

      {/* Emergency Comms Cutoff */}
      <IntelCard title="EMERGENCY COMMS CUTOFF" classification="SECRET" status={status?.kill_switch.active ? 'critical' : 'active'}>
        {status && (
          <>
            <div style={{ marginBottom: '12px', fontSize: '18px', fontFamily: 'var(--font-mono)' }}>
              <span style={{ color: 'var(--text-muted)', letterSpacing: '1px' }}>STATUS: </span>
              <span style={{
                color: status.kill_switch.active ? 'var(--severity-critical)' : 'var(--status-online)',
                fontWeight: 700,
                letterSpacing: '1px',
              }}>
                {status.kill_switch.active ? 'ACTIVE — ALL TRAFFIC BLOCKED' : 'STANDBY'}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '4px' }}>
              {['alert_only', 'app_specific', 'full'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => handleModeChange(mode)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    fontSize: '16px',
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '1px',
                    background: status.kill_switch.mode === mode
                      ? (mode === 'full' ? 'var(--red-dark)' : 'var(--bg-elevated)')
                      : 'var(--bg-tertiary)',
                    color: status.kill_switch.mode === mode ? '#fff' : 'var(--text-secondary)',
                    border: `1px solid ${status.kill_switch.mode === mode ? (mode === 'full' ? 'var(--red-primary)' : 'var(--cyan-dark)') : 'var(--border-default)'}`,
                    borderRadius: '2px',
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
      </IntelCard>

      {/* Actions Row */}
      <div style={{ display: 'flex', gap: '12px' }}>
        <button
          onClick={handleLeakCheck}
          disabled={loading === 'leak'}
          style={actionBtnStyle(loading === 'leak')}
        >
          {loading === 'leak' ? 'CHECKING...' : 'SEAL INTEGRITY CHECK'}
        </button>
        <button
          onClick={handleAudit}
          disabled={loading === 'audit'}
          style={actionBtnStyle(loading === 'audit')}
        >
          {loading === 'audit' ? 'AUDITING...' : 'CONFIG AUDIT'}
        </button>
      </div>

      {/* Seal Integrity Results */}
      {leakResult && (
        <IntelCard title="SEAL INTEGRITY CHECK" classification="SECRET">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '12px' }}>
            <SealIndicator label="IP SEAL" sealed={!leakResult.ip_leak} />
            <SealIndicator label="DNS SEAL" sealed={!leakResult.dns_leak} />
            <SealIndicator label="IPv6 SEAL" sealed={!leakResult.ipv6_leak} />
          </div>
          {leakResult.public_ip && (
            <div style={{ fontSize: '17px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
              PUBLIC IP: {leakResult.public_ip}
            </div>
          )}
        </IntelCard>
      )}

      {/* Config Audit Results */}
      {audit && (
        <IntelCard title="CONFIG AUDIT" classification="SECRET">
          <pre style={{ fontSize: '17px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(audit, null, 2)}
          </pre>
        </IntelCard>
      )}

      {/* Route Table */}
      {Array.isArray(routes) && routes.length > 0 && (
        <IntelCard title="ROUTE TABLE" classification="UNCLASSIFIED">
          <pre style={{ fontSize: '17px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(routes, null, 2)}
          </pre>
        </IntelCard>
      )}
    </div>
  );
}

function InfoRow({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <div style={{ fontSize: '15px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '2px' }}>
        {label}
      </div>
      <div style={{ fontSize: '19px', fontFamily: 'var(--font-mono)', color: color || 'var(--text-primary)', fontWeight: 600 }}>
        {value}
      </div>
    </div>
  );
}

function SealIndicator({ label, sealed }: { label: string; sealed: boolean }) {
  return (
    <div style={{
      padding: '16px',
      background: sealed ? 'rgba(76, 175, 80, 0.08)' : 'rgba(255, 23, 68, 0.08)',
      border: `1px solid ${sealed ? 'rgba(76, 175, 80, 0.3)' : 'rgba(255, 23, 68, 0.3)'}`,
      borderRadius: '2px',
      textAlign: 'center',
    }}>
      <div style={{
        width: '40px', height: '40px', borderRadius: '50%',
        border: `3px solid ${sealed ? 'var(--status-online)' : 'var(--severity-critical)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        margin: '0 auto 8px',
        fontSize: '24px',
      }}>
        {sealed ? '\u2713' : '\u2717'}
      </div>
      <div style={{
        fontSize: '16px', fontFamily: 'var(--font-mono)', letterSpacing: '1px',
        color: sealed ? 'var(--status-online)' : 'var(--severity-critical)',
        fontWeight: 700,
      }}>
        {label}
      </div>
      <div style={{
        fontSize: '15px', fontFamily: 'var(--font-mono)', letterSpacing: '1px',
        color: 'var(--text-muted)', marginTop: '2px',
      }}>
        {sealed ? 'SEALED' : 'BREACH DETECTED'}
      </div>
    </div>
  );
}

function actionBtnStyle(disabled: boolean): React.CSSProperties {
  return {
    padding: '8px 20px',
    fontSize: '17px',
    fontFamily: 'var(--font-mono)',
    letterSpacing: '1px',
    background: disabled ? 'var(--bg-tertiary)' : 'var(--bg-elevated)',
    color: disabled ? 'var(--text-muted)' : 'var(--text-primary)',
    border: '1px solid var(--border-default)',
    borderRadius: '2px',
    cursor: disabled ? 'default' : 'pointer',
    textTransform: 'uppercase',
  };
}
