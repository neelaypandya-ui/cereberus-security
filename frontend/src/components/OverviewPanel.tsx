import { useEffect, useState, useRef } from 'react';
import { api } from '../services/api';
import { ThreatLevelBanner } from './ThreatLevelBanner';
import { Sparkline } from './Sparkline';
import { ReportButton } from './ReportButton';
import { IntelCard } from './ui/IntelCard';
import { RadarSweep } from './ui/RadarSweep';

interface OverviewPanelProps {
  alerts: Record<string, number>;
  eventsToday: number;
  modules: Array<{ name: string; enabled: boolean; health: string }>;
  networkStats: {
    total: number;
    established: number;
    suspicious: number;
  } | null;
  threatLevel?: string;
}

const DEFCON_MAP: Record<string, { label: string; color: string }> = {
  none: { label: 'DEFCON 5 — NORMAL', color: 'var(--cyan-primary)' },
  low: { label: 'DEFCON 4 — ELEVATED', color: 'var(--status-online)' },
  medium: { label: 'DEFCON 3 — INCREASED', color: 'var(--amber-primary)' },
  high: { label: 'DEFCON 2 — HIGH', color: 'var(--severity-high)' },
  critical: { label: 'DEFCON 1 — CRITICAL', color: 'var(--severity-critical)' },
};

const PRIORITY_MAP: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

export function OverviewPanel({ alerts, eventsToday: _eventsToday, modules, networkStats, threatLevel = 'none' }: OverviewPanelProps) {
  const alertTotal = Object.values(alerts).reduce((a, b) => a + b, 0);
  const [recentAlerts, setRecentAlerts] = useState<Array<{
    id: number; severity: string; title: string; timestamp: string; module_source: string;
  }>>([]);

  const connectionHistory = useRef<number[]>([]);
  if (networkStats) {
    connectionHistory.current = [...connectionHistory.current, networkStats.total].slice(-60);
  }

  useEffect(() => {
    api.getAlerts({ limit: 8 }).then((data: unknown) => {
      setRecentAlerts(data as typeof recentAlerts);
    }).catch(() => {});
  }, []);

  const defcon = DEFCON_MAP[threatLevel] || DEFCON_MAP.none;

  // Generate radar blips from threat data
  const radarBlips = [];
  if (networkStats?.suspicious) {
    for (let i = 0; i < Math.min(networkStats.suspicious, 8); i++) {
      radarBlips.push({
        angle: (i * 360 / Math.max(networkStats.suspicious, 1)) + 30,
        distance: 0.4 + Math.random() * 0.5,
        severity: i < (alerts.critical ?? 0) ? 'critical' : i < (alerts.critical ?? 0) + (alerts.high ?? 0) ? 'high' : 'medium',
      });
    }
  }

  const onlineModules = modules.filter((m) => m.enabled && m.health === 'running').length;

  return (
    <div>
      {/* Header with Report Button */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <ThreatLevelBanner level={threatLevel} />
        <ReportButton />
      </div>

      {/* Top Row: Radar + SITREP Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '16px', marginBottom: '16px' }}>
        {/* Radar Display */}
        <IntelCard title="THREAT RADAR" classification="SECRET" status={threatLevel === 'critical' ? 'critical' : threatLevel === 'high' ? 'warning' : 'active'}>
          <div style={{ textAlign: 'center' }}>
            <RadarSweep size={240} blips={radarBlips} />
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              fontWeight: 700,
              color: defcon.color,
              letterSpacing: '2px',
              marginTop: '8px',
            }}>
              {defcon.label}
            </div>
            <div className="breathing" style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '9px',
              color: 'var(--text-muted)',
              letterSpacing: '2px',
              marginTop: '4px',
            }}>
              THREAT DETECTION ACTIVE
            </div>
          </div>
        </IntelCard>

        {/* SITREP Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gridTemplateRows: '1fr 1fr', gap: '12px' }}>
          <SitrepCard label="ACTIVE CONNECTIONS" value={networkStats?.total ?? 0} color="var(--cyan-primary)">
            {connectionHistory.current.length > 2 && (
              <Sparkline data={connectionHistory.current} width={120} height={24} />
            )}
          </SitrepCard>
          <SitrepCard label="FLAGGED THREATS" value={networkStats?.suspicious ?? 0} color="var(--severity-critical)" />
          <SitrepCard label="MODULES ONLINE" value={onlineModules} subtext={`/ ${modules.length}`} color="var(--status-online)" />
          <SitrepCard label="OPEN ALERTS" value={alertTotal} color="var(--amber-primary)" />
        </div>
      </div>

      {/* Module Status Grid — STATION STATUS */}
      <IntelCard title="STATION STATUS" classification="SECRET" style={{ marginBottom: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
          {modules.map((m) => {
            const isRunning = m.health === 'running';
            return (
              <div key={m.name} style={{
                padding: '10px 12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '2px',
                borderLeft: `3px solid ${isRunning ? 'var(--status-online)' : m.enabled ? 'var(--amber-primary)' : 'var(--text-muted)'}`,
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
              }}>
                <div
                  className={isRunning ? 'status-dot-glow' : ''}
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: isRunning ? 'var(--status-online)' : 'var(--text-muted)',
                    flexShrink: 0,
                    color: isRunning ? 'var(--status-online)' : 'var(--text-muted)',
                  }}
                />
                <div style={{ flex: 1 }}>
                  <div style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '1px',
                    color: 'var(--text-secondary)',
                  }}>
                    {m.name.toUpperCase().replace(/_/g, ' ')}
                  </div>
                  <div style={{
                    fontSize: '9px',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '2px',
                    color: isRunning ? 'var(--status-online)' : 'var(--text-muted)',
                    letterSpacing: '1px',
                  }}>
                    {isRunning ? 'STATION ONLINE' : m.enabled ? m.health.toUpperCase() : 'OFFLINE'}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </IntelCard>

      {/* Intelligence Cable Feed */}
      <IntelCard title="SIGINT FEED" classification="SECRET//SI">
        <div style={{ maxHeight: '240px', overflow: 'auto' }}>
          {recentAlerts.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-mono)', padding: '12px 0' }}>
              No intelligence traffic
            </div>
          ) : (
            recentAlerts.map((a, i) => {
              const pri = PRIORITY_MAP[a.severity] || PRIORITY_MAP.info;
              const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }) : '--:--:--';
              return (
                <div key={i} className="cable-feed-item">
                  <span className={`stamp-badge ${pri.stampClass}`}>{pri.label}</span>
                  <span style={{ color: 'var(--text-muted)', minWidth: '70px' }}>{ts}Z</span>
                  <span style={{ color: 'var(--text-muted)' }}>//</span>
                  <span style={{ color: 'var(--cyan-primary)', minWidth: '100px' }}>
                    {(a.module_source || 'SYSTEM').toUpperCase().replace(/_/g, '_')}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>&mdash;</span>
                  <span style={{ color: 'var(--text-primary)', flex: 1 }}>{a.title}</span>
                </div>
              );
            })
          )}
        </div>
      </IntelCard>
    </div>
  );
}

function SitrepCard({ label, value, color, subtext, children }: {
  label: string; value: number; color: string; subtext?: string; children?: React.ReactNode;
}) {
  return (
    <IntelCard title={label} classification="UNCLASSIFIED">
      <div style={{ textAlign: 'center' }}>
        <div style={{
          fontSize: '32px',
          fontWeight: 700,
          fontFamily: 'var(--font-mono)',
          color,
          letterSpacing: '2px',
          lineHeight: 1,
        }}>
          {value}
          {subtext && <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>{subtext}</span>}
        </div>
        {children && <div style={{ marginTop: '8px' }}>{children}</div>}
      </div>
    </IntelCard>
  );
}
