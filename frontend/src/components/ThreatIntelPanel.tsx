import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface Correlation {
  pattern: string;
  threat_level: string;
  description: string;
  matched_event_types: string[];
  matched_events: Array<{
    event_type: string;
    source_module: string;
    severity: string;
    timestamp: string;
    details: Record<string, unknown>;
  }>;
  window: string;
}

interface FeedEvent {
  event_type: string;
  source_module: string;
  severity: string;
  timestamp: string;
  details: Record<string, unknown>;
}

const PRIORITY_MAP: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

export function ThreatIntelPanel() {
  const [threatLevel, setThreatLevel] = useState('none');
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [expandedCorr, setExpandedCorr] = useState<number | null>(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [level, corrs, feedData] = await Promise.all([
        api.getThreatLevel(),
        api.getCorrelations(),
        api.getThreatFeed(),
      ]);
      setThreatLevel((level as { threat_level: string }).threat_level);
      setCorrelations(corrs as Correlation[]);
      setFeed(feedData as FeedEvent[]);
    } catch { /* ignore */ }
  };

  const levelColor = (level: string) => {
    const map: Record<string, string> = {
      none: 'var(--cyan-primary)',
      low: 'var(--status-online)',
      medium: 'var(--amber-primary)',
      high: 'var(--severity-high)',
      critical: 'var(--severity-critical)',
    };
    return map[level] || 'var(--text-muted)';
  };

  const severityColor = (s: string) => {
    const map: Record<string, string> = {
      critical: 'var(--severity-critical)',
      high: 'var(--severity-high)',
      medium: 'var(--severity-medium)',
      low: 'var(--severity-low)',
      info: 'var(--severity-info)',
    };
    return map[s] || 'var(--text-muted)';
  };

  const statusForLevel = (l: string): 'active' | 'warning' | 'critical' => {
    if (l === 'critical') return 'critical';
    if (l === 'high' || l === 'medium') return 'warning';
    return 'active';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Threat Level Indicator Panel */}
      <IntelCard title="FUSION CENTER" classification="TOP SECRET//SCI" status={statusForLevel(threatLevel)}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '20px',
          padding: '12px 0',
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            border: `4px solid ${levelColor(threatLevel)}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '24px',
            boxShadow: `0 0 24px ${levelColor(threatLevel)}40, 0 0 48px ${levelColor(threatLevel)}20`,
            flexShrink: 0,
          }}>
            {threatLevel === 'critical' ? '\u2620' :
             threatLevel === 'high' ? '\u26A0' :
             threatLevel === 'medium' ? '\u25B2' :
             threatLevel === 'low' ? '\u25CF' : '\u2713'}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{
              fontSize: '24px',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              color: levelColor(threatLevel),
              letterSpacing: '4px',
            }}>
              {threatLevel.toUpperCase()}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px', marginTop: '4px' }}>
              OVERALL THREAT ASSESSMENT
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>ACTIVE CORRELATIONS</div>
            <div style={{ fontSize: '28px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
              {correlations.length}
            </div>
          </div>
        </div>
      </IntelCard>

      {/* Intelligence Reports */}
      {correlations.length > 0 && (
        <IntelCard title="INTELLIGENCE REPORTS" classification="TOP SECRET//SCI">
          {correlations.map((corr, i) => (
            <div key={i} style={{ borderBottom: i < correlations.length - 1 ? '1px solid var(--border-default)' : 'none' }}>
              <div
                onClick={() => setExpandedCorr(expandedCorr === i ? null : i)}
                style={{
                  padding: '10px 0',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <span className={`stamp-badge ${(PRIORITY_MAP[corr.threat_level] || PRIORITY_MAP.info).stampClass}`}>
                  {(PRIORITY_MAP[corr.threat_level] || PRIORITY_MAP.info).label}
                </span>
                <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 600, letterSpacing: '1px' }}>
                  {corr.pattern.replace(/_/g, ' ').toUpperCase()}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)', flex: 1 }}>{corr.description}</span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {corr.matched_events.length} events
                </span>
              </div>
              {expandedCorr === i && (
                <div style={{ padding: '8px 12px 14px', background: 'var(--bg-tertiary)', borderRadius: '2px', marginBottom: '8px' }}>
                  {corr.matched_events.map((evt, j) => (
                    <div key={j} className="cable-feed-item" style={{ borderLeft: `2px solid ${severityColor(evt.severity)}`, paddingLeft: '10px' }}>
                      <span style={{ color: severityColor(evt.severity), minWidth: '50px' }}>{evt.severity}</span>
                      <span style={{ color: 'var(--text-primary)' }}>{evt.event_type.replace(/_/g, ' ')}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{evt.source_module}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </IntelCard>
      )}

      {/* Cable Traffic Feed */}
      <IntelCard title="THREAT EVENT FEED" classification="SECRET//SI">
        {feed.length === 0 ? (
          <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
            NO EVENTS IN FEED
          </div>
        ) : (
          <div style={{ maxHeight: '300px', overflow: 'auto' }}>
            {feed.slice(0, 50).map((evt, i) => {
              const pri = PRIORITY_MAP[evt.severity] || PRIORITY_MAP.info;
              const ts = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }) : '';
              return (
                <div key={i} className="cable-feed-item">
                  <span className={`stamp-badge ${pri.stampClass}`} style={{ minWidth: '70px', textAlign: 'center' }}>{pri.label}</span>
                  <span style={{ color: 'var(--text-muted)', minWidth: '65px' }}>{ts}Z</span>
                  <span style={{ color: 'var(--cyan-primary)', minWidth: '90px' }}>{evt.source_module}</span>
                  <span style={{ color: 'var(--text-primary)', flex: 1 }}>{evt.event_type.replace(/_/g, ' ')}</span>
                </div>
              );
            })}
          </div>
        )}
      </IntelCard>
    </div>
  );
}
