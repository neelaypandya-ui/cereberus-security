import { useEffect, useState } from 'react';
import { api } from '../services/api';

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

  return (
    <div>
      {/* Threat Level Display */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        padding: '20px',
        background: 'var(--bg-card)',
        border: `1px solid ${levelColor(threatLevel)}`,
        borderRadius: '8px',
        marginBottom: '20px',
      }}>
        <div style={{
          width: '48px',
          height: '48px',
          borderRadius: '50%',
          border: `3px solid ${levelColor(threatLevel)}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '20px',
          boxShadow: `0 0 20px ${levelColor(threatLevel)}40`,
        }}>
          {threatLevel === 'critical' ? '\u2620' :
           threatLevel === 'high' ? '\u26A0' :
           threatLevel === 'medium' ? '\u25B2' :
           threatLevel === 'low' ? '\u25CF' : '\u2713'}
        </div>
        <div>
          <div style={{
            fontSize: '20px',
            fontWeight: 700,
            fontFamily: 'var(--font-mono)',
            color: levelColor(threatLevel),
            letterSpacing: '2px',
          }}>
            {threatLevel.toUpperCase()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Overall threat assessment
          </div>
        </div>
        <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Active correlations</div>
          <div style={{ fontSize: '24px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {correlations.length}
          </div>
        </div>
      </div>

      {/* Correlated Event Groups */}
      {correlations.length > 0 && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
          marginBottom: '20px',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '12px 16px',
            background: 'var(--bg-tertiary)',
            borderBottom: '1px solid var(--border-default)',
            fontSize: '12px',
            fontWeight: 600,
            letterSpacing: '1px',
          }}>
            ATTACK PATTERN CORRELATIONS
          </div>
          {correlations.map((corr, i) => (
            <div key={i}>
              <div
                onClick={() => setExpandedCorr(expandedCorr === i ? null : i)}
                style={{
                  padding: '12px 16px',
                  borderBottom: '1px solid var(--border-default)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                }}
              >
                <span style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  color: levelColor(corr.threat_level),
                  textTransform: 'uppercase',
                  minWidth: '55px',
                  padding: '2px 6px',
                  borderRadius: '3px',
                  background: `${levelColor(corr.threat_level)}15`,
                }}>
                  {corr.threat_level}
                </span>
                <span style={{ fontSize: '12px', fontWeight: 600 }}>
                  {corr.pattern.replace(/_/g, ' ').toUpperCase()}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)', flex: 1 }}>
                  {corr.description}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {corr.matched_events.length} events
                </span>
              </div>
              {expandedCorr === i && (
                <div style={{ padding: '8px 16px 16px', background: 'var(--bg-tertiary)' }}>
                  {corr.matched_events.map((evt, j) => (
                    <div key={j} style={{
                      display: 'flex',
                      gap: '10px',
                      padding: '6px 10px',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      borderLeft: `2px solid ${severityColor(evt.severity)}`,
                      marginBottom: '4px',
                    }}>
                      <span style={{ color: severityColor(evt.severity), minWidth: '50px' }}>{evt.severity}</span>
                      <span style={{ color: 'var(--text-primary)' }}>{evt.event_type}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{evt.source_module}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Unified Timeline */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 16px',
          background: 'var(--bg-tertiary)',
          borderBottom: '1px solid var(--border-default)',
          fontSize: '12px',
          fontWeight: 600,
          letterSpacing: '1px',
        }}>
          THREAT EVENT FEED
        </div>
        {feed.length === 0 ? (
          <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
            No events in feed
          </div>
        ) : (
          feed.slice(0, 50).map((evt, i) => (
            <div key={i} style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '8px 16px',
              borderBottom: '1px solid var(--border-default)',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
            }}>
              <span style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: severityColor(evt.severity),
                flexShrink: 0,
              }} />
              <span style={{ color: 'var(--text-muted)', minWidth: '60px' }}>{evt.source_module}</span>
              <span style={{ color: 'var(--text-primary)', flex: 1 }}>{evt.event_type.replace(/_/g, ' ')}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>
                {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : ''}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
