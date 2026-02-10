import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';
import { CopyButton } from './ui/CopyButton';

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

interface IOCRecord {
  id: number;
  ioc_type: string;
  value: string;
  source: string;
  severity: string;
  first_seen: string;
  last_seen: string;
  tags_json: string;
  active: boolean;
  confidence: number | null;
  false_positive: boolean;
  false_positive_reason: string | null;
  false_positive_by: string | null;
  false_positive_at: string | null;
  hit_count: number;
  last_hit_at: string | null;
  expires_at: string | null;
}

interface ThreatFeedRecord {
  id: number;
  name: string;
  feed_type: string;
  enabled: boolean;
  last_polled: string | null;
  last_success: string | null;
  items_count: number;
  poll_interval_seconds: number;
}

interface BondThreat {
  id: string;
  name: string;
  description: string;
  severity: string;
  category: string;
  source: string;
  iocs: Array<{ type: string; value: string }>;
  mitigation: string;
  cvss_score: number | null;
}

const PRIORITY_MAP: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

const IOC_TYPE_FILTERS = ['all', 'ip', 'domain', 'url', 'hash', 'email'];

export function ThreatIntelPanel() {
  const { showToast } = useToast();
  const [threatLevel, setThreatLevel] = useState('none');
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [expandedCorr, setExpandedCorr] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'correlations' | 'threats' | 'ioc' | 'feeds' | 'timeline'>('correlations');

  // IOC state
  const [iocs, setIocs] = useState<IOCRecord[]>([]);
  const [iocSearch, setIocSearch] = useState('');
  const [iocTypeFilter, setIocTypeFilter] = useState('all');
  const [addIocForm, setAddIocForm] = useState({ ioc_type: 'ip', value: '', source: 'manual', severity: 'medium' });

  // Feed state
  const [feeds, setFeeds] = useState<ThreatFeedRecord[]>([]);

  // Threats state (Bond threats — for neutralization)
  const [threats, setThreats] = useState<BondThreat[]>([]);
  const [threatsLoading, setThreatsLoading] = useState(false);
  const [neutralizingId, setNeutralizingId] = useState<string | null>(null);
  const [neutralizingAll, setNeutralizingAll] = useState(false);

  // Timeline state
  interface TimelineEvent {
    timestamp: string;
    event_type: string;
    source_module: string;
    severity: string;
    details: Record<string, unknown>;
  }
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [timelineLookback, setTimelineLookback] = useState(60);
  const [expandedTimelineIdx, setExpandedTimelineIdx] = useState<number | null>(null);

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
    } catch (e: unknown) { showToast('error', 'Failed to load threat intel', (e as Error).message); }
  };

  const loadIocs = async () => {
    try {
      const params: Record<string, string> = {};
      if (iocSearch) params.search = iocSearch;
      if (iocTypeFilter !== 'all') params.ioc_type = iocTypeFilter;
      const data = await api.searchIocs(params.search || '');
      setIocs((data as { items: IOCRecord[] }).items || data as IOCRecord[]);
    } catch (e: unknown) { showToast('error', 'Failed to load IOCs', (e as Error).message); }
  };

  const loadFeeds = async () => {
    try {
      const data = await api.getFeeds();
      setFeeds(data as ThreatFeedRecord[]);
    } catch (e: unknown) { showToast('error', 'Failed to load feeds', (e as Error).message); }
  };

  const loadTimeline = async () => {
    try {
      const data = await api.getThreatTimeline(timelineLookback);
      setTimelineEvents((data as { timeline: TimelineEvent[] }).timeline || []);
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  useEffect(() => {
    if (activeTab === 'ioc') loadIocs();
    if (activeTab === 'feeds') loadFeeds();
    if (activeTab === 'timeline') loadTimeline();
    if (activeTab === 'threats') loadThreats();
  }, [activeTab, iocTypeFilter, timelineLookback]);

  const handleAddIoc = async () => {
    if (!addIocForm.value.trim()) return;
    try {
      await api.addIoc(addIocForm);
      setAddIocForm({ ...addIocForm, value: '' });
      loadIocs();
      showToast('success', 'IOC added successfully');
    } catch (e: unknown) { showToast('error', 'Failed to add IOC', (e as Error).message); }
  };

  const handlePollFeed = async (feedId: number) => {
    try {
      await api.pollFeed(feedId);
      showToast('info', 'Feed poll initiated');
      setTimeout(loadFeeds, 2000);
    } catch (e: unknown) { showToast('error', 'Failed to poll feed', (e as Error).message); }
  };

  const handleToggleFalsePositive = async (ioc: IOCRecord) => {
    try {
      if (ioc.false_positive) {
        await api.unmarkIocFalsePositive(ioc.id);
        showToast('success', 'False positive marking removed');
      } else {
        await api.markIocFalsePositive(ioc.id, 'Manually flagged via UI');
        showToast('success', 'Marked as false positive');
      }
      loadIocs();
    } catch (e: unknown) { showToast('error', 'Failed to update IOC', (e as Error).message); }
  };

  const loadThreats = async () => {
    setThreatsLoading(true);
    try {
      const data = await api.getBondThreats({}) as BondThreat[];
      setThreats(data);
    } catch (e: unknown) { showToast('error', 'Failed to load threats', (e as Error).message); } finally {
      setThreatsLoading(false);
    }
  };

  const handleNeutralize = async (threatId: string) => {
    setNeutralizingId(threatId);
    try {
      await api.neutralizeBondThreat(threatId);
      setThreats(prev => prev.filter(t => t.id !== threatId));
      showToast('success', 'Threat neutralized');
    } catch (e: unknown) { showToast('error', 'Failed to neutralize threat', (e as Error).message); } finally {
      setNeutralizingId(null);
    }
  };

  const handleNeutralizeAll = async () => {
    setNeutralizingAll(true);
    try {
      await api.neutralizeAllBondThreats();
      setThreats([]);
      showToast('success', 'All threats neutralized');
    } catch (e: unknown) { showToast('error', 'Failed to neutralize threats', (e as Error).message); } finally {
      setNeutralizingAll(false);
    }
  };

  const confidenceColor = (c: number | null): string => {
    if (c === null || c === undefined) return 'var(--text-muted)';
    if (c >= 80) return 'var(--severity-critical)';
    if (c >= 60) return 'var(--severity-high)';
    if (c >= 40) return 'var(--severity-medium)';
    if (c >= 20) return 'var(--severity-low)';
    return 'var(--severity-info)';
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

  const tabs = [
    { key: 'correlations' as const, label: 'CORRELATIONS' },
    { key: 'threats' as const, label: 'ACTIVE THREATS' },
    { key: 'timeline' as const, label: 'TIMELINE' },
    { key: 'ioc' as const, label: 'IOC DATABASE' },
    { key: 'feeds' as const, label: 'FEED STATUS' },
  ];

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
            fontSize: '30px',
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
              fontSize: '30px',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              color: levelColor(threatLevel),
              letterSpacing: '4px',
            }}>
              {threatLevel.toUpperCase()}
            </div>
            <div style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px', marginTop: '4px' }}>
              OVERALL THREAT ASSESSMENT
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>ACTIVE CORRELATIONS</div>
            <div style={{ fontSize: '34px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
              {correlations.length}
            </div>
          </div>
        </div>
      </IntelCard>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: '2px', background: 'var(--bg-secondary)', borderRadius: '2px', padding: '2px' }}>
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              flex: 1,
              padding: '8px',
              border: 'none',
              background: activeTab === tab.key ? 'var(--bg-tertiary)' : 'transparent',
              color: activeTab === tab.key ? 'var(--cyan-primary)' : 'var(--text-muted)',
              fontSize: '16px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              letterSpacing: '2px',
              cursor: 'pointer',
              borderBottom: activeTab === tab.key ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* CORRELATIONS TAB */}
      {activeTab === 'correlations' && (
        <>
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
                    <span style={{ fontSize: '18px', fontFamily: 'var(--font-mono)', fontWeight: 600, letterSpacing: '1px' }}>
                      {corr.pattern.replace(/_/g, ' ').toUpperCase()}
                    </span>
                    <span style={{ fontSize: '17px', color: 'var(--text-secondary)', flex: 1 }}>{corr.description}</span>
                    <span style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
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

          <IntelCard title="THREAT EVENT FEED" classification="SECRET//SI">
            {feed.length === 0 ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
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
        </>
      )}

      {/* ACTIVE THREATS TAB */}
      {activeTab === 'threats' && (
        <IntelCard title="ACTIVE THREAT DOSSIERS" classification="TOP SECRET//SCI">
          {threatsLoading ? (
            <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
              RETRIEVING THREAT INTELLIGENCE...
            </div>
          ) : threats.length === 0 ? (
            <div style={{ padding: '30px', color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
              NO ACTIVE THREATS — ALL CLEAR
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                  {threats.length} ACTIVE THREAT{threats.length !== 1 ? 'S' : ''}
                </span>
                <button
                  onClick={handleNeutralizeAll}
                  disabled={neutralizingAll}
                  style={{
                    padding: '6px 18px',
                    background: 'transparent',
                    border: '1px solid var(--severity-critical)',
                    color: 'var(--severity-critical)',
                    fontSize: '14px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    letterSpacing: '2px',
                    cursor: neutralizingAll ? 'not-allowed' : 'pointer',
                    opacity: neutralizingAll ? 0.5 : 1,
                  }}
                >
                  {neutralizingAll ? 'NEUTRALIZING...' : 'NEUTRALIZE ALL'}
                </button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '500px', overflow: 'auto' }}>
                {threats.map((threat) => {
                  const sev = PRIORITY_MAP[threat.severity] || PRIORITY_MAP.info;
                  return (
                    <div key={threat.id} style={{
                      padding: '12px',
                      background: 'var(--bg-tertiary)',
                      borderRadius: '2px',
                      borderLeft: `3px solid ${severityColor(threat.severity)}`,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                        <span className={`stamp-badge ${sev.stampClass}`}>{sev.label}</span>
                        <span style={{ fontSize: '18px', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '1px', color: 'var(--text-primary)', flex: 1 }}>
                          {threat.name}
                        </span>
                        {threat.cvss_score != null && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: threat.cvss_score >= 9 ? 'var(--severity-critical)' : threat.cvss_score >= 7 ? 'var(--severity-high)' : 'var(--severity-medium)' }}>
                            CVSS {threat.cvss_score}
                          </span>
                        )}
                        <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                          {threat.category.toUpperCase()}
                        </span>
                        <button
                          onClick={() => handleNeutralize(threat.id)}
                          disabled={neutralizingId === threat.id}
                          style={{
                            padding: '4px 14px',
                            background: 'transparent',
                            border: '1px solid var(--severity-critical)',
                            color: 'var(--severity-critical)',
                            fontSize: '13px',
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            letterSpacing: '1px',
                            cursor: neutralizingId === threat.id ? 'not-allowed' : 'pointer',
                            opacity: neutralizingId === threat.id ? 0.5 : 1,
                            flexShrink: 0,
                          }}
                        >
                          {neutralizingId === threat.id ? 'NEUTRALIZING...' : 'NEUTRALIZE'}
                        </button>
                      </div>
                      <div style={{ fontSize: '16px', color: 'var(--text-secondary)', marginBottom: '6px', lineHeight: 1.5 }}>
                        {threat.description}
                      </div>
                      {threat.mitigation && (
                        <div style={{ fontSize: '15px', color: 'var(--cyan-primary)', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                          MITIGATION: {threat.mitigation}
                        </div>
                      )}
                      <div style={{ fontSize: '14px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        SOURCE: {threat.source} | IOCs: {threat.iocs?.length || 0}
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </IntelCard>
      )}

      {/* TIMELINE TAB */}
      {activeTab === 'timeline' && (
        <IntelCard title="THREAT EVENT TIMELINE" classification="SECRET//SI">
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px' }}>LOOKBACK:</span>
            {[15, 30, 60, 120, 480].map(mins => (
              <button
                key={mins}
                onClick={() => setTimelineLookback(mins)}
                style={{
                  padding: '4px 8px',
                  border: '1px solid var(--border-default)',
                  background: timelineLookback === mins ? 'var(--cyan-primary)' : 'transparent',
                  color: timelineLookback === mins ? 'var(--bg-primary)' : 'var(--text-muted)',
                  fontSize: '15px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  cursor: 'pointer',
                  letterSpacing: '1px',
                }}
              >
                {mins < 60 ? `${mins}m` : `${mins / 60}h`}
              </button>
            ))}
            <button
              onClick={loadTimeline}
              style={{
                marginLeft: 'auto',
                padding: '4px 10px',
                background: 'var(--amber-primary)',
                border: 'none',
                color: 'var(--bg-primary)',
                fontSize: '15px',
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                cursor: 'pointer',
                letterSpacing: '1px',
              }}
            >
              REFRESH
            </button>
          </div>

          {timelineEvents.length === 0 ? (
            <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
              NO EVENTS IN TIMELINE WINDOW
            </div>
          ) : (
            <div style={{ maxHeight: '500px', overflow: 'auto' }}>
              {timelineEvents.map((evt, i) => {
                const ts = new Date(evt.timestamp);
                const prevTs = i > 0 ? new Date(timelineEvents[i - 1].timestamp) : null;
                const deltaMs = prevTs ? ts.getTime() - prevTs.getTime() : 0;
                const deltaSec = Math.floor(deltaMs / 1000);
                const deltaStr = i === 0 ? '' : deltaSec < 60 ? `+${deltaSec}s` : deltaSec < 3600 ? `+${Math.floor(deltaSec / 60)}m ${deltaSec % 60}s` : `+${Math.floor(deltaSec / 3600)}h ${Math.floor((deltaSec % 3600) / 60)}m`;
                const isExpanded = expandedTimelineIdx === i;

                return (
                  <div
                    key={i}
                    onClick={() => setExpandedTimelineIdx(isExpanded ? null : i)}
                    style={{
                      display: 'flex',
                      gap: '10px',
                      padding: '8px 0',
                      borderLeft: `3px solid ${severityColor(evt.severity)}`,
                      paddingLeft: '12px',
                      marginBottom: '2px',
                      cursor: 'pointer',
                      background: isExpanded ? 'var(--bg-tertiary)' : 'transparent',
                      flexDirection: 'column',
                    }}
                  >
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', minWidth: '75px' }}>
                        {ts.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
                      </span>
                      {deltaStr && (
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '13px',
                          color: deltaSec > 300 ? 'var(--severity-medium)' : 'var(--text-muted)',
                          minWidth: '60px',
                        }}>
                          {deltaStr}
                        </span>
                      )}
                      <span style={{
                        padding: '2px 8px',
                        background: `${severityColor(evt.severity)}20`,
                        border: `1px solid ${severityColor(evt.severity)}`,
                        color: severityColor(evt.severity),
                        fontSize: '14px',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        letterSpacing: '1px',
                        borderRadius: '2px',
                      }}>
                        {evt.event_type.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--cyan-primary)' }}>
                        {evt.source_module}
                      </span>
                      <span className={`stamp-badge ${(PRIORITY_MAP[evt.severity] || PRIORITY_MAP.info).stampClass}`} style={{ fontSize: '13px', marginLeft: 'auto' }}>
                        {evt.severity.toUpperCase()}
                      </span>
                    </div>
                    {isExpanded && evt.details && Object.keys(evt.details).length > 0 && (
                      <div style={{
                        marginTop: '4px',
                        padding: '8px',
                        background: 'var(--bg-secondary)',
                        borderRadius: '2px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '14px',
                        color: 'var(--text-secondary)',
                        wordBreak: 'break-all',
                      }}>
                        {Object.entries(evt.details).map(([k, v]) => (
                          <div key={k} style={{ marginBottom: '2px' }}>
                            <span style={{ color: 'var(--text-muted)' }}>{k}: </span>
                            <span>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </IntelCard>
      )}

      {/* IOC DATABASE TAB */}
      {activeTab === 'ioc' && (
        <IntelCard title="INDICATORS OF COMPROMISE" classification="SECRET//SI">
          {/* Search and Filter */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}>
            <input
              className="terminal-input"
              value={iocSearch}
              onChange={(e) => setIocSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadIocs()}
              placeholder="Search IOCs..."
              style={{ flex: 1, padding: '6px 10px', fontSize: '17px' }}
            />
            <div style={{ display: 'flex', gap: '2px' }}>
              {IOC_TYPE_FILTERS.map(t => (
                <button
                  key={t}
                  onClick={() => setIocTypeFilter(t)}
                  style={{
                    padding: '4px 8px',
                    border: '1px solid var(--border-default)',
                    background: iocTypeFilter === t ? 'var(--cyan-primary)' : 'transparent',
                    color: iocTypeFilter === t ? 'var(--bg-primary)' : 'var(--text-muted)',
                    fontSize: '15px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    letterSpacing: '1px',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                  }}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Manual Add Form */}
          <div style={{ display: 'flex', gap: '6px', marginBottom: '12px', alignItems: 'center', padding: '8px', background: 'var(--bg-tertiary)', borderRadius: '2px' }}>
            <select
              value={addIocForm.ioc_type}
              onChange={(e) => setAddIocForm({ ...addIocForm, ioc_type: e.target.value })}
              style={{ padding: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border-default)', color: 'var(--text-primary)', fontSize: '16px', fontFamily: 'var(--font-mono)' }}
            >
              <option value="ip">IP</option>
              <option value="domain">DOMAIN</option>
              <option value="url">URL</option>
              <option value="hash">HASH</option>
              <option value="email">EMAIL</option>
            </select>
            <input
              className="terminal-input"
              value={addIocForm.value}
              onChange={(e) => setAddIocForm({ ...addIocForm, value: e.target.value })}
              placeholder="Enter indicator value..."
              style={{ flex: 1, padding: '4px 8px', fontSize: '16px' }}
            />
            <select
              value={addIocForm.severity}
              onChange={(e) => setAddIocForm({ ...addIocForm, severity: e.target.value })}
              style={{ padding: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border-default)', color: 'var(--text-primary)', fontSize: '16px', fontFamily: 'var(--font-mono)' }}
            >
              <option value="critical">CRITICAL</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
            </select>
            <button
              onClick={handleAddIoc}
              style={{
                padding: '4px 12px',
                background: 'var(--cyan-primary)',
                border: 'none',
                color: 'var(--bg-primary)',
                fontSize: '16px',
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                cursor: 'pointer',
                letterSpacing: '1px',
              }}
            >
              + ADD
            </button>
          </div>

          {/* IOC Table */}
          <div style={{ maxHeight: '400px', overflow: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '17px', fontFamily: 'var(--font-mono)' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-default)', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '2px' }}>
                  <th style={{ padding: '6px', textAlign: 'left' }}>TYPE</th>
                  <th style={{ padding: '6px', textAlign: 'left' }}>VALUE</th>
                  <th style={{ padding: '6px', textAlign: 'left' }}>SOURCE</th>
                  <th style={{ padding: '6px', textAlign: 'left' }}>SEVERITY</th>
                  <th style={{ padding: '6px', textAlign: 'left' }}>CONF</th>
                  <th style={{ padding: '6px', textAlign: 'left' }}>HITS</th>
                  <th style={{ padding: '6px', textAlign: 'left' }}>FIRST SEEN</th>
                  <th style={{ padding: '6px', textAlign: 'center' }}>FP</th>
                </tr>
              </thead>
              <tbody>
                {iocs.length === 0 ? (
                  <tr><td colSpan={8} style={{ padding: '20px', color: 'var(--text-muted)', textAlign: 'center', letterSpacing: '2px' }}>NO INDICATORS LOADED</td></tr>
                ) : iocs.map((ioc) => (
                  <tr key={ioc.id} style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    opacity: ioc.false_positive ? 0.5 : 1,
                  }}>
                    <td style={{ padding: '6px' }}>
                      <span style={{ padding: '2px 6px', background: 'var(--bg-tertiary)', borderRadius: '2px', fontSize: '15px', letterSpacing: '1px' }}>
                        {ioc.ioc_type.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '6px', color: ioc.false_positive ? 'var(--text-muted)' : 'var(--cyan-primary)', wordBreak: 'break-all', maxWidth: '250px', textDecoration: ioc.false_positive ? 'line-through' : 'none' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '2px' }}>
                        {ioc.value}
                        <CopyButton value={ioc.value} label={`Copy IOC ${ioc.value}`} />
                      </span>
                    </td>
                    <td style={{ padding: '6px', color: 'var(--text-secondary)' }}>{ioc.source}</td>
                    <td style={{ padding: '6px' }}>
                      <span className={`stamp-badge ${(PRIORITY_MAP[ioc.severity] || PRIORITY_MAP.info).stampClass}`}>
                        {(PRIORITY_MAP[ioc.severity] || PRIORITY_MAP.info).label}
                      </span>
                    </td>
                    <td style={{ padding: '6px' }}>
                      {ioc.confidence !== null && ioc.confidence !== undefined ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <div style={{
                            width: '40px',
                            height: '6px',
                            background: 'var(--bg-secondary)',
                            borderRadius: '3px',
                            overflow: 'hidden',
                          }}>
                            <div style={{
                              width: `${ioc.confidence}%`,
                              height: '100%',
                              background: confidenceColor(ioc.confidence),
                              borderRadius: '3px',
                            }} />
                          </div>
                          <span style={{ fontSize: '14px', color: confidenceColor(ioc.confidence) }}>
                            {ioc.confidence}
                          </span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '14px' }}>--</span>
                      )}
                    </td>
                    <td style={{ padding: '6px', color: (ioc.hit_count || 0) > 0 ? 'var(--amber-primary)' : 'var(--text-muted)', fontSize: '15px' }}>
                      {ioc.hit_count || 0}
                    </td>
                    <td style={{ padding: '6px', color: 'var(--text-muted)', fontSize: '16px' }}>
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : '-'}
                    </td>
                    <td style={{ padding: '6px', textAlign: 'center' }}>
                      <button
                        onClick={() => handleToggleFalsePositive(ioc)}
                        title={ioc.false_positive ? `FP by ${ioc.false_positive_by || '?'}: ${ioc.false_positive_reason || 'no reason'}` : 'Mark as false positive'}
                        style={{
                          padding: '2px 6px',
                          border: `1px solid ${ioc.false_positive ? 'var(--severity-medium)' : 'var(--border-default)'}`,
                          background: ioc.false_positive ? 'var(--severity-medium)' : 'transparent',
                          color: ioc.false_positive ? 'var(--bg-primary)' : 'var(--text-muted)',
                          fontSize: '13px',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          cursor: 'pointer',
                          borderRadius: '2px',
                          letterSpacing: '1px',
                        }}
                      >
                        FP
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </IntelCard>
      )}

      {/* FEED STATUS TAB */}
      {activeTab === 'feeds' && (
        <IntelCard title="THREAT FEED OPERATIONS" classification="SECRET//SI">
          {feeds.length === 0 ? (
            <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
              NO FEEDS CONFIGURED
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {feeds.map((f) => (
                <div key={f.id} style={{
                  padding: '12px',
                  background: 'var(--bg-tertiary)',
                  borderRadius: '2px',
                  borderLeft: `3px solid ${f.enabled ? 'var(--status-online)' : 'var(--text-muted)'}`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontSize: '18px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '1px' }}>
                        {f.name}
                      </div>
                      <div style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                        TYPE: {f.feed_type.toUpperCase()} | INTERVAL: {Math.floor(f.poll_interval_seconds / 60)}m | ITEMS: {f.items_count}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <div style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        background: f.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                        boxShadow: f.enabled ? '0 0 8px var(--status-online)' : 'none',
                      }} />
                      <span style={{ fontSize: '16px', fontFamily: 'var(--font-mono)', color: f.enabled ? 'var(--status-online)' : 'var(--text-muted)' }}>
                        {f.enabled ? 'ACTIVE' : 'DISABLED'}
                      </span>
                      <button
                        onClick={() => handlePollFeed(f.id)}
                        disabled={!f.enabled}
                        style={{
                          padding: '4px 10px',
                          background: f.enabled ? 'var(--amber-primary)' : 'var(--bg-secondary)',
                          border: 'none',
                          color: f.enabled ? 'var(--bg-primary)' : 'var(--text-muted)',
                          fontSize: '15px',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          cursor: f.enabled ? 'pointer' : 'not-allowed',
                          letterSpacing: '1px',
                        }}
                      >
                        POLL NOW
                      </button>
                    </div>
                  </div>
                  <div style={{ fontSize: '15px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '6px' }}>
                    LAST POLLED: {f.last_polled ? new Date(f.last_polled).toLocaleString() : 'NEVER'} |
                    LAST SUCCESS: {f.last_success ? new Date(f.last_success).toLocaleString() : 'NEVER'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </IntelCard>
      )}
    </div>
  );
}
