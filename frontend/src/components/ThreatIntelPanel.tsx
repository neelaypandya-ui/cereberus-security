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

const PRIORITY_MAP: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

const IOC_TYPE_FILTERS = ['all', 'ip', 'domain', 'url', 'hash', 'email'];

export function ThreatIntelPanel() {
  const [threatLevel, setThreatLevel] = useState('none');
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [expandedCorr, setExpandedCorr] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'correlations' | 'ioc' | 'feeds'>('correlations');

  // IOC state
  const [iocs, setIocs] = useState<IOCRecord[]>([]);
  const [iocSearch, setIocSearch] = useState('');
  const [iocTypeFilter, setIocTypeFilter] = useState('all');
  const [addIocForm, setAddIocForm] = useState({ ioc_type: 'ip', value: '', source: 'manual', severity: 'medium' });

  // Feed state
  const [feeds, setFeeds] = useState<ThreatFeedRecord[]>([]);

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

  const loadIocs = async () => {
    try {
      const params: Record<string, string> = {};
      if (iocSearch) params.search = iocSearch;
      if (iocTypeFilter !== 'all') params.ioc_type = iocTypeFilter;
      const data = await api.searchIocs(params.search || '');
      setIocs((data as { items: IOCRecord[] }).items || data as IOCRecord[]);
    } catch { /* ignore */ }
  };

  const loadFeeds = async () => {
    try {
      const data = await api.getFeeds();
      setFeeds(data as ThreatFeedRecord[]);
    } catch { /* ignore */ }
  };

  useEffect(() => {
    if (activeTab === 'ioc') loadIocs();
    if (activeTab === 'feeds') loadFeeds();
  }, [activeTab, iocTypeFilter]);

  const handleAddIoc = async () => {
    if (!addIocForm.value.trim()) return;
    try {
      await api.addIoc(addIocForm);
      setAddIocForm({ ...addIocForm, value: '' });
      loadIocs();
    } catch { /* ignore */ }
  };

  const handlePollFeed = async (feedId: number) => {
    try {
      await api.pollFeed(feedId);
      setTimeout(loadFeeds, 2000);
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

  const tabs = [
    { key: 'correlations' as const, label: 'CORRELATIONS' },
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
                  <th style={{ padding: '6px', textAlign: 'left' }}>FIRST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {iocs.length === 0 ? (
                  <tr><td colSpan={5} style={{ padding: '20px', color: 'var(--text-muted)', textAlign: 'center', letterSpacing: '2px' }}>NO INDICATORS LOADED</td></tr>
                ) : iocs.map((ioc) => (
                  <tr key={ioc.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '6px' }}>
                      <span style={{ padding: '2px 6px', background: 'var(--bg-tertiary)', borderRadius: '2px', fontSize: '15px', letterSpacing: '1px' }}>
                        {ioc.ioc_type.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '6px', color: 'var(--cyan-primary)', wordBreak: 'break-all', maxWidth: '300px' }}>{ioc.value}</td>
                    <td style={{ padding: '6px', color: 'var(--text-secondary)' }}>{ioc.source}</td>
                    <td style={{ padding: '6px' }}>
                      <span className={`stamp-badge ${(PRIORITY_MAP[ioc.severity] || PRIORITY_MAP.info).stampClass}`}>
                        {(PRIORITY_MAP[ioc.severity] || PRIORITY_MAP.info).label}
                      </span>
                    </td>
                    <td style={{ padding: '6px', color: 'var(--text-muted)', fontSize: '16px' }}>
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : '-'}
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
