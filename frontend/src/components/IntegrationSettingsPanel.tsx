import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

type Tab = 'channels' | 'feeds' | 'exports';

interface Channel {
  id: number;
  name: string;
  channel_type: string;
  config: Record<string, unknown>;
  enabled: boolean;
  events: string[];
  created_at: string;
}

interface Feed {
  id: number;
  name: string;
  feed_type: string;
  url: string | null;
  enabled: boolean;
  poll_interval_seconds: number;
  last_polled: string | null;
  last_success: string | null;
  items_count: number;
  created_at: string;
}

interface ExportJobData {
  id: number;
  export_type: string;
  format: string;
  status: string;
  requested_at: string;
  completed_at: string | null;
  file_size_bytes: number | null;
  error_message: string | null;
}

const EVENT_TYPES = [
  'alert_critical', 'alert_high', 'incident_created', 'playbook_fired',
  'feed_updated', 'ioc_match', 'system_error',
];

const CHANNEL_TYPES = ['webhook', 'smtp', 'desktop'];

export function IntegrationSettingsPanel() {
  const [tab, setTab] = useState<Tab>('channels');
  const [channels, setChannels] = useState<Channel[]>([]);
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [exports, setExports] = useState<ExportJobData[]>([]);

  // Channel form
  const [showChannelForm, setShowChannelForm] = useState(false);
  const [chName, setChName] = useState('');
  const [chType, setChType] = useState('webhook');
  const [chUrl, setChUrl] = useState('');
  const [chEvents, setChEvents] = useState<string[]>(['alert_critical']);

  // Feed form
  const [showFeedForm, setShowFeedForm] = useState(false);
  const [fdName, setFdName] = useState('');
  const [fdType, setFdType] = useState('urlhaus');
  const [fdUrl, setFdUrl] = useState('');
  const [fdApiKey, setFdApiKey] = useState('');

  // Export form
  const [expType, setExpType] = useState('alerts');
  const [expFormat, setExpFormat] = useState('csv');

  const loadChannels = useCallback(async () => {
    try { setChannels(await api.getNotificationChannels() as Channel[]); } catch { /* */ }
  }, []);

  const loadFeeds = useCallback(async () => {
    try { setFeeds(await api.getFeeds() as Feed[]); } catch { /* */ }
  }, []);

  const loadExports = useCallback(async () => {
    try { setExports(await api.getExportJobs() as ExportJobData[]); } catch { /* */ }
  }, []);

  useEffect(() => {
    if (tab === 'channels') loadChannels();
    if (tab === 'feeds') loadFeeds();
    if (tab === 'exports') loadExports();
  }, [tab, loadChannels, loadFeeds, loadExports]);

  const createChannel = async () => {
    if (!chName) return;
    try {
      await api.createNotificationChannel({
        name: chName, channel_type: chType,
        config: chType === 'webhook' ? { url: chUrl } : {},
        enabled: true, events: chEvents,
      });
      setShowChannelForm(false);
      setChName('');
      loadChannels();
    } catch { /* */ }
  };

  const createFeed = async () => {
    if (!fdName) return;
    try {
      await api.createFeed({
        name: fdName, feed_type: fdType, url: fdUrl || undefined,
        api_key: fdApiKey || undefined, enabled: false,
      });
      setShowFeedForm(false);
      setFdName('');
      loadFeeds();
    } catch { /* */ }
  };

  const requestExport = async () => {
    try {
      await api.requestExport({ export_type: expType, format: expFormat });
      loadExports();
    } catch { /* */ }
  };

  const tabStyle = (t: Tab) => ({
    padding: '6px 16px', fontFamily: 'var(--font-mono)' as const, fontSize: '16px',
    letterSpacing: '1px' as const, cursor: 'pointer' as const, border: 'none' as const,
    borderBottom: tab === t ? '2px solid var(--cyan-primary)' : '2px solid transparent',
    background: 'transparent' as const,
    color: tab === t ? 'var(--cyan-primary)' : 'var(--text-muted)',
  });

  return (
    <IntelCard title="SIGNAL RELAY" classification="SECRET">
      {/* Tabs */}
      <div style={{ display: 'flex', gap: '4px', borderBottom: '1px solid var(--border-default)', marginBottom: '16px' }}>
        <button style={tabStyle('channels')} onClick={() => setTab('channels')}>NOTIFICATION CHANNELS</button>
        <button style={tabStyle('feeds')} onClick={() => setTab('feeds')}>THREAT FEED CONFIG</button>
        <button style={tabStyle('exports')} onClick={() => setTab('exports')}>EXPORT CENTER</button>
      </div>

      {/* Channels Tab */}
      {tab === 'channels' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-muted)' }}>{channels.length} CHANNELS</span>
            <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowChannelForm(!showChannelForm)}>+ ADD CHANNEL</button>
          </div>
          {showChannelForm && (
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '12px', borderRadius: '2px' }}>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                <input className="terminal-input" placeholder="Name..." value={chName} onChange={e => setChName(e.target.value)} style={{ flex: 1, padding: '6px 8px', fontSize: '17px' }} />
                <select className="terminal-input" value={chType} onChange={e => setChType(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
                  {CHANNEL_TYPES.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                </select>
              </div>
              {chType === 'webhook' && (
                <input className="terminal-input" placeholder="Webhook URL..." value={chUrl} onChange={e => setChUrl(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '17px', marginBottom: '8px', boxSizing: 'border-box' }} />
              )}
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--text-muted)', marginBottom: '4px' }}>SUBSCRIBE TO EVENTS:</div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '8px' }}>
                {EVENT_TYPES.map(et => (
                  <label key={et} style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <input type="checkbox" checked={chEvents.includes(et)} onChange={e => {
                      if (e.target.checked) setChEvents([...chEvents, et]);
                      else setChEvents(chEvents.filter(x => x !== et));
                    }} />
                    {et}
                  </label>
                ))}
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={createChannel}>CREATE</button>
                <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowChannelForm(false)}>CANCEL</button>
              </div>
            </div>
          )}
          {channels.map(ch => (
            <div key={ch.id} style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '10px 14px', marginBottom: '6px', borderRadius: '2px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: ch.enabled ? 'var(--status-online)' : 'var(--text-muted)' }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>{ch.name}</span>
                  <span className="stamp-badge stamp-advisory" style={{ fontSize: '13px' }}>{ch.channel_type.toUpperCase()}</span>
                </div>
                <div style={{ display: 'flex', gap: '4px' }}>
                  <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={async () => { try { await api.testNotificationChannel(ch.id); } catch { /* */ } }}>TEST</button>
                  <button className="stamp-badge stamp-hostile" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={async () => { try { await api.deleteNotificationChannel(ch.id); loadChannels(); } catch { /* */ } }}>DELETE</button>
                </div>
              </div>
              <div style={{ marginTop: '4px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {ch.events.map(e => <span key={e} className="stamp-badge stamp-suspect" style={{ fontSize: '13px' }}>{e}</span>)}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Feeds Tab */}
      {tab === 'feeds' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-muted)' }}>{feeds.length} FEEDS</span>
            <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowFeedForm(!showFeedForm)}>+ ADD FEED</button>
          </div>
          {showFeedForm && (
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '12px', borderRadius: '2px' }}>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                <input className="terminal-input" placeholder="Feed name..." value={fdName} onChange={e => setFdName(e.target.value)} style={{ flex: 1, padding: '6px 8px', fontSize: '17px' }} />
                <select className="terminal-input" value={fdType} onChange={e => setFdType(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
                  <option value="virustotal">VIRUSTOTAL</option>
                  <option value="abuseipdb">ABUSEIPDB</option>
                  <option value="urlhaus">URLHAUS</option>
                  <option value="custom_api">CUSTOM API</option>
                </select>
              </div>
              <input className="terminal-input" placeholder="Feed URL..." value={fdUrl} onChange={e => setFdUrl(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '17px', marginBottom: '8px', boxSizing: 'border-box' }} />
              <input className="terminal-input" placeholder="API Key (optional)..." value={fdApiKey} onChange={e => setFdApiKey(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '17px', marginBottom: '8px', boxSizing: 'border-box' }} type="password" />
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={createFeed}>CREATE</button>
                <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowFeedForm(false)}>CANCEL</button>
              </div>
            </div>
          )}
          {feeds.map(fd => (
            <div key={fd.id} style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '10px 14px', marginBottom: '6px', borderRadius: '2px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: fd.enabled ? 'var(--status-online)' : 'var(--text-muted)' }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>{fd.name}</span>
                  <span className="stamp-badge stamp-advisory" style={{ fontSize: '13px' }}>{fd.feed_type.toUpperCase()}</span>
                </div>
                <div style={{ display: 'flex', gap: '4px' }}>
                  <button className="stamp-badge stamp-priority" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={async () => { try { await api.pollFeed(fd.id); loadFeeds(); } catch { /* */ } }}>POLL NOW</button>
                  <button className="stamp-badge stamp-hostile" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={async () => { try { await api.deleteFeed(fd.id); loadFeeds(); } catch { /* */ } }}>DELETE</button>
                </div>
              </div>
              <div style={{ marginTop: '4px', fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', display: 'flex', gap: '12px' }}>
                <span>ITEMS: <span style={{ color: 'var(--cyan-primary)' }}>{fd.items_count}</span></span>
                <span>INTERVAL: {fd.poll_interval_seconds}s</span>
                {fd.last_polled && <span>LAST POLLED: {new Date(fd.last_polled).toLocaleString('en-US', { hour12: false })}</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Exports Tab */}
      {tab === 'exports' && (
        <div>
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '16px', borderRadius: '2px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>REQUEST EXPORT</div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <select className="terminal-input" value={expType} onChange={e => setExpType(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
                <option value="alerts">ALERTS</option>
                <option value="incidents">INCIDENTS</option>
                <option value="audit">AUDIT LOGS</option>
                <option value="iocs">IOCs</option>
                <option value="full_report">FULL REPORT</option>
              </select>
              <select className="terminal-input" value={expFormat} onChange={e => setExpFormat(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
              </select>
              <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={requestExport}>EXPORT</button>
            </div>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>EXPORT HISTORY</div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '17px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-default)' }}>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>TYPE</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>FORMAT</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>STATUS</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>REQUESTED</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>SIZE</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {exports.map(ex => (
                <tr key={ex.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '6px', color: 'var(--text-primary)' }}>{ex.export_type.toUpperCase()}</td>
                  <td style={{ padding: '6px', color: 'var(--cyan-primary)' }}>{ex.format.toUpperCase()}</td>
                  <td style={{ padding: '6px' }}>
                    <span style={{ color: ex.status === 'completed' ? 'var(--status-online)' : ex.status === 'failed' ? 'var(--severity-critical)' : 'var(--amber-primary)' }}>
                      {ex.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '6px', color: 'var(--text-muted)', fontSize: '16px' }}>{new Date(ex.requested_at).toLocaleString('en-US', { hour12: false })}</td>
                  <td style={{ padding: '6px', color: 'var(--text-muted)' }}>{ex.file_size_bytes ? `${(ex.file_size_bytes / 1024).toFixed(1)} KB` : '—'}</td>
                  <td style={{ padding: '6px' }}>
                    {ex.status === 'completed' && (
                      <button className="stamp-badge stamp-cleared" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => api.downloadExport(ex.id)}>DOWNLOAD</button>
                    )}
                  </td>
                </tr>
              ))}
              {exports.length === 0 && (
                <tr><td colSpan={6} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>NO EXPORTS</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </IntelCard>
  );
}
