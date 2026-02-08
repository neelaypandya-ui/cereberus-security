import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

// --- Types ---

interface BondStatus {
  state: 'scanning' | 'idle' | 'offline';
  last_scan: string | null;
  next_scan: string | null;
  threat_count: number;
  scan_interval_seconds: number;
}

interface BondThreat {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  source: string;
  bond_assessment: string;
  iocs: string[];
  cereberus_prompt: string;
  mitre_techniques?: string[];
  raw?: Record<string, unknown>;
}

interface BondReport {
  id: string;
  timestamp: string;
  summary: string;
  threat_count: number;
  status: string;
  threats: BondThreat[];
  scan_duration_seconds?: number;
  all_clear?: boolean;
}

// get_latest_report() returns a flat report dict (same shape as BondReport), not { report, threats }
type BondLatest = BondReport;

interface ScanResult {
  scan_id: string;
  started_at: string;
  duration_seconds?: number;
}

// --- Constants ---

const BOND_GOLD = '#C9A84C';

const STATUS_LABELS: Record<string, string> = {
  scanning: 'IN THE FIELD',
  idle: 'STANDING BY',
  offline: 'OFFLINE',
};

const STATUS_CARD: Record<string, 'active' | 'warning' | 'offline'> = {
  scanning: 'active',
  idle: 'warning',
  offline: 'offline',
};

const SEVERITY_MAP: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

const SCANNING_MESSAGES = [
  'Bond is in the field...',
  'Gathering intelligence...',
  'Analysing threats...',
];

const CATEGORY_OPTIONS = ['all', 'known_exploited_vulnerability', 'cve', 'c2_infrastructure', 'malware_url', 'malware_sample', 'ioc'];
const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'];

// --- Component ---

export function CommanderBondPanel() {
  // Tab state
  const [activeTab, setActiveTab] = useState<'briefing' | 'dossiers' | 'operations'>('briefing');

  // Briefing state
  const [bondStatus, setBondStatus] = useState<BondStatus | null>(null);
  const [latest, setLatest] = useState<BondLatest | null>(null);
  const [expandedIocs, setExpandedIocs] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [latestLoading, setLatestLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [latestError, setLatestError] = useState<string | null>(null);

  // Dossiers state
  const [reports, setReports] = useState<BondReport[]>([]);
  const [expandedReport, setExpandedReport] = useState<string | null>(null);
  const [dossierCategoryFilter, setDossierCategoryFilter] = useState('all');
  const [dossierSeverityFilter, setDossierSeverityFilter] = useState('all');
  const [reportsLoading, setReportsLoading] = useState(false);

  // Operations state
  const [scanning, setScanning] = useState(false);
  const [scanMessageIdx, setScanMessageIdx] = useState(0);
  const [missionHistory, setMissionHistory] = useState<ScanResult[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);

  // Neutralize state
  const [neutralizingId, setNeutralizingId] = useState<string | null>(null);
  const [neutralizingAll, setNeutralizingAll] = useState(false);

  // Countdown state
  const [countdown, setCountdown] = useState<string | null>(null);

  // --- Data loaders ---

  const loadBondStatus = async () => {
    try {
      setStatusError(null);
      const data = await api.getBondStatus() as BondStatus;
      setBondStatus(data);
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : 'Failed to load status');
    } finally {
      setStatusLoading(false);
    }
  };

  const loadLatest = async () => {
    try {
      setLatestError(null);
      const data = await api.getBondLatest() as Record<string, unknown>;
      // Backend returns flat report dict or { status: "NO INTELLIGENCE...", threats: [], threat_count: 0 }
      if (data && data.id && typeof data.id === 'string') {
        setLatest(data as unknown as BondLatest);
      } else {
        setLatest(null);
      }
    } catch (err) {
      setLatestError(err instanceof Error ? err.message : 'Failed to load latest report');
    } finally {
      setLatestLoading(false);
    }
  };

  const loadReports = async () => {
    setReportsLoading(true);
    try {
      const data = await api.getBondReports() as BondReport[];
      setReports(data);
    } catch { /* ignore */ } finally {
      setReportsLoading(false);
    }
  };

  const loadThreats = async () => {
    try {
      const params: Record<string, string> = {};
      if (dossierCategoryFilter !== 'all') params.category = dossierCategoryFilter;
      if (dossierSeverityFilter !== 'all') params.severity = dossierSeverityFilter;
      const data = await api.getBondThreats(params) as BondThreat[];
      // Update reports with filtered threats if needed
      void data;
    } catch { /* ignore */ }
  };

  // --- Effects ---

  // Auto-refresh bond status every 15s
  useEffect(() => {
    loadBondStatus();
    const interval = setInterval(loadBondStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  // Auto-refresh latest report every 30s
  useEffect(() => {
    loadLatest();
    const interval = setInterval(loadLatest, 30000);
    return () => clearInterval(interval);
  }, []);

  // Load dossiers data when tab changes
  useEffect(() => {
    if (activeTab === 'dossiers') {
      loadReports();
      loadThreats();
    }
  }, [activeTab, dossierCategoryFilter, dossierSeverityFilter]);

  // Countdown timer
  useEffect(() => {
    if (!bondStatus?.next_scan) {
      setCountdown(null);
      return;
    }
    const tick = () => {
      const diff = new Date(bondStatus.next_scan!).getTime() - Date.now();
      if (diff <= 0) {
        setCountdown('IMMINENT');
        return;
      }
      const m = Math.floor(diff / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setCountdown(`${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`);
    };
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [bondStatus?.next_scan]);

  // Cycling scan messages
  useEffect(() => {
    if (!scanning) return;
    const interval = setInterval(() => {
      setScanMessageIdx(prev => (prev + 1) % SCANNING_MESSAGES.length);
    }, 2500);
    return () => clearInterval(interval);
  }, [scanning]);

  // --- Handlers ---

  const handleDeployBond = async () => {
    setScanning(true);
    setScanError(null);
    setScanMessageIdx(0);
    try {
      const result = await api.triggerBondScan() as ScanResult;
      setMissionHistory(prev => [result, ...prev]);
      loadBondStatus();
      loadLatest();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Scan deployment failed');
    } finally {
      setScanning(false);
    }
  };

  const toggleIocs = (threatId: string) => {
    setExpandedIocs(prev => {
      const next = new Set(prev);
      if (next.has(threatId)) next.delete(threatId);
      else next.add(threatId);
      return next;
    });
  };

  const copyToClipboard = (text: string, threatId: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(threatId);
      setTimeout(() => setCopiedId(null), 2000);
    });
  };

  const handleNeutralize = async (threatId: string) => {
    setNeutralizingId(threatId);
    try {
      await api.neutralizeBondThreat(threatId);
      // Refresh data after neutralizing
      loadBondStatus();
      loadLatest();
      if (activeTab === 'dossiers') loadReports();
    } catch { /* ignore */ } finally {
      setNeutralizingId(null);
    }
  };

  const handleNeutralizeAll = async () => {
    setNeutralizingAll(true);
    try {
      await api.neutralizeAllBondThreats();
      loadBondStatus();
      loadLatest();
      if (activeTab === 'dossiers') loadReports();
    } catch { /* ignore */ } finally {
      setNeutralizingAll(false);
    }
  };

  const formatTimestamp = (ts: string | null) => {
    if (!ts) return 'NEVER';
    return new Date(ts).toLocaleString('en-US', { hour12: false });
  };

  // --- Filtered reports for dossiers ---

  const filteredReports = reports.map(r => ({
    ...r,
    threats: r.threats.filter(t => {
      if (dossierCategoryFilter !== 'all' && t.category !== dossierCategoryFilter) return false;
      if (dossierSeverityFilter !== 'all' && t.severity !== dossierSeverityFilter) return false;
      return true;
    }),
  })).filter(r => r.threats.length > 0 || (dossierCategoryFilter === 'all' && dossierSeverityFilter === 'all'));

  // --- Render helpers ---

  const renderThreatCard = (threat: BondThreat) => {
    const sev = SEVERITY_MAP[threat.severity] || SEVERITY_MAP.info;
    return (
      <div key={threat.id} style={{
        padding: '12px',
        background: 'var(--bg-tertiary)',
        borderRadius: '2px',
        borderLeft: '3px solid ' + (threat.severity === 'critical' ? 'var(--severity-critical)' :
          threat.severity === 'high' ? 'var(--severity-high)' :
          threat.severity === 'medium' ? 'var(--severity-medium)' : 'var(--text-muted)'),
        marginBottom: '10px',
      }}>
        {/* Header row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
          <span className={`stamp-badge ${sev.stampClass}`}>{sev.label}</span>
          <span style={{
            fontSize: '18px',
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            letterSpacing: '1px',
            color: 'var(--text-primary)',
          }}>
            {threat.name}
          </span>
          <span style={{
            fontSize: '15px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)',
            letterSpacing: '1px',
            marginLeft: 'auto',
          }}>
            {threat.category.toUpperCase()} | {threat.source}
          </span>
          <button
            onClick={(e) => { e.stopPropagation(); handleNeutralize(threat.id); }}
            disabled={neutralizingId === threat.id}
            style={{
              padding: '3px 12px',
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

        {/* Bond's assessment */}
        <div style={{
          fontStyle: 'italic',
          color: 'var(--text-secondary)',
          fontSize: '16px',
          fontFamily: 'var(--font-mono)',
          lineHeight: 1.5,
          padding: '6px 0 10px',
          borderBottom: '1px solid var(--border-subtle)',
        }}>
          {threat.bond_assessment}
        </div>

        {/* IOCs (collapsible) */}
        {threat.iocs && threat.iocs.length > 0 && (
          <div style={{ marginTop: '8px' }}>
            <div
              onClick={() => toggleIocs(threat.id)}
              style={{
                cursor: 'pointer',
                fontSize: '15px',
                fontFamily: 'var(--font-mono)',
                color: BOND_GOLD,
                letterSpacing: '1px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span style={{ fontSize: '12px' }}>{expandedIocs.has(threat.id) ? '\u25BC' : '\u25B6'}</span>
              IOCs ({threat.iocs.length})
            </div>
            {expandedIocs.has(threat.id) && (
              <div style={{
                marginTop: '6px',
                padding: '8px',
                background: 'var(--bg-secondary)',
                borderRadius: '2px',
                fontFamily: 'var(--font-mono)',
                fontSize: '15px',
              }}>
                {threat.iocs.map((ioc, idx) => (
                  <div key={idx} style={{
                    color: 'var(--cyan-primary)',
                    padding: '2px 0',
                    wordBreak: 'break-all',
                  }}>
                    {ioc}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Cereberus Prompt */}
        {threat.cereberus_prompt && (
          <div style={{ marginTop: '10px' }}>
            <div style={{
              fontSize: '15px',
              fontFamily: 'var(--font-mono)',
              color: BOND_GOLD,
              letterSpacing: '1px',
              marginBottom: '6px',
            }}>
              CEREBERUS PROMPT
            </div>
            <div style={{
              position: 'relative',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-default)',
              borderRadius: '2px',
              padding: '10px 12px',
            }}>
              <pre style={{
                margin: 0,
                fontFamily: 'var(--font-mono)',
                fontSize: '14px',
                color: 'var(--text-primary)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                lineHeight: 1.5,
              }}>
                {threat.cereberus_prompt}
              </pre>
              <button
                onClick={() => copyToClipboard(threat.cereberus_prompt, threat.id)}
                style={{
                  position: 'absolute',
                  top: '6px',
                  right: '6px',
                  padding: '3px 10px',
                  background: copiedId === threat.id ? 'var(--status-online)' : BOND_GOLD,
                  border: 'none',
                  color: 'var(--bg-primary)',
                  fontSize: '14px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  cursor: 'pointer',
                  letterSpacing: '1px',
                }}
              >
                {copiedId === threat.id ? 'COPIED' : 'COPY'}
              </button>
            </div>
          </div>
        )}
      </div>
    );
  };

  // --- Tab config ---

  const tabs = [
    { key: 'briefing' as const, label: 'BRIEFING' },
    { key: 'dossiers' as const, label: 'DOSSIERS' },
    { key: 'operations' as const, label: 'OPERATIONS' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Bond Status Header */}
      <IntelCard
        title="COMMANDER BOND"
        classification="CLASSIFIED"
        status={bondStatus ? STATUS_CARD[bondStatus.state] || 'offline' : 'offline'}
        style={{ borderTop: `2px solid ${BOND_GOLD}` }}
      >
        {statusLoading ? (
          <div style={{ padding: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
            ESTABLISHING SECURE LINK...
          </div>
        ) : statusError ? (
          <div style={{ padding: '16px', color: 'var(--severity-critical)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
            COMMS FAILURE: {statusError}
          </div>
        ) : bondStatus && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px', padding: '8px 0' }}>
            {/* Status indicator */}
            <div style={{
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              border: `4px solid ${bondStatus.state === 'scanning' ? BOND_GOLD : bondStatus.state === 'idle' ? 'var(--text-muted)' : 'var(--severity-critical)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: bondStatus.state === 'scanning' ? `0 0 24px ${BOND_GOLD}40, 0 0 48px ${BOND_GOLD}20` : 'none',
            }}>
              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '50%',
                background: bondStatus.state === 'scanning' ? BOND_GOLD : bondStatus.state === 'idle' ? 'var(--text-muted)' : 'var(--severity-critical)',
                boxShadow: bondStatus.state === 'scanning' ? `0 0 12px ${BOND_GOLD}` : 'none',
              }} />
            </div>

            {/* Status text */}
            <div style={{ flex: 1 }}>
              <div style={{
                fontSize: '28px',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                color: BOND_GOLD,
                letterSpacing: '4px',
              }}>
                {STATUS_LABELS[bondStatus.state] || 'UNKNOWN'}
              </div>
              <div style={{
                fontSize: '15px',
                color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '1px',
                marginTop: '4px',
              }}>
                LAST SCAN: {formatTimestamp(bondStatus.last_scan)}
              </div>
            </div>

            {/* Next scan countdown */}
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '15px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
                NEXT SCAN
              </div>
              <div style={{
                fontSize: '30px',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-primary)',
              }}>
                {countdown || '--:--'}
              </div>
            </div>

            {/* Threat count badge */}
            <div style={{
              textAlign: 'center',
              padding: '8px 16px',
              background: bondStatus.threat_count > 0 ? 'var(--severity-critical)20' : 'var(--bg-tertiary)',
              borderRadius: '2px',
              border: `1px solid ${bondStatus.threat_count > 0 ? 'var(--severity-critical)' : 'var(--border-default)'}`,
            }}>
              <div style={{ fontSize: '15px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
                THREATS
              </div>
              <div style={{
                fontSize: '34px',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                color: bondStatus.threat_count > 0 ? 'var(--severity-critical)' : 'var(--text-primary)',
              }}>
                {bondStatus.threat_count}
              </div>
            </div>
          </div>
        )}
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
              color: activeTab === tab.key ? BOND_GOLD : 'var(--text-muted)',
              fontSize: '16px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              letterSpacing: '2px',
              cursor: 'pointer',
              borderBottom: activeTab === tab.key ? `2px solid ${BOND_GOLD}` : '2px solid transparent',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ===== BRIEFING TAB ===== */}
      {activeTab === 'briefing' && (
        <>
          {latestLoading ? (
            <IntelCard title="LATEST BRIEFING" classification="CLASSIFIED">
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
                DECRYPTING INTELLIGENCE...
              </div>
            </IntelCard>
          ) : latestError ? (
            <IntelCard title="LATEST BRIEFING" classification="CLASSIFIED" status="critical">
              <div style={{ padding: '16px', color: 'var(--severity-critical)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
                INTELLIGENCE RETRIEVAL FAILED: {latestError}
              </div>
            </IntelCard>
          ) : latest ? (
            <>
              {/* Bond's summary */}
              <IntelCard title="BOND REPORT" classification="CLASSIFIED">
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.6,
                  letterSpacing: '0.5px',
                }}>
                  {latest.summary}
                </div>
                <div style={{
                  marginTop: '10px',
                  fontSize: '14px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-muted)',
                  letterSpacing: '1px',
                }}>
                  FILED: {formatTimestamp(latest.timestamp)} | STATUS: {latest.status.toUpperCase()} | THREATS: {latest.threat_count}
                </div>
              </IntelCard>

              {/* Threat dossier cards */}
              {latest.threats && latest.threats.length > 0 && (
                <IntelCard title="THREAT DOSSIERS" classification="CLASSIFIED">
                  <div style={{
                    display: 'flex',
                    justifyContent: 'flex-end',
                    marginBottom: '12px',
                  }}>
                    <button
                      onClick={handleNeutralizeAll}
                      disabled={neutralizingAll}
                      style={{
                        padding: '6px 18px',
                        background: 'transparent',
                        border: `1px solid ${BOND_GOLD}`,
                        color: BOND_GOLD,
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
                  {latest.threats.map(threat => renderThreatCard(threat))}
                </IntelCard>
              )}
            </>
          ) : (
            <IntelCard title="LATEST BRIEFING" classification="CLASSIFIED">
              <div style={{
                padding: '30px',
                textAlign: 'center',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                fontSize: '16px',
                letterSpacing: '2px',
              }}>
                NO INTELLIGENCE REPORTS AVAILABLE
                <div style={{ marginTop: '8px', fontSize: '14px', letterSpacing: '1px' }}>
                  Deploy Bond from the OPERATIONS tab to begin reconnaissance
                </div>
              </div>
            </IntelCard>
          )}
        </>
      )}

      {/* ===== DOSSIERS TAB ===== */}
      {activeTab === 'dossiers' && (
        <IntelCard title="HISTORICAL DOSSIERS" classification="CLASSIFIED">
          {/* Filters */}
          <div style={{ display: 'flex', gap: '12px', marginBottom: '14px', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '15px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                CATEGORY:
              </span>
              <select
                value={dossierCategoryFilter}
                onChange={(e) => setDossierCategoryFilter(e.target.value)}
                style={{
                  padding: '4px 8px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--text-primary)',
                  fontSize: '15px',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                }}
              >
                {CATEGORY_OPTIONS.map(c => (
                  <option key={c} value={c}>{c.toUpperCase()}</option>
                ))}
              </select>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '15px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                SEVERITY:
              </span>
              <select
                value={dossierSeverityFilter}
                onChange={(e) => setDossierSeverityFilter(e.target.value)}
                style={{
                  padding: '4px 8px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--text-primary)',
                  fontSize: '15px',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                }}
              >
                {SEVERITY_OPTIONS.map(s => (
                  <option key={s} value={s}>{s.toUpperCase()}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Reports table */}
          {reportsLoading ? (
            <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
              RETRIEVING DOSSIERS...
            </div>
          ) : filteredReports.length === 0 ? (
            <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
              NO DOSSIERS MATCH CURRENT FILTERS
            </div>
          ) : (
            <div style={{ maxHeight: '500px', overflow: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '16px', fontFamily: 'var(--font-mono)' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-default)', color: 'var(--text-muted)', fontSize: '14px', letterSpacing: '2px' }}>
                    <th style={{ padding: '8px', textAlign: 'left' }}>DATE</th>
                    <th style={{ padding: '8px', textAlign: 'center' }}>THREATS</th>
                    <th style={{ padding: '8px', textAlign: 'left' }}>STATUS</th>
                    <th style={{ padding: '8px', textAlign: 'center' }}>DETAILS</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredReports.map((report) => (
                    <tr key={report.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td colSpan={4} style={{ padding: 0 }}>
                        {/* Report summary row */}
                        <div
                          onClick={() => setExpandedReport(expandedReport === report.id ? null : report.id)}
                          style={{
                            display: 'grid',
                            gridTemplateColumns: '1fr auto 1fr auto',
                            alignItems: 'center',
                            padding: '10px 8px',
                            cursor: 'pointer',
                          }}
                        >
                          <span style={{ color: 'var(--text-primary)' }}>
                            {formatTimestamp(report.timestamp)}
                          </span>
                          <span style={{
                            textAlign: 'center',
                            padding: '2px 10px',
                            background: report.threat_count > 0 ? 'var(--severity-critical)20' : 'var(--bg-tertiary)',
                            borderRadius: '2px',
                            color: report.threat_count > 0 ? 'var(--severity-critical)' : 'var(--text-primary)',
                            fontWeight: 700,
                          }}>
                            {report.threat_count}
                          </span>
                          <span style={{ color: 'var(--text-secondary)', paddingLeft: '12px' }}>
                            {report.status.toUpperCase()}
                          </span>
                          <span style={{ textAlign: 'center', color: BOND_GOLD, fontSize: '14px' }}>
                            {expandedReport === report.id ? '\u25BC' : '\u25B6'}
                          </span>
                        </div>

                        {/* Expanded threats */}
                        {expandedReport === report.id && (
                          <div style={{ padding: '0 8px 12px' }}>
                            {report.threats.length === 0 ? (
                              <div style={{ padding: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
                                NO THREATS IN THIS REPORT
                              </div>
                            ) : (
                              report.threats.map(threat => renderThreatCard(threat))
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </IntelCard>
      )}

      {/* ===== OPERATIONS TAB ===== */}
      {activeTab === 'operations' && (
        <>
          <IntelCard title="MISSION CONTROL" classification="CLASSIFIED">
            {/* Deploy button */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px', padding: '16px 0' }}>
              <button
                onClick={handleDeployBond}
                disabled={scanning}
                style={{
                  padding: '14px 48px',
                  background: scanning ? 'var(--bg-tertiary)' : BOND_GOLD,
                  border: scanning ? `2px solid ${BOND_GOLD}` : '2px solid transparent',
                  color: scanning ? BOND_GOLD : 'var(--bg-primary)',
                  fontSize: '20px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  letterSpacing: '4px',
                  cursor: scanning ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s',
                  boxShadow: scanning ? 'none' : `0 0 20px ${BOND_GOLD}30`,
                }}
              >
                {scanning ? 'DEPLOYED' : 'DEPLOY BOND'}
              </button>

              {/* Scanning status message */}
              {scanning && (
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  color: BOND_GOLD,
                  letterSpacing: '2px',
                  textAlign: 'center',
                }}>
                  {SCANNING_MESSAGES[scanMessageIdx]}
                </div>
              )}

              {scanError && (
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '15px',
                  color: 'var(--severity-critical)',
                  letterSpacing: '1px',
                  textAlign: 'center',
                }}>
                  MISSION FAILED: {scanError}
                </div>
              )}
            </div>

            {/* Scan interval display */}
            {bondStatus && (
              <div style={{
                textAlign: 'center',
                padding: '10px 0',
                borderTop: '1px solid var(--border-default)',
                fontSize: '15px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                letterSpacing: '1px',
              }}>
                SCAN INTERVAL: {Math.floor((bondStatus.scan_interval_seconds || 0) / 60)} MINUTES
              </div>
            )}
          </IntelCard>

          {/* Mission history */}
          <IntelCard title="MISSION HISTORY" classification="CLASSIFIED">
            {missionHistory.length === 0 ? (
              <div style={{
                padding: '24px',
                textAlign: 'center',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                fontSize: '16px',
                letterSpacing: '2px',
              }}>
                NO MISSIONS LOGGED THIS SESSION
              </div>
            ) : (
              <div style={{ maxHeight: '300px', overflow: 'auto' }}>
                {missionHistory.map((mission, idx) => (
                  <div key={idx} className="cable-feed-item" style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    padding: '8px 0',
                    borderBottom: idx < missionHistory.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                  }}>
                    <span style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      background: BOND_GOLD,
                      flexShrink: 0,
                    }} />
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '15px',
                      color: 'var(--text-primary)',
                      letterSpacing: '1px',
                    }}>
                      {formatTimestamp(mission.started_at)}
                    </span>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '15px',
                      color: 'var(--text-muted)',
                      letterSpacing: '1px',
                    }}>
                      ID: {mission.scan_id}
                    </span>
                    {mission.duration_seconds !== undefined && (
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '15px',
                        color: BOND_GOLD,
                        letterSpacing: '1px',
                        marginLeft: 'auto',
                      }}>
                        {mission.duration_seconds.toFixed(1)}s
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </IntelCard>
        </>
      )}
    </div>
  );
}
