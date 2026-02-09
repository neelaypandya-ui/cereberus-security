import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';
import { useToast } from '../hooks/useToast';
import type {
  BondStatusResponse,
  BondThreat,
  BondReportResponse,
  GuardianStatusResponse,
  SwordPolicyResponse,
  SwordLogResponse,
  SwordStats,
  YaraRuleResponse,
  YaraScanResultResponse,
  OverwatchStatus,
  OverwatchIntegrityReport,
} from '../bridge';

// --- Types (bridge-backed + local extensions) ---

type BondStatus = BondStatusResponse;
type BondReport = BondReportResponse;
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
  const [activeTab, setActiveTab] = useState<'briefing' | 'dossiers' | 'operations' | 'guardian' | 'qbranch' | 'sword' | 'overwatch'>('briefing');

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

  // Guardian state (Phase 14)
  const [guardian, setGuardian] = useState<GuardianStatusResponse | null>(null);
  const [guardianLoading, setGuardianLoading] = useState(false);
  const [clearingLockdown, setClearingLockdown] = useState(false);

  // Q-Branch state (Phase 15)
  const [yaraRules, setYaraRules] = useState<YaraRuleResponse[]>([]);
  const [yaraRulesLoading, setYaraRulesLoading] = useState(false);
  const [yaraResults, setYaraResults] = useState<YaraScanResultResponse[]>([]);
  const [yaraStats, setYaraStats] = useState<Record<string, unknown> | null>(null);
  const [yaraScanPath, setYaraScanPath] = useState('');
  const [yaraScanning, setYaraScanning] = useState(false);
  const [yaraCompiling, setYaraCompiling] = useState(false);

  // Sword Protocol state (Phase 15)
  const [swordPolicies, setSwordPolicies] = useState<SwordPolicyResponse[]>([]);
  const [swordPoliciesLoading, setSwordPoliciesLoading] = useState(false);
  const [swordLogs, setSwordLogs] = useState<SwordLogResponse[]>([]);
  const [swordLogsLoading, setSwordLogsLoading] = useState(false);
  const [swordEnabling, setSwordEnabling] = useState(false);
  const [swordLockingOut, setSwordLockingOut] = useState(false);
  const [togglingPolicyId, setTogglingPolicyId] = useState<number | null>(null);

  // Overwatch state (Phase 15)
  const [overwatchStatus, setOverwatchStatus] = useState<OverwatchStatus | null>(null);
  const [overwatchStatusLoading, setOverwatchStatusLoading] = useState(false);
  const [overwatchIntegrity, setOverwatchIntegrity] = useState<OverwatchIntegrityReport | null>(null);
  const [overwatchIntegrityLoading, setOverwatchIntegrityLoading] = useState(false);
  const [overwatchChecking, setOverwatchChecking] = useState(false);

  // Toast
  const { showToast } = useToast();

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
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
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
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const loadGuardian = async () => {
    setGuardianLoading(true);
    try {
      const data = await api.getGuardianStatus() as GuardianStatusResponse;
      setGuardian(data);
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
      setGuardianLoading(false);
    }
  };

  const handleClearLockdown = async () => {
    setClearingLockdown(true);
    try {
      await api.clearGuardianLockdown();
      loadGuardian();
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
      setClearingLockdown(false);
    }
  };

  // --- Q-Branch loaders (Phase 15) ---

  const loadYaraRules = async () => {
    setYaraRulesLoading(true);
    try {
      const data = await api.getYaraRules() as YaraRuleResponse[];
      setYaraRules(data);
    } catch (err) {
      showToast('error', 'YARA RULES LOAD FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setYaraRulesLoading(false);
    }
  };

  const loadYaraResults = async () => {
    try {
      const data = await api.getYaraResults(20) as YaraScanResultResponse[];
      setYaraResults(data);
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const loadYaraStats = async () => {
    try {
      const data = await api.getYaraStats() as Record<string, unknown>;
      setYaraStats(data);
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const handleCompileYara = async () => {
    setYaraCompiling(true);
    try {
      await api.compileYaraRules();
      showToast('success', 'YARA RULES COMPILED', 'All rules compiled successfully');
      loadYaraRules();
    } catch (err) {
      showToast('error', 'COMPILATION FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setYaraCompiling(false);
    }
  };

  const handleYaraScanFile = async () => {
    if (!yaraScanPath.trim()) {
      showToast('warning', 'NO TARGET', 'Enter a file path to scan');
      return;
    }
    setYaraScanning(true);
    try {
      await api.scanYaraFile(yaraScanPath.trim());
      showToast('success', 'SCAN COMPLETE', `Scanned: ${yaraScanPath.trim()}`);
      setYaraScanPath('');
      loadYaraResults();
    } catch (err) {
      showToast('error', 'SCAN FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setYaraScanning(false);
    }
  };

  // --- Sword Protocol loaders (Phase 15) ---

  const loadSwordPolicies = async () => {
    setSwordPoliciesLoading(true);
    try {
      const data = await api.getSwordPolicies() as SwordPolicyResponse[];
      setSwordPolicies(data);
    } catch (err) {
      showToast('error', 'SWORD POLICIES LOAD FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setSwordPoliciesLoading(false);
    }
  };

  const loadSwordLogs = async () => {
    setSwordLogsLoading(true);
    try {
      const data = await api.getSwordLogs(20) as SwordLogResponse[];
      setSwordLogs(data);
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
      setSwordLogsLoading(false);
    }
  };

  const handleEnableSword = async () => {
    setSwordEnabling(true);
    try {
      await api.enableSword();
      showToast('success', 'SWORD PROTOCOL ENABLED', 'Autonomous response activated');
      loadBondStatus();
    } catch (err) {
      showToast('error', 'ENABLE FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setSwordEnabling(false);
    }
  };

  const handleDisableSword = async () => {
    setSwordEnabling(true);
    try {
      await api.disableSword();
      showToast('info', 'SWORD PROTOCOL DISABLED', 'Autonomous response deactivated');
      loadBondStatus();
    } catch (err) {
      showToast('error', 'DISABLE FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setSwordEnabling(false);
    }
  };

  const handleSwordLockout = async () => {
    if (!window.confirm('EMERGENCY LOCKOUT: This will immediately halt all autonomous response actions. Confirm?')) return;
    setSwordLockingOut(true);
    try {
      await api.swordLockout();
      showToast('warning', 'EMERGENCY LOCKOUT ENGAGED', 'All Sword Protocol actions halted');
      loadBondStatus();
      loadSwordPolicies();
    } catch (err) {
      showToast('error', 'LOCKOUT FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setSwordLockingOut(false);
    }
  };

  const handleSwordClearLockout = async () => {
    setSwordLockingOut(true);
    try {
      await api.swordClearLockout();
      showToast('success', 'LOCKOUT CLEARED', 'Sword Protocol lockout released');
      loadBondStatus();
    } catch (err) {
      showToast('error', 'CLEAR LOCKOUT FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setSwordLockingOut(false);
    }
  };

  const handleToggleSwordPolicy = async (id: number) => {
    setTogglingPolicyId(id);
    try {
      await api.toggleSwordPolicy(id);
      showToast('success', 'POLICY TOGGLED', `Policy #${id} updated`);
      loadSwordPolicies();
    } catch (err) {
      showToast('error', 'TOGGLE FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setTogglingPolicyId(null);
    }
  };

  // --- Overwatch loaders (Phase 15) ---

  const loadOverwatchStatus = async () => {
    setOverwatchStatusLoading(true);
    try {
      const data = await api.getOverwatchStatus() as OverwatchStatus;
      setOverwatchStatus(data);
    } catch (err) {
      showToast('error', 'OVERWATCH STATUS FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setOverwatchStatusLoading(false);
    }
  };

  const loadOverwatchIntegrity = async () => {
    setOverwatchIntegrityLoading(true);
    try {
      const data = await api.getOverwatchIntegrity() as OverwatchIntegrityReport;
      setOverwatchIntegrity(data);
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
      setOverwatchIntegrityLoading(false);
    }
  };

  const handleOverwatchCheck = async () => {
    setOverwatchChecking(true);
    try {
      await api.triggerOverwatchCheck();
      showToast('success', 'INTEGRITY CHECK COMPLETE', 'Overwatch scan finished');
      loadOverwatchStatus();
      loadOverwatchIntegrity();
    } catch (err) {
      showToast('error', 'CHECK FAILED', err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setOverwatchChecking(false);
    }
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
    if (activeTab === 'guardian') {
      loadGuardian();
      const interval = setInterval(loadGuardian, 10000);
      return () => clearInterval(interval);
    }
    if (activeTab === 'qbranch') {
      loadYaraRules();
      loadYaraResults();
      loadYaraStats();
    }
    if (activeTab === 'sword') {
      loadSwordPolicies();
      loadSwordLogs();
    }
    if (activeTab === 'overwatch') {
      loadOverwatchStatus();
      loadOverwatchIntegrity();
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
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
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
    } catch (err) { console.error('[CEREBERUS]', err); } finally {
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
    { key: 'guardian' as const, label: 'GUARDIAN' },
    { key: 'qbranch' as const, label: 'Q-BRANCH' },
    { key: 'sword' as const, label: 'SWORD' },
    { key: 'overwatch' as const, label: 'OVERWATCH' },
  ];

  // Sword stats from bond status
  const swordStats: SwordStats | null = bondStatus?.sword ?? null;

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

      {/* ===== GUARDIAN TAB ===== */}
      {activeTab === 'guardian' && (
        <>
          <IntelCard title="GUARDIAN PROTOCOL" classification="CLASSIFIED" status={
            guardian?.containment_level === 3 ? 'critical' :
            guardian?.containment_level === 2 ? 'warning' :
            guardian?.containment_level === 1 ? 'warning' : 'active'
          }>
            {guardianLoading && !guardian ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
                ESTABLISHING GUARDIAN LINK...
              </div>
            ) : guardian ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Containment Level + Stability */}
                <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                  {/* Containment badge */}
                  <div style={{
                    padding: '12px 24px',
                    borderRadius: '2px',
                    border: `2px solid ${
                      guardian.level_name === 'RED' ? 'var(--severity-critical)' :
                      guardian.level_name === 'ORANGE' ? 'var(--severity-high)' :
                      guardian.level_name === 'YELLOW' ? 'var(--severity-medium)' :
                      'var(--status-online)'
                    }`,
                    background: `${
                      guardian.level_name === 'RED' ? 'var(--severity-critical)' :
                      guardian.level_name === 'ORANGE' ? 'var(--severity-high)' :
                      guardian.level_name === 'YELLOW' ? 'var(--severity-medium)' :
                      'var(--status-online)'
                    }20`,
                  }}>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '2px' }}>CONTAINMENT</div>
                    <div style={{
                      fontSize: '32px', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '4px',
                      color: guardian.level_name === 'RED' ? 'var(--severity-critical)' :
                             guardian.level_name === 'ORANGE' ? 'var(--severity-high)' :
                             guardian.level_name === 'YELLOW' ? 'var(--severity-medium)' :
                             'var(--status-online)',
                    }}>
                      {guardian.level_name}
                    </div>
                  </div>

                  {/* Stability gauge */}
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '2px', marginBottom: '6px' }}>
                      STABILITY SCORE
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div style={{ flex: 1, height: '12px', background: 'var(--bg-secondary)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div style={{
                          width: `${guardian.stability_score}%`,
                          height: '100%',
                          background: guardian.stability_score >= 80 ? 'var(--status-online)' :
                                     guardian.stability_score >= 50 ? 'var(--severity-medium)' :
                                     guardian.stability_score >= 20 ? 'var(--severity-high)' : 'var(--severity-critical)',
                          transition: 'width 0.5s',
                        }} />
                      </div>
                      <span style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', minWidth: '60px' }}>
                        {guardian.stability_score.toFixed(1)}%
                      </span>
                    </div>
                  </div>

                  {/* Lockdown indicator + clear button */}
                  {guardian.lockdown_active && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                      <div style={{
                        padding: '6px 16px', background: 'var(--severity-critical)20', border: '1px solid var(--severity-critical)',
                        color: 'var(--severity-critical)', fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '2px',
                      }}>
                        LOCKDOWN ACTIVE
                      </div>
                      <button
                        onClick={handleClearLockdown}
                        disabled={clearingLockdown}
                        style={{
                          padding: '6px 18px', background: 'transparent', border: `1px solid ${BOND_GOLD}`,
                          color: BOND_GOLD, fontSize: '13px', fontFamily: 'var(--font-mono)', fontWeight: 700,
                          letterSpacing: '1px', cursor: clearingLockdown ? 'not-allowed' : 'pointer',
                        }}
                      >
                        {clearingLockdown ? 'CLEARING...' : 'CLEAR LOCKDOWN'}
                      </button>
                    </div>
                  )}
                </div>

                {/* Last check */}
                <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                  LAST CHECK: {guardian.last_check ? formatTimestamp(guardian.last_check) : 'NEVER'}
                  {guardian.lockdown_reason && (
                    <span style={{ marginLeft: '16px', color: 'var(--severity-critical)' }}>
                      REASON: {guardian.lockdown_reason}
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                GUARDIAN PROTOCOL NOT INITIALIZED
              </div>
            )}
          </IntelCard>

          {/* Intervention Timeline */}
          {guardian && guardian.interventions.length > 0 && (
            <IntelCard title="INTERVENTION TIMELINE" classification="CLASSIFIED">
              <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                {guardian.interventions.map((intervention, idx) => (
                  <div key={idx} style={{
                    padding: '10px 12px', borderLeft: `3px solid ${
                      intervention.level === 'RED' ? 'var(--severity-critical)' :
                      intervention.level === 'ORANGE' ? 'var(--severity-high)' :
                      intervention.level === 'YELLOW' ? 'var(--severity-medium)' : 'var(--status-online)'
                    }`,
                    marginBottom: '8px', background: 'var(--bg-tertiary)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                      <span style={{
                        padding: '2px 8px', fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '1px',
                        background: `${
                          intervention.level === 'RED' ? 'var(--severity-critical)' :
                          intervention.level === 'ORANGE' ? 'var(--severity-high)' :
                          intervention.level === 'YELLOW' ? 'var(--severity-medium)' : 'var(--status-online)'
                        }20`,
                        color: intervention.level === 'RED' ? 'var(--severity-critical)' :
                               intervention.level === 'ORANGE' ? 'var(--severity-high)' :
                               intervention.level === 'YELLOW' ? 'var(--severity-medium)' : 'var(--status-online)',
                      }}>
                        {intervention.level}
                      </span>
                      <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        {formatTimestamp(intervention.timestamp)}
                      </span>
                      <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                        STABILITY: {intervention.stability_score}%
                      </span>
                    </div>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', marginBottom: '2px' }}>
                      {intervention.action_taken}
                    </div>
                    <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {intervention.reason}
                    </div>
                  </div>
                ))}
              </div>
            </IntelCard>
          )}

          {/* Intelligence Brain Metrics */}
          {bondStatus && (bondStatus as BondStatus).intelligence && (
            <IntelCard title="INTELLIGENCE BRAIN" classification="CLASSIFIED">
              {(() => {
                const intel = (bondStatus as BondStatus).intelligence!;
                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {/* Top metrics */}
                    <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                      {[
                        { label: 'GENERATION', value: intel.generation },
                        { label: 'TREND', value: intel.threat_trend.toUpperCase() },
                        { label: 'ADAPTIVE INTERVAL', value: `${Math.floor(intel.adaptive_interval / 60)}m` },
                        { label: 'CORRELATIONS', value: intel.correlations_found },
                        { label: 'ANALYZED', value: intel.total_threats_analyzed },
                      ].map(m => (
                        <div key={m.label} style={{ padding: '8px 14px', background: 'var(--bg-tertiary)', borderRadius: '2px', textAlign: 'center' }}>
                          <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>{m.label}</div>
                          <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: BOND_GOLD }}>{m.value}</div>
                        </div>
                      ))}
                    </div>

                    {/* Source Rankings */}
                    <div>
                      <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '2px', marginBottom: '8px' }}>
                        SOURCE QUALITY RANKINGS
                      </div>
                      {intel.source_rankings.map((src, idx) => {
                        const score = intel.source_scores[src]?.quality_score ?? 0;
                        return (
                          <div key={src} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '4px 0' }}>
                            <span style={{ width: '24px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>#{idx + 1}</span>
                            <span style={{ flex: 1, fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{src}</span>
                            <div style={{ width: '120px', height: '8px', background: 'var(--bg-secondary)', borderRadius: '2px', overflow: 'hidden' }}>
                              <div style={{
                                width: `${score}%`, height: '100%',
                                background: score >= 70 ? 'var(--status-online)' : score >= 40 ? 'var(--severity-medium)' : 'var(--severity-high)',
                              }} />
                            </div>
                            <span style={{ width: '50px', textAlign: 'right', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 700 }}>
                              {score.toFixed(0)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}
            </IntelCard>
          )}
        </>
      )}

      {/* ===== Q-BRANCH TAB ===== */}
      {activeTab === 'qbranch' && (
        <>
          {/* YARA Stats Overview */}
          <IntelCard title="Q-BRANCH ARSENAL" classification="CLASSIFIED" status="active">
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '16px' }}>
              {[
                { label: 'RULES LOADED', value: yaraStats ? String((yaraStats as Record<string, unknown>).total_rules ?? yaraRules.length) : String(yaraRules.length) },
                { label: 'ENABLED', value: String(yaraRules.filter(r => r.enabled).length) },
                { label: 'TOTAL MATCHES', value: yaraStats ? String((yaraStats as Record<string, unknown>).total_matches ?? 0) : '0' },
                { label: 'LAST SCAN', value: yaraStats && (yaraStats as Record<string, unknown>).last_scan ? formatTimestamp((yaraStats as Record<string, unknown>).last_scan as string) : 'NEVER' },
              ].map(m => (
                <div key={m.label} style={{ padding: '8px 14px', background: 'var(--bg-tertiary)', borderRadius: '2px', textAlign: 'center', flex: '1 1 120px' }}>
                  <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>{m.label}</div>
                  <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: BOND_GOLD }}>{m.value}</div>
                </div>
              ))}
            </div>

            {/* Actions row */}
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px' }}>
              <button
                onClick={handleCompileYara}
                disabled={yaraCompiling}
                style={{
                  padding: '8px 24px', background: BOND_GOLD, border: 'none',
                  color: 'var(--bg-primary)', fontSize: '14px', fontFamily: 'var(--font-mono)',
                  fontWeight: 700, letterSpacing: '2px',
                  cursor: yaraCompiling ? 'not-allowed' : 'pointer',
                  opacity: yaraCompiling ? 0.6 : 1,
                }}
              >
                {yaraCompiling ? 'COMPILING...' : 'COMPILE RULES'}
              </button>

              {/* Scan file input */}
              <div style={{ display: 'flex', flex: 1, gap: '6px' }}>
                <input
                  type="text"
                  value={yaraScanPath}
                  onChange={(e) => setYaraScanPath(e.target.value)}
                  placeholder="C:\path\to\file..."
                  onKeyDown={(e) => e.key === 'Enter' && handleYaraScanFile()}
                  style={{
                    flex: 1, padding: '8px 12px', background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-default)', color: 'var(--text-primary)',
                    fontSize: '14px', fontFamily: 'var(--font-mono)',
                  }}
                />
                <button
                  onClick={handleYaraScanFile}
                  disabled={yaraScanning}
                  style={{
                    padding: '8px 18px', background: 'transparent',
                    border: `1px solid ${BOND_GOLD}`, color: BOND_GOLD,
                    fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700,
                    letterSpacing: '1px', cursor: yaraScanning ? 'not-allowed' : 'pointer',
                    opacity: yaraScanning ? 0.6 : 1,
                  }}
                >
                  {yaraScanning ? 'SCANNING...' : 'SCAN FILE'}
                </button>
              </div>
            </div>
          </IntelCard>

          {/* YARA Rules List */}
          <IntelCard title="YARA RULES" classification="CLASSIFIED">
            {yaraRulesLoading ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                LOADING ARSENAL...
              </div>
            ) : yaraRules.length === 0 ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                NO YARA RULES DEPLOYED
              </div>
            ) : (
              <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px', fontFamily: 'var(--font-mono)' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-default)', color: 'var(--text-muted)', fontSize: '12px', letterSpacing: '2px' }}>
                      <th style={{ padding: '8px', textAlign: 'left' }}>RULE NAME</th>
                      <th style={{ padding: '8px', textAlign: 'center' }}>STATUS</th>
                      <th style={{ padding: '8px', textAlign: 'center' }}>MATCHES</th>
                      <th style={{ padding: '8px', textAlign: 'left' }}>LAST MATCH</th>
                    </tr>
                  </thead>
                  <tbody>
                    {yaraRules.map(rule => (
                      <tr key={rule.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '8px', color: 'var(--text-primary)' }}>
                          {rule.name}
                          {rule.description && (
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>{rule.description}</div>
                          )}
                        </td>
                        <td style={{ padding: '8px', textAlign: 'center' }}>
                          <span style={{
                            padding: '2px 10px', borderRadius: '2px', fontSize: '12px', fontWeight: 700,
                            letterSpacing: '1px',
                            background: rule.enabled ? 'var(--status-online)20' : 'var(--text-muted)20',
                            color: rule.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                          }}>
                            {rule.enabled ? 'ACTIVE' : 'INACTIVE'}
                          </span>
                        </td>
                        <td style={{ padding: '8px', textAlign: 'center', color: rule.match_count > 0 ? BOND_GOLD : 'var(--text-muted)', fontWeight: 700 }}>
                          {rule.match_count}
                        </td>
                        <td style={{ padding: '8px', color: 'var(--text-muted)', fontSize: '13px' }}>
                          {rule.last_match_at ? formatTimestamp(rule.last_match_at) : 'NEVER'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </IntelCard>

          {/* Recent Scan Results */}
          <IntelCard title="RECENT SCAN RESULTS" classification="CLASSIFIED">
            {yaraResults.length === 0 ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                NO SCAN RESULTS RECORDED
              </div>
            ) : (
              <div style={{ maxHeight: '350px', overflow: 'auto' }}>
                {yaraResults.map((result, idx) => (
                  <div key={result.id ?? idx} style={{
                    padding: '10px 12px',
                    borderLeft: `3px solid ${
                      result.severity === 'critical' ? 'var(--severity-critical)' :
                      result.severity === 'high' ? 'var(--severity-high)' :
                      result.severity === 'medium' ? 'var(--severity-medium)' : 'var(--text-muted)'
                    }`,
                    marginBottom: '8px', background: 'var(--bg-tertiary)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                      <span style={{
                        padding: '2px 8px', fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)',
                        letterSpacing: '1px', textTransform: 'uppercase',
                        background: result.severity === 'critical' ? 'var(--severity-critical)20' :
                                   result.severity === 'high' ? 'var(--severity-high)20' : 'var(--bg-secondary)',
                        color: result.severity === 'critical' ? 'var(--severity-critical)' :
                               result.severity === 'high' ? 'var(--severity-high)' :
                               result.severity === 'medium' ? 'var(--severity-medium)' : 'var(--text-muted)',
                      }}>
                        {result.severity}
                      </span>
                      <span style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: BOND_GOLD, fontWeight: 700 }}>
                        {result.rule_name}
                      </span>
                      <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                        {result.scanned_at ? formatTimestamp(result.scanned_at) : ''}
                      </span>
                    </div>
                    <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                      TARGET: {result.target}
                    </div>
                    {result.strings_matched && result.strings_matched.length > 0 && (
                      <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--cyan-primary)', marginTop: '4px' }}>
                        STRINGS: {result.strings_matched.join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </IntelCard>
        </>
      )}

      {/* ===== SWORD PROTOCOL TAB ===== */}
      {activeTab === 'sword' && (
        <>
          {/* Sword Control Panel */}
          <IntelCard
            title="SWORD PROTOCOL"
            classification="CLASSIFIED"
            status={swordStats?.lockout ? 'critical' : swordStats?.enabled ? 'active' : 'warning'}
          >
            {/* Status + Controls */}
            <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap' }}>
              {/* Stats row */}
              {swordStats && (
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', flex: 1 }}>
                  {[
                    { label: 'STATUS', value: swordStats.lockout ? 'LOCKOUT' : swordStats.enabled ? 'ARMED' : 'DISARMED' },
                    { label: 'EVALUATIONS', value: String(swordStats.total_evaluations) },
                    { label: 'STRIKES', value: String(swordStats.total_strikes) },
                    { label: 'FAILED', value: String(swordStats.total_failed) },
                    { label: 'POLICIES', value: String(swordStats.policies_loaded) },
                  ].map(m => (
                    <div key={m.label} style={{ padding: '8px 14px', background: 'var(--bg-tertiary)', borderRadius: '2px', textAlign: 'center' }}>
                      <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>{m.label}</div>
                      <div style={{
                        fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)',
                        color: m.label === 'STATUS' ? (swordStats.lockout ? 'var(--severity-critical)' : swordStats.enabled ? 'var(--status-online)' : 'var(--text-muted)') : BOND_GOLD,
                      }}>{m.value}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Control buttons */}
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              {/* Enable / Disable toggle */}
              {swordStats?.enabled ? (
                <button
                  onClick={handleDisableSword}
                  disabled={swordEnabling}
                  style={{
                    padding: '8px 24px', background: 'transparent',
                    border: '1px solid var(--text-muted)', color: 'var(--text-muted)',
                    fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700,
                    letterSpacing: '2px', cursor: swordEnabling ? 'not-allowed' : 'pointer',
                    opacity: swordEnabling ? 0.6 : 1,
                  }}
                >
                  {swordEnabling ? 'PROCESSING...' : 'DISARM SWORD'}
                </button>
              ) : (
                <button
                  onClick={handleEnableSword}
                  disabled={swordEnabling}
                  style={{
                    padding: '8px 24px', background: BOND_GOLD, border: 'none',
                    color: 'var(--bg-primary)', fontSize: '14px', fontFamily: 'var(--font-mono)',
                    fontWeight: 700, letterSpacing: '2px',
                    cursor: swordEnabling ? 'not-allowed' : 'pointer',
                    opacity: swordEnabling ? 0.6 : 1,
                  }}
                >
                  {swordEnabling ? 'PROCESSING...' : 'ARM SWORD'}
                </button>
              )}

              {/* Emergency Lockout */}
              {swordStats?.lockout ? (
                <button
                  onClick={handleSwordClearLockout}
                  disabled={swordLockingOut}
                  style={{
                    padding: '8px 24px', background: 'transparent',
                    border: `1px solid ${BOND_GOLD}`, color: BOND_GOLD,
                    fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700,
                    letterSpacing: '2px', cursor: swordLockingOut ? 'not-allowed' : 'pointer',
                    opacity: swordLockingOut ? 0.6 : 1,
                  }}
                >
                  {swordLockingOut ? 'PROCESSING...' : 'CLEAR LOCKOUT'}
                </button>
              ) : (
                <button
                  onClick={handleSwordLockout}
                  disabled={swordLockingOut}
                  style={{
                    padding: '8px 24px', background: 'transparent',
                    border: '1px solid var(--severity-critical)', color: 'var(--severity-critical)',
                    fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 700,
                    letterSpacing: '2px', cursor: swordLockingOut ? 'not-allowed' : 'pointer',
                    opacity: swordLockingOut ? 0.6 : 1,
                  }}
                >
                  {swordLockingOut ? 'PROCESSING...' : 'EMERGENCY LOCKOUT'}
                </button>
              )}

              {swordStats?.last_strike && (
                <div style={{ marginLeft: 'auto', fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px', alignSelf: 'center' }}>
                  LAST STRIKE: {formatTimestamp(swordStats.last_strike)}
                </div>
              )}
            </div>
          </IntelCard>

          {/* Sword Policies */}
          <IntelCard title="RESPONSE POLICIES" classification="CLASSIFIED">
            {swordPoliciesLoading ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                LOADING POLICIES...
              </div>
            ) : swordPolicies.length === 0 ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                NO POLICIES CONFIGURED
              </div>
            ) : (
              <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px', fontFamily: 'var(--font-mono)' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-default)', color: 'var(--text-muted)', fontSize: '12px', letterSpacing: '2px' }}>
                      <th style={{ padding: '8px', textAlign: 'left' }}>CODENAME</th>
                      <th style={{ padding: '8px', textAlign: 'left' }}>NAME</th>
                      <th style={{ padding: '8px', textAlign: 'center' }}>STATUS</th>
                      <th style={{ padding: '8px', textAlign: 'center' }}>EXECUTIONS</th>
                      <th style={{ padding: '8px', textAlign: 'center' }}>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {swordPolicies.map(policy => (
                      <tr key={policy.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '8px', color: BOND_GOLD, fontWeight: 700, letterSpacing: '1px' }}>
                          {policy.codename}
                        </td>
                        <td style={{ padding: '8px', color: 'var(--text-primary)' }}>
                          {policy.name}
                          {policy.description && (
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>{policy.description}</div>
                          )}
                        </td>
                        <td style={{ padding: '8px', textAlign: 'center' }}>
                          <span style={{
                            padding: '2px 10px', borderRadius: '2px', fontSize: '12px', fontWeight: 700,
                            letterSpacing: '1px',
                            background: policy.enabled ? 'var(--status-online)20' : 'var(--text-muted)20',
                            color: policy.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                          }}>
                            {policy.enabled ? 'ARMED' : 'DISARMED'}
                          </span>
                        </td>
                        <td style={{ padding: '8px', textAlign: 'center', color: policy.execution_count > 0 ? BOND_GOLD : 'var(--text-muted)', fontWeight: 700 }}>
                          {policy.execution_count}
                        </td>
                        <td style={{ padding: '8px', textAlign: 'center' }}>
                          <button
                            onClick={() => handleToggleSwordPolicy(policy.id)}
                            disabled={togglingPolicyId === policy.id}
                            style={{
                              padding: '3px 12px', background: 'transparent',
                              border: `1px solid ${policy.enabled ? 'var(--text-muted)' : BOND_GOLD}`,
                              color: policy.enabled ? 'var(--text-muted)' : BOND_GOLD,
                              fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 700,
                              letterSpacing: '1px', cursor: togglingPolicyId === policy.id ? 'not-allowed' : 'pointer',
                              opacity: togglingPolicyId === policy.id ? 0.5 : 1,
                            }}
                          >
                            {togglingPolicyId === policy.id ? '...' : policy.enabled ? 'DISARM' : 'ARM'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </IntelCard>

          {/* Execution Log */}
          <IntelCard title="EXECUTION LOG" classification="CLASSIFIED">
            {swordLogsLoading ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                LOADING EXECUTION LOG...
              </div>
            ) : swordLogs.length === 0 ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                NO EXECUTIONS RECORDED
              </div>
            ) : (
              <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                {swordLogs.map((log, idx) => (
                  <div key={log.id ?? idx} style={{
                    padding: '10px 12px',
                    borderLeft: `3px solid ${
                      log.result === 'success' ? 'var(--status-online)' :
                      log.result === 'failed' ? 'var(--severity-critical)' :
                      'var(--severity-medium)'
                    }`,
                    marginBottom: '8px', background: 'var(--bg-tertiary)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                      <span style={{
                        padding: '2px 8px', fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)',
                        letterSpacing: '1px', color: BOND_GOLD,
                      }}>
                        {log.codename}
                      </span>
                      <span style={{
                        padding: '2px 8px', fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)',
                        letterSpacing: '1px', textTransform: 'uppercase',
                        background: log.result === 'success' ? 'var(--status-online)20' : 'var(--severity-critical)20',
                        color: log.result === 'success' ? 'var(--status-online)' : 'var(--severity-critical)',
                      }}>
                        {log.result}
                      </span>
                      <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                        ESC-LVL: {log.escalation_level}
                      </span>
                      {log.duration_ms !== null && (
                        <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                          {log.duration_ms}ms
                        </span>
                      )}
                      <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                        {log.executed_at ? formatTimestamp(log.executed_at) : ''}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </IntelCard>
        </>
      )}

      {/* ===== OVERWATCH TAB ===== */}
      {activeTab === 'overwatch' && (
        <>
          {/* Overwatch Status */}
          <IntelCard
            title="OVERWATCH"
            classification="CLASSIFIED"
            status={
              overwatchStatus?.status === 'clean' ? 'active' :
              overwatchStatus?.tamper_count && overwatchStatus.tamper_count > 0 ? 'critical' :
              'warning'
            }
          >
            {overwatchStatusLoading && !overwatchStatus ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
                ESTABLISHING OVERWATCH LINK...
              </div>
            ) : overwatchStatus ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Status + Metrics */}
                <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
                  {/* Status badge */}
                  <div style={{
                    padding: '12px 24px', borderRadius: '2px',
                    border: `2px solid ${overwatchStatus.tamper_count > 0 ? 'var(--severity-critical)' : 'var(--status-online)'}`,
                    background: `${overwatchStatus.tamper_count > 0 ? 'var(--severity-critical)' : 'var(--status-online)'}20`,
                  }}>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '2px' }}>SYSTEM INTEGRITY</div>
                    <div style={{
                      fontSize: '28px', fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '4px',
                      color: overwatchStatus.tamper_count > 0 ? 'var(--severity-critical)' : 'var(--status-online)',
                    }}>
                      {overwatchStatus.tamper_count > 0 ? 'TAMPERED' : 'CLEAN'}
                    </div>
                  </div>

                  {/* Metrics */}
                  <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', flex: 1 }}>
                    {[
                      { label: 'FILES BASELINED', value: String(overwatchStatus.files_baselined) },
                      { label: 'TAMPER COUNT', value: String(overwatchStatus.tamper_count) },
                      { label: 'LAST CHECK', value: overwatchStatus.last_check ? formatTimestamp(overwatchStatus.last_check) : 'NEVER' },
                    ].map(m => (
                      <div key={m.label} style={{ padding: '8px 14px', background: 'var(--bg-tertiary)', borderRadius: '2px', textAlign: 'center', flex: '1 1 100px' }}>
                        <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>{m.label}</div>
                        <div style={{
                          fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)',
                          color: m.label === 'TAMPER COUNT' && overwatchStatus.tamper_count > 0 ? 'var(--severity-critical)' : BOND_GOLD,
                        }}>{m.value}</div>
                      </div>
                    ))}
                  </div>

                  {/* Run Check button */}
                  <button
                    onClick={handleOverwatchCheck}
                    disabled={overwatchChecking}
                    style={{
                      padding: '10px 24px', background: BOND_GOLD, border: 'none',
                      color: 'var(--bg-primary)', fontSize: '14px', fontFamily: 'var(--font-mono)',
                      fontWeight: 700, letterSpacing: '2px', flexShrink: 0,
                      cursor: overwatchChecking ? 'not-allowed' : 'pointer',
                      opacity: overwatchChecking ? 0.6 : 1,
                    }}
                  >
                    {overwatchChecking ? 'CHECKING...' : 'RUN CHECK'}
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                OVERWATCH NOT INITIALIZED
              </div>
            )}
          </IntelCard>

          {/* Integrity Report */}
          <IntelCard title="INTEGRITY REPORT" classification="CLASSIFIED">
            {overwatchIntegrityLoading ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                LOADING INTEGRITY DATA...
              </div>
            ) : !overwatchIntegrity ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '2px', textAlign: 'center' }}>
                NO INTEGRITY REPORT AVAILABLE
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {/* Summary */}
                <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                  {[
                    { label: 'TOTAL BASELINED', value: String(overwatchIntegrity.total_baselined), color: BOND_GOLD },
                    { label: 'TAMPERED', value: String(overwatchIntegrity.tampered.length), color: overwatchIntegrity.tampered.length > 0 ? 'var(--severity-critical)' : 'var(--status-online)' },
                    { label: 'MISSING', value: String(overwatchIntegrity.missing.length), color: overwatchIntegrity.missing.length > 0 ? 'var(--severity-high)' : 'var(--status-online)' },
                    { label: 'NEW', value: String(overwatchIntegrity.new.length), color: overwatchIntegrity.new.length > 0 ? 'var(--severity-medium)' : 'var(--status-online)' },
                  ].map(m => (
                    <div key={m.label} style={{ padding: '8px 14px', background: 'var(--bg-tertiary)', borderRadius: '2px', textAlign: 'center', flex: '1 1 100px' }}>
                      <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>{m.label}</div>
                      <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: m.color }}>{m.value}</div>
                    </div>
                  ))}
                </div>

                <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                  CHECKED: {formatTimestamp(overwatchIntegrity.checked_at)}
                </div>

                {/* Tampered files */}
                {overwatchIntegrity.tampered.length > 0 && (
                  <div>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--severity-critical)', letterSpacing: '2px', marginBottom: '6px', fontWeight: 700 }}>
                      TAMPERED FILES
                    </div>
                    <div style={{ maxHeight: '200px', overflow: 'auto', background: 'var(--bg-secondary)', borderRadius: '2px', padding: '8px', border: '1px solid var(--severity-critical)40' }}>
                      {overwatchIntegrity.tampered.map((file, idx) => (
                        <div key={idx} style={{ padding: '3px 0', fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--severity-critical)', wordBreak: 'break-all' }}>
                          {file}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Missing files */}
                {overwatchIntegrity.missing.length > 0 && (
                  <div>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--severity-high)', letterSpacing: '2px', marginBottom: '6px', fontWeight: 700 }}>
                      MISSING FILES
                    </div>
                    <div style={{ maxHeight: '200px', overflow: 'auto', background: 'var(--bg-secondary)', borderRadius: '2px', padding: '8px', border: '1px solid var(--severity-high)40' }}>
                      {overwatchIntegrity.missing.map((file, idx) => (
                        <div key={idx} style={{ padding: '3px 0', fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--severity-high)', wordBreak: 'break-all' }}>
                          {file}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* New files */}
                {overwatchIntegrity.new.length > 0 && (
                  <div>
                    <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--severity-medium)', letterSpacing: '2px', marginBottom: '6px', fontWeight: 700 }}>
                      NEW FILES (UNBASELINED)
                    </div>
                    <div style={{ maxHeight: '200px', overflow: 'auto', background: 'var(--bg-secondary)', borderRadius: '2px', padding: '8px', border: '1px solid var(--severity-medium)40' }}>
                      {overwatchIntegrity.new.map((file, idx) => (
                        <div key={idx} style={{ padding: '3px 0', fontSize: '13px', fontFamily: 'var(--font-mono)', color: 'var(--severity-medium)', wordBreak: 'break-all' }}>
                          {file}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* All clear */}
                {overwatchIntegrity.tampered.length === 0 && overwatchIntegrity.missing.length === 0 && overwatchIntegrity.new.length === 0 && (
                  <div style={{
                    padding: '20px', textAlign: 'center', fontFamily: 'var(--font-mono)',
                    color: 'var(--status-online)', fontSize: '16px', letterSpacing: '2px',
                    background: 'var(--status-online)10', borderRadius: '2px',
                    border: '1px solid var(--status-online)30',
                  }}>
                    ALL FILES VERIFIED -- SYSTEM INTEGRITY INTACT
                  </div>
                )}
              </div>
            )}
          </IntelCard>
        </>
      )}
    </div>
  );
}
