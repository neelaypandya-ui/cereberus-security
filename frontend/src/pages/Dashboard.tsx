import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { useNotifications } from '../hooks/useNotifications';
import { usePermissions } from '../hooks/usePermissions';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import { useSessionTimeout } from '../hooks/useSessionTimeout';
import { PanelErrorBoundary } from '../components/PanelErrorBoundary';
import { VpnStatusPanel } from '../components/VpnStatusPanel/VpnStatusPanel';
import { OverviewPanel } from '../components/OverviewPanel';
import { NetworkPanel } from '../components/NetworkPanel';
import { AlertsPanel } from '../components/AlertsPanel';
import { VpnDetailPanel } from '../components/VpnDetailPanel';
import { ModulesPanel } from '../components/ModulesPanel';
import { SettingsPanel } from '../components/SettingsPanel';
import { ProcessesPanel } from '../components/ProcessesPanel';
import { VulnerabilityPanel } from '../components/VulnerabilityPanel';
import { ThreatIntelPanel } from '../components/ThreatIntelPanel';
import { ResourcePanel } from '../components/ResourcePanel';
import { PersistencePanel } from '../components/PersistencePanel';
import { AnalyticsPanel } from '../components/AnalyticsPanel';
import { EmailAnalyzerPanel } from '../components/EmailAnalyzerPanel';
import { AuditLogPanel } from '../components/AuditLogPanel';
import { AiOpsPanel } from '../components/AiOpsPanel';
import { IncidentResponsePanel } from '../components/IncidentResponsePanel';
import { PlaybookPanel } from '../components/PlaybookPanel';
import { IntegrationSettingsPanel } from '../components/IntegrationSettingsPanel';
import { UserManagementPanel } from '../components/UserManagementPanel';
import { SearchBar } from '../components/SearchBar';
import { NotificationBell } from '../components/notifications/NotificationBell';
import { StatusTicker } from '../components/ui/StatusTicker';
import '../components/notifications/notifications.css';

interface DashboardSummary {
  alerts: Record<string, number>;
  events_today: number;
  modules: Array<{ name: string; enabled: boolean; health: string }>;
  vpn: {
    connected: boolean;
    protocol: string | null;
    provider: string | null;
    vpn_ip: string | null;
    interface_name?: string | null;
  };
}

const NAV_ITEMS = [
  { id: 'overview', label: 'CMD CENTER', icon: '\u25C6', fullLabel: 'Command Center' },
  { id: 'network', label: 'SIGINT', icon: '\u26A1', fullLabel: 'Signals Intelligence' },
  { id: 'processes', label: 'ASSET TRKR', icon: '\u2699', fullLabel: 'Asset Tracker' },
  { id: 'vulnerabilities', label: 'THREAT ASMT', icon: '\u26A0', fullLabel: 'Threat Assessment' },
  { id: 'threats', label: 'FUSION CTR', icon: '\u2620', fullLabel: 'Fusion Center' },
  { id: 'resources', label: 'SYS DIAG', icon: '\u{1F4CA}', fullLabel: 'Systems Diagnostics' },
  { id: 'persistence', label: 'WATCHLIST', icon: '\u{1F512}', fullLabel: 'Watchlist' },
  { id: 'analytics', label: 'INTEL BRIEF', icon: '\u{1F4C8}', fullLabel: 'Intelligence Briefing' },
  { id: 'email', label: 'COMINT', icon: '\u2709', fullLabel: 'COMINT Analysis' },
  { id: 'alerts', label: 'THREAT BOARD', icon: '\u26A1', fullLabel: 'Threat Board' },
  { id: 'audit', label: 'OPS LOG', icon: '\u{1F4DD}', fullLabel: 'Operations Log' },
  { id: 'vpn', label: 'SEC COMMS', icon: '\u2693', fullLabel: 'Secure Comms' },
  { id: 'aiops', label: 'AI OPS', icon: '\u{1F9E0}', fullLabel: 'AI Operations Center' },
  { id: 'incidents', label: 'INCIDENT CMD', icon: '\u{1F6A8}', fullLabel: 'Incident Command' },
  { id: 'playbooks', label: 'DEF PROTOCOL', icon: '\u{1F6E1}', fullLabel: 'Defense Protocols' },
  { id: 'integrations', label: 'SIGNAL RELAY', icon: '\u{1F4E1}', fullLabel: 'Signal Relay' },
  { id: 'personnel', label: 'PERSONNEL', icon: '\u{1F464}', fullLabel: 'Personnel Management', adminOnly: true },
  { id: 'modules', label: 'OPS BOARD', icon: '\u2630', fullLabel: 'Operations Board' },
  { id: 'settings', label: 'SYS CONFIG', icon: '\u2699', fullLabel: 'System Configuration' },
] as const;

const PANEL_CODES: Record<string, string> = {
  overview: 'SEC-01',
  network: 'SIG-02',
  processes: 'AST-03',
  vulnerabilities: 'THR-04',
  threats: 'FUS-05',
  resources: 'DIA-06',
  persistence: 'WCH-07',
  analytics: 'INT-08',
  email: 'COM-09',
  alerts: 'ALT-10',
  audit: 'OPS-11',
  vpn: 'VPN-12',
  aiops: 'AIO-15',
  incidents: 'INC-16',
  playbooks: 'PLB-17',
  integrations: 'SRL-18',
  personnel: 'PER-19',
  modules: 'MOD-13',
  settings: 'CFG-14',
};

function useUtcClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);
  return time;
}

function useUptime() {
  const start = useRef(Date.now());
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => setElapsed(Date.now() - start.current), 1000);
    return () => clearInterval(interval);
  }, []);
  const hrs = Math.floor(elapsed / 3600000);
  const mins = Math.floor((elapsed % 3600000) / 60000);
  const secs = Math.floor((elapsed % 60000) / 1000);
  return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function Dashboard() {
  const navigate = useNavigate();
  const [activeNav, setActiveNav] = useState('overview');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const { vpnStatus, networkStats, threatLevel, alerts: wsAlerts, aiStatus, predictions, trainingProgress } = useWebSocket();
  const { notifications, unreadCount, markRead, markAllRead } = useNotifications();
  const { hasPermission, role } = usePermissions();
  const utcTime = useUtcClock();
  const uptime = useUptime();

  const prevAlertCount = useRef(0);
  const searchRef = useRef<HTMLInputElement>(null);

  // Ghost Protocol — session self-destructs after 15 min inactivity
  useSessionTimeout(() => {
    api.logout().catch(() => {});
    localStorage.removeItem('cereberus_token');
    navigate('/login');
  });

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onFocusSearch: () => searchRef.current?.focus(),
    onPanelSwitch: (index) => {
      const filteredNav = NAV_ITEMS.filter(n => !('adminOnly' in n && n.adminOnly) || role === 'admin');
      if (index < filteredNav.length) setActiveNav(filteredNav[index].id);
    },
    onExport: () => setActiveNav('integrations'),
  });

  // Build ticker events from recent WS alerts
  const tickerEvents = wsAlerts.slice(0, 10).map((a) => ({
    time: new Date(a.timestamp || Date.now()).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }),
    module: (a.module_source || 'SYSTEM').toUpperCase(),
    message: a.title || a.description || 'Event detected',
  }));

  useEffect(() => {
    loadSummary();
    const interval = setInterval(loadSummary, 30000);
    return () => clearInterval(interval);
  }, []);

  // Track alert count for ticker — no toast popups
  useEffect(() => {
    prevAlertCount.current = wsAlerts.length;
  }, [wsAlerts]);

  useEffect(() => {
    if (threatLevel === 'high' || threatLevel === 'critical') {
      document.body.classList.add('threat-active');
    } else {
      document.body.classList.remove('threat-active');
    }
    return () => document.body.classList.remove('threat-active');
  }, [threatLevel]);

  const loadSummary = async () => {
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch {
      // Token might be expired
    }
  };

  const handleLogout = () => {
    api.logout().catch(() => {});
    localStorage.removeItem('cereberus_token');
    navigate('/login');
  };

  const getModuleHealth = (navId: string): string => {
    if (!summary) return 'unknown';
    const moduleMap: Record<string, string> = {
      network: 'network_sentinel',
      processes: 'process_analyzer',
      vulnerabilities: 'vuln_scanner',
      threats: 'threat_intelligence',
      resources: 'resource_monitor',
      persistence: 'persistence_scanner',
      email: 'email_analyzer',
      vpn: 'vpn_guardian',
    };
    const moduleName = moduleMap[navId];
    if (!moduleName) return 'none';
    const mod = summary.modules.find((m) => m.name === moduleName);
    if (!mod) return 'unknown';
    if (!mod.enabled) return 'offline';
    return mod.health;
  };

  const healthDotColor = (health: string): string => {
    if (health === 'running') return 'var(--status-online)';
    if (health === 'error') return 'var(--severity-critical)';
    if (health === 'offline' || health === 'stopped') return 'var(--text-muted)';
    if (health === 'none') return 'transparent';
    return 'var(--amber-primary)';
  };

  // Filter nav items based on permissions
  const visibleNavItems = NAV_ITEMS.filter(n => {
    if ('adminOnly' in n && n.adminOnly && role !== 'admin') return false;
    return true;
  });

  const currentNav = NAV_ITEMS.find((n) => n.id === activeNav);
  const utcStr = utcTime.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' });

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Scan-line + Hex Grid overlays */}
      <div className="scan-line-overlay" />
      <div className="hex-grid-overlay" />

      {/* Toast notifications disabled — alerts visible on THREAT BOARD */}

      {/* Sidebar */}
      <aside style={{
        width: 'var(--sidebar-width)',
        background: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border-default)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        zIndex: 10,
      }}>
        {/* Logo */}
        <div style={{
          padding: '16px 16px 12px',
          borderBottom: '1px solid var(--border-default)',
          textAlign: 'center',
        }}>
          <div style={{ display: 'inline-block' }} className="logo-ring">
            <img
              src="/logo.jpg"
              alt="CEREBERUS"
              style={{ width: '44px', borderRadius: '50%' }}
            />
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '14px',
            fontWeight: 700,
            letterSpacing: '4px',
            color: 'var(--red-primary)',
            marginTop: '8px',
          }}>
            CEREBERUS
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '8px',
            letterSpacing: '3px',
            color: 'var(--text-muted)',
            marginTop: '2px',
          }}>
            DEFENSE NETWORK
          </div>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '4px',
            marginTop: '6px',
          }}>
            <div className="online-blink" style={{
              width: '5px',
              height: '5px',
              borderRadius: '50%',
              backgroundColor: 'var(--status-online)',
            }} />
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '8px',
              letterSpacing: '2px',
              color: 'var(--status-online)',
            }}>
              ONLINE
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '8px 8px', overflowY: 'auto' }}>
          {visibleNavItems.map((item) => {
            const isActive = activeNav === item.id;
            const health = getModuleHealth(item.id);
            return (
              <button
                key={item.id}
                onClick={() => setActiveNav(item.id)}
                className={isActive ? 'nav-item-active' : ''}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  width: '100%',
                  padding: '8px 10px',
                  background: isActive ? undefined : 'transparent',
                  border: 'none',
                  borderLeft: isActive ? undefined : '2px solid transparent',
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  letterSpacing: '1px',
                  cursor: 'pointer',
                  borderRadius: '0 2px 2px 0',
                  textAlign: 'left',
                  transition: 'all 0.15s ease',
                }}
              >
                <span style={{ fontSize: '12px', width: '16px', textAlign: 'center', flexShrink: 0 }}>{item.icon}</span>
                <span style={{ flex: 1 }}>{item.label}</span>
                {health !== 'none' && health !== 'transparent' && (
                  <div style={{
                    width: '5px',
                    height: '5px',
                    borderRadius: '50%',
                    backgroundColor: healthDotColor(health),
                    flexShrink: 0,
                  }} />
                )}
              </button>
            );
          })}
        </nav>

        {/* Logout */}
        <div style={{ padding: '8px 8px', borderTop: '1px solid var(--border-default)' }}>
          <button
            onClick={handleLogout}
            style={{
              width: '100%',
              padding: '6px 10px',
              background: 'transparent',
              border: '1px solid var(--border-default)',
              borderRadius: '2px',
              color: 'var(--text-muted)',
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '2px',
              cursor: 'pointer',
              textTransform: 'uppercase',
            }}
          >
            Disconnect
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', zIndex: 10 }}>
        {/* Classification Banner */}
        <div className="classification-banner" style={{ flexShrink: 0 }}>
          TOP SECRET // SCI // CEREBERUS DEFENSE NETWORK // NOFORN
        </div>

        {/* Header */}
        <header style={{
          height: 'var(--header-height)',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-default)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 20px',
          flexShrink: 0,
          gap: '16px',
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,229,255,0.01) 3px, rgba(0,229,255,0.01) 4px)',
        }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', flexShrink: 0 }}>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '10px',
              color: 'var(--text-muted)',
              letterSpacing: '1px',
            }}>
              [{PANEL_CODES[activeNav] || 'SYS-00'}]
            </span>
            <h1 style={{
              fontSize: '14px',
              fontWeight: 600,
              letterSpacing: '2px',
              fontFamily: 'var(--font-mono)',
            }}>
              {currentNav?.fullLabel?.toUpperCase() || activeNav.toUpperCase()}
            </h1>
          </div>

          <SearchBar onNavigate={setActiveNav} />

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexShrink: 0 }}>
            {/* UTC Clock */}
            <div style={{ textAlign: 'right' }}>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '14px',
                fontWeight: 700,
                color: 'var(--cyan-primary)',
                letterSpacing: '2px',
              }}>
                {utcStr}
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '8px',
                color: 'var(--text-muted)',
                letterSpacing: '1px',
              }}>
                UTC | UP {uptime}
              </div>
            </div>

            <div style={{ width: '1px', height: '24px', background: 'var(--border-default)' }} />

            <NotificationBell
              notifications={notifications}
              unreadCount={unreadCount}
              onMarkRead={markRead}
              onMarkAllRead={markAllRead}
            />
            <VpnStatusPanel
              connected={vpnStatus?.connected ?? summary?.vpn?.connected ?? false}
              protocol={vpnStatus?.protocol ?? summary?.vpn?.protocol ?? null}
              vpnIp={vpnStatus?.vpn_ip ?? summary?.vpn?.vpn_ip ?? null}
              provider={vpnStatus?.provider ?? summary?.vpn?.provider ?? null}
            />
          </div>
        </header>

        {/* Content Area */}
        <div style={{ flex: 1, overflow: 'auto', padding: '20px', paddingBottom: 'calc(20px + var(--ticker-height))' }}>
          {activeNav === 'overview' && summary && (
            <PanelErrorBoundary panelName="CMD CENTER">
              <OverviewPanel
                alerts={summary.alerts}
                eventsToday={summary.events_today}
                modules={summary.modules}
                networkStats={networkStats}
                threatLevel={threatLevel}
              />
            </PanelErrorBoundary>
          )}
          {activeNav === 'network' && <PanelErrorBoundary panelName="SIGINT"><NetworkPanel /></PanelErrorBoundary>}
          {activeNav === 'processes' && <PanelErrorBoundary panelName="ASSET TRACKER"><ProcessesPanel /></PanelErrorBoundary>}
          {activeNav === 'vulnerabilities' && <PanelErrorBoundary panelName="THREAT ASSESSMENT"><VulnerabilityPanel /></PanelErrorBoundary>}
          {activeNav === 'threats' && <PanelErrorBoundary panelName="FUSION CENTER"><ThreatIntelPanel /></PanelErrorBoundary>}
          {activeNav === 'resources' && <PanelErrorBoundary panelName="SYS DIAGNOSTICS"><ResourcePanel /></PanelErrorBoundary>}
          {activeNav === 'persistence' && <PanelErrorBoundary panelName="WATCHLIST"><PersistencePanel /></PanelErrorBoundary>}
          {activeNav === 'analytics' && <PanelErrorBoundary panelName="INTEL BRIEFING"><AnalyticsPanel /></PanelErrorBoundary>}
          {activeNav === 'email' && <PanelErrorBoundary panelName="COMINT"><EmailAnalyzerPanel /></PanelErrorBoundary>}
          {activeNav === 'alerts' && <PanelErrorBoundary panelName="THREAT BOARD"><AlertsPanel /></PanelErrorBoundary>}
          {activeNav === 'audit' && <PanelErrorBoundary panelName="OPS LOG"><AuditLogPanel /></PanelErrorBoundary>}
          {activeNav === 'aiops' && (
            <PanelErrorBoundary panelName="AI OPS">
              <AiOpsPanel
                aiStatus={aiStatus}
                predictions={predictions}
                trainingProgress={trainingProgress}
              />
            </PanelErrorBoundary>
          )}
          {activeNav === 'vpn' && <PanelErrorBoundary panelName="SEC COMMS"><VpnDetailPanel /></PanelErrorBoundary>}
          {activeNav === 'incidents' && <PanelErrorBoundary panelName="INCIDENT CMD"><IncidentResponsePanel /></PanelErrorBoundary>}
          {activeNav === 'playbooks' && <PanelErrorBoundary panelName="DEF PROTOCOL"><PlaybookPanel /></PanelErrorBoundary>}
          {activeNav === 'integrations' && <PanelErrorBoundary panelName="SIGNAL RELAY"><IntegrationSettingsPanel /></PanelErrorBoundary>}
          {activeNav === 'personnel' && hasPermission('manage_users') && <PanelErrorBoundary panelName="PERSONNEL"><UserManagementPanel /></PanelErrorBoundary>}
          {activeNav === 'modules' && <PanelErrorBoundary panelName="OPS BOARD"><ModulesPanel /></PanelErrorBoundary>}
          {activeNav === 'settings' && <PanelErrorBoundary panelName="SYS CONFIG"><SettingsPanel /></PanelErrorBoundary>}
        </div>

        {/* Status Ticker */}
        <StatusTicker events={tickerEvents} />
      </main>
    </div>
  );
}

export default Dashboard;
