import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
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

interface DashboardSummary {
  alerts: Record<string, number>;
  events_today: number;
  modules: Array<{ name: string; enabled: boolean; health: string }>;
  vpn: {
    connected: boolean;
    protocol: string | null;
    provider: string | null;
    vpn_ip: string | null;
    interface_name: string | null;
  };
}

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: '\u25C6' },
  { id: 'network', label: 'Network', icon: '\u26A1' },
  { id: 'processes', label: 'Processes', icon: '\u2699' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '\u26A0' },
  { id: 'threats', label: 'Threats', icon: '\u2620' },
  { id: 'alerts', label: 'Alerts', icon: '\u26A1' },
  { id: 'vpn', label: 'VPN', icon: '\u2693' },
  { id: 'modules', label: 'Modules', icon: '\u2630' },
  { id: 'settings', label: 'Settings', icon: '\u2699' },
];

function Dashboard() {
  const navigate = useNavigate();
  const [activeNav, setActiveNav] = useState('overview');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const { vpnStatus, networkStats, threatLevel } = useWebSocket();

  useEffect(() => {
    loadSummary();
    const interval = setInterval(loadSummary, 30000);
    return () => clearInterval(interval);
  }, []);

  // Toggle body class for threat-active styling
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
    localStorage.removeItem('cereberus_token');
    navigate('/login');
  };

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Scan-line + Grid overlays */}
      <div className="scan-line-overlay" />
      <div className="grid-overlay" />

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
          padding: '20px 16px',
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
            THE GUARDIAN SENTINEL
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }}>
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveNav(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                width: '100%',
                padding: '10px 12px',
                background: activeNav === item.id ? 'var(--bg-hover)' : 'transparent',
                border: 'none',
                borderLeft: activeNav === item.id ? '2px solid var(--cyan-primary)' : '2px solid transparent',
                color: activeNav === item.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontSize: '13px',
                fontFamily: 'var(--font-sans)',
                cursor: 'pointer',
                borderRadius: '0 4px 4px 0',
                textAlign: 'left',
                transition: 'all 0.15s ease',
              }}
            >
              <span style={{ fontSize: '13px', width: '18px', textAlign: 'center' }}>{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        {/* Logout */}
        <div style={{ padding: '12px 8px', borderTop: '1px solid var(--border-default)' }}>
          <button
            onClick={handleLogout}
            style={{
              width: '100%',
              padding: '8px 12px',
              background: 'transparent',
              border: '1px solid var(--border-default)',
              borderRadius: '4px',
              color: 'var(--text-muted)',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            Logout
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', zIndex: 10 }}>
        {/* Header */}
        <header style={{
          height: 'var(--header-height)',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-default)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 24px',
          flexShrink: 0,
        }}>
          <h1 style={{ fontSize: '16px', fontWeight: 600, letterSpacing: '1px' }}>
            {activeNav.toUpperCase()}
          </h1>

          <VpnStatusPanel
            connected={vpnStatus?.connected ?? summary?.vpn?.connected ?? false}
            protocol={vpnStatus?.protocol ?? summary?.vpn?.protocol ?? null}
            vpnIp={vpnStatus?.vpn_ip ?? summary?.vpn?.vpn_ip ?? null}
            provider={vpnStatus?.provider ?? summary?.vpn?.provider ?? null}
          />
        </header>

        {/* Content Area */}
        <div style={{ flex: 1, overflow: 'auto', padding: '24px' }}>
          {activeNav === 'overview' && summary && (
            <OverviewPanel
              alerts={summary.alerts}
              eventsToday={summary.events_today}
              modules={summary.modules}
              networkStats={networkStats}
              threatLevel={threatLevel}
            />
          )}
          {activeNav === 'network' && <NetworkPanel />}
          {activeNav === 'processes' && <ProcessesPanel />}
          {activeNav === 'vulnerabilities' && <VulnerabilityPanel />}
          {activeNav === 'threats' && <ThreatIntelPanel />}
          {activeNav === 'alerts' && <AlertsPanel />}
          {activeNav === 'vpn' && <VpnDetailPanel />}
          {activeNav === 'modules' && <ModulesPanel />}
          {activeNav === 'settings' && <SettingsPanel />}
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
