import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';
import { CsvExportButton } from './ui/CsvExportButton';
interface Alert {
  id: number;
  timestamp: string;
  severity: string;
  module_source: string;
  title: string;
  description: string;
  vpn_status_at_event: string | null;
  acknowledged: boolean;
  resolved_at: string | null;
  resolved_by: string | null;
  dismissed: boolean;
  snoozed_until: string | null;
  escalated_to_incident_id: number | null;
  vpn_status?: string | null;
}

const SEVERITY_LEVELS = ['all', 'critical', 'high', 'medium', 'low', 'info'];

const MILITARY_LABELS: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

export function AlertsPanel() {
  const { showToast } = useToast();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [showDismissed, setShowDismissed] = useState(false);
  const [showSnoozed, setShowSnoozed] = useState(false);
  const [bulkLoading, setBulkLoading] = useState<string | null>(null);

  const load = () => {
    const params: Record<string, unknown> = { limit: 100, show_dismissed: showDismissed, show_snoozed: showSnoozed };
    if (filter !== 'all') params.severity = filter;
    api.getAlerts(params as Parameters<typeof api.getAlerts>[0]).then((d: unknown) => setAlerts(d as Alert[])).catch((e: Error) => showToast('error', 'Failed to load alerts', e.message));
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [filter, showDismissed, showSnoozed]);

  const handleAcknowledge = async (ids: number[]) => {
    // Optimistic UI — update state immediately, no lag
    setAlerts(prev => prev.map(a => ids.includes(a.id) ? { ...a, acknowledged: true } : a));
    try {
      await api.acknowledgeAlerts(ids);
      showToast('success', `${ids.length} alert(s) acknowledged`);
    } catch (e: unknown) {
      // Revert on failure
      setAlerts(prev => prev.map(a => ids.includes(a.id) ? { ...a, acknowledged: false } : a));
      showToast('error', 'Failed to acknowledge alert', (e as Error).message);
    }
  };

  const handleDismiss = async (id: number) => {
    // Remove from list immediately if dismissed alerts are hidden
    if (!showDismissed) {
      setAlerts(prev => prev.filter(a => a.id !== id));
    } else {
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, dismissed: true } : a));
    }
    try {
      await api.dismissAlert(id);
      showToast('success', 'Alert dismissed');
    } catch (e: unknown) {
      load(); // Revert by reloading
      showToast('error', 'Failed to dismiss alert', (e as Error).message);
    }
  };

  const handleDismissAll = async () => {
    setBulkLoading('dismiss');
    setAlerts([]);
    try {
      const result = await api.dismissAllAlerts() as { dismissed_count: number };
      showToast('success', `${result.dismissed_count} alert(s) dismissed`);
      setTimeout(load, 500);
    } catch (e: unknown) {
      load();
      showToast('error', 'Failed to dismiss all alerts', (e as Error).message);
    } finally {
      setBulkLoading(null);
    }
  };

  const handleAcknowledgeAll = async () => {
    setBulkLoading('acknowledge');
    setAlerts(prev => prev.map(a => ({ ...a, acknowledged: true })));
    try {
      const result = await api.acknowledgeAllAlerts() as { acknowledged_count: number };
      showToast('success', `${result.acknowledged_count} alert(s) acknowledged`);
    } catch (e: unknown) {
      load();
      showToast('error', 'Failed to acknowledge all alerts', (e as Error).message);
    } finally {
      setBulkLoading(null);
    }
  };

  const handleEscalate = async (id: number) => {
    try {
      const result = await api.escalateAlert(id) as { incident_id?: number };
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, escalated_to_incident_id: result.incident_id ?? -1 } : a));
      showToast('success', 'Alert escalated to incident');
    } catch (e: unknown) { showToast('error', 'Failed to escalate alert', (e as Error).message); }
  };

  const handleSnooze = async (id: number) => {
    setAlerts(prev => prev.filter(a => a.id !== id));
    try {
      await api.snoozeAlert(id);
      showToast('success', 'Alert snoozed for 1 hour');
    } catch (e: unknown) {
      load(); // Revert by reloading on failure
      showToast('error', 'Failed to snooze alert', (e as Error).message);
    }
  };

  const severityColor = (s: string) => {
    const map: Record<string, string> = {
      critical: 'var(--severity-critical)',
      high: 'var(--severity-high)',
      medium: '#f59e0b',
      low: '#3b82f6',
      info: 'var(--severity-info)',
    };
    return map[s] || 'var(--text-muted)';
  };

  return (
    <IntelCard title="THREAT BOARD" classification="SECRET" status={alerts.some((a) => !a.acknowledged && a.severity === 'critical') ? 'critical' : 'active'}>
      {/* CSV Export + Severity Filter Buttons */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '16px', flexWrap: 'wrap', alignItems: 'center' }}>
        <CsvExportButton
          data={alerts as unknown as Record<string, unknown>[]}
          filename="cereberus-alerts"
          columns={[
            { key: 'id', label: 'ID' },
            { key: 'timestamp', label: 'Timestamp' },
            { key: 'severity', label: 'Severity' },
            { key: 'title', label: 'Title' },
            { key: 'module_source', label: 'Source' },
            { key: 'description', label: 'Description' },
            { key: 'acknowledged', label: 'Acknowledged' },
          ]}
        />
      </div>
      <div style={{ display: 'flex', gap: '6px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {SEVERITY_LEVELS.map((level) => (
          <button
            key={level}
            onClick={() => setFilter(level)}
            style={{
              padding: '4px 12px',
              fontSize: '16px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '1px',
              textTransform: 'uppercase',
              background: filter === level ? (level === 'all' ? 'var(--red-dark)' : severityColor(level)) : 'var(--bg-tertiary)',
              color: filter === level ? '#fff' : 'var(--text-secondary)',
              border: `1px solid ${filter === level ? 'transparent' : 'var(--border-default)'}`,
              borderRadius: '2px',
              cursor: 'pointer',
            }}
          >
            {MILITARY_LABELS[level]?.label || 'ALL'}
          </button>
        ))}
      </div>

      {/* Triage Filters */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', cursor: 'pointer' }}>
          <input type="checkbox" checked={showDismissed} onChange={(e) => setShowDismissed(e.target.checked)} />
          SHOW DISMISSED
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', cursor: 'pointer' }}>
          <input type="checkbox" checked={showSnoozed} onChange={(e) => setShowSnoozed(e.target.checked)} />
          SHOW SNOOZED
        </label>
      </div>

      {/* Bulk Operations */}
      {alerts.length > 0 && (
        <div style={{ marginBottom: '12px', display: 'flex', gap: '8px' }}>
          {alerts.some((a) => !a.acknowledged) && (
            <button
              onClick={handleAcknowledgeAll}
              disabled={bulkLoading !== null}
              style={{
                padding: '5px 14px',
                fontSize: '16px',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '1px',
                background: 'var(--bg-tertiary)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-default)',
                borderRadius: '2px',
                cursor: bulkLoading ? 'not-allowed' : 'pointer',
                textTransform: 'uppercase',
              }}
            >
              {bulkLoading === 'acknowledge' ? 'ACKNOWLEDGING...' : 'ACKNOWLEDGE ALL'}
            </button>
          )}
          <button
            onClick={handleDismissAll}
            disabled={bulkLoading !== null}
            style={{
              padding: '5px 14px',
              fontSize: '16px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '1px',
              background: 'var(--severity-critical)',
              color: '#fff',
              border: '1px solid var(--severity-critical)',
              borderRadius: '2px',
              cursor: bulkLoading ? 'not-allowed' : 'pointer',
              textTransform: 'uppercase',
              fontWeight: 700,
            }}
          >
            {bulkLoading === 'dismiss' ? 'DISMISSING...' : 'DISMISS ALL'}
          </button>
        </div>
      )}

      {/* Alert List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {alerts.length === 0 && (
          <div style={{
            padding: '40px',
            textAlign: 'center',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            fontSize: '17px',
            letterSpacing: '2px',
          }}>
            NO THREATS MATCHING FILTER
          </div>
        )}
        {alerts.map((a) => {
          const mil = MILITARY_LABELS[a.severity] || MILITARY_LABELS.info;
          const isNeutralized = !!a.resolved_by;
          return (
            <div
              key={a.id}
              className={!a.acknowledged && !isNeutralized ? 'alert-pulse' : isNeutralized ? 'threat-neutralized' : ''}
              style={{
                background: isNeutralized ? 'rgba(0, 200, 83, 0.05)' : 'var(--bg-tertiary)',
                border: `1px solid ${isNeutralized ? 'var(--status-online)' : !a.acknowledged ? 'var(--amber-primary)' : 'var(--border-default)'}`,
                borderLeft: `3px solid ${isNeutralized ? 'var(--status-online)' : severityColor(a.severity)}`,
                borderRadius: '2px',
                padding: '10px 14px',
                opacity: isNeutralized ? 0.7 : a.acknowledged ? 0.5 : 1,
              }}
            >
              <div
                style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
                onClick={() => setExpandedId(expandedId === a.id ? null : a.id)}
              >
                {isNeutralized ? (
                  <span className="stamp-badge stamp-cleared">NEUTRALIZED</span>
                ) : (
                  <span className={`stamp-badge ${mil.stampClass}`}>{mil.label}</span>
                )}
                <span style={{ fontSize: '18px', color: isNeutralized ? 'var(--status-online)' : 'var(--text-primary)', flex: 1 }}>
                  {a.title}
                </span>
                <span style={{ fontSize: '16px', color: 'var(--cyan-primary)', fontFamily: 'var(--font-mono)' }}>
                  {a.module_source}
                </span>
                <span style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
                </span>
                {!a.acknowledged && !isNeutralized && (
                  <button
                    onClick={(e) => { e.stopPropagation(); handleAcknowledge([a.id]); }}
                    style={{
                      padding: '2px 8px',
                      fontSize: '15px',
                      fontFamily: 'var(--font-mono)',
                      letterSpacing: '1px',
                      background: 'var(--bg-elevated)',
                      color: 'var(--text-muted)',
                      border: '1px solid var(--border-default)',
                      borderRadius: '2px',
                      cursor: 'pointer',
                    }}
                  >
                    ACKNOWLEDGE
                  </button>
                )}
              </div>
              {expandedId === a.id && (
                <div style={{
                  marginTop: '10px',
                  paddingTop: '10px',
                  borderTop: '1px solid var(--border-default)',
                }}>
                  <div style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '15px',
                    letterSpacing: '2px',
                    color: 'var(--text-muted)',
                    marginBottom: '6px',
                  }}>
                    CLASSIFIED DETAILS
                  </div>
                  <div style={{
                    fontSize: '18px',
                    color: 'var(--text-secondary)',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 1.6,
                  }}>
                    {a.description}
                  </div>
                  {isNeutralized && a.resolved_at && (
                    <div style={{ marginTop: '8px', fontSize: '15px', color: 'var(--status-online)', fontFamily: 'var(--font-mono)', letterSpacing: '1px', fontWeight: 700 }}>
                      NEUTRALIZED BY {a.resolved_by} AT {new Date(a.resolved_at).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
                    </div>
                  )}
                  {a.vpn_status && (
                    <div style={{ marginTop: '6px', fontSize: '17px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      VPN STATUS: {a.vpn_status}
                    </div>
                  )}
                  {a.escalated_to_incident_id && (
                    <div style={{ marginTop: '6px', fontSize: '15px', color: 'var(--cyan-primary)', fontFamily: 'var(--font-mono)' }}>
                      ESCALATED TO INCIDENT #{a.escalated_to_incident_id}
                    </div>
                  )}
                  {/* Triage Actions — hidden for neutralized alerts (Bond handled it) */}
                  {!isNeutralized && (
                    <div style={{ display: 'flex', gap: '8px', marginTop: '10px' }}>
                      {!a.dismissed && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleDismiss(a.id); }}
                          style={{ padding: '3px 10px', fontSize: '14px', fontFamily: 'var(--font-mono)', letterSpacing: '1px', background: 'var(--bg-elevated)', color: 'var(--text-muted)', border: '1px solid var(--border-default)', borderRadius: '2px', cursor: 'pointer' }}
                        >
                          DISMISS
                        </button>
                      )}
                      {!a.escalated_to_incident_id && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleEscalate(a.id); }}
                          style={{ padding: '3px 10px', fontSize: '14px', fontFamily: 'var(--font-mono)', letterSpacing: '1px', background: 'var(--red-dark)', color: '#fff', border: '1px solid var(--severity-critical)', borderRadius: '2px', cursor: 'pointer' }}
                        >
                          ESCALATE
                        </button>
                      )}
                      <button
                        onClick={(e) => { e.stopPropagation(); handleSnooze(a.id); }}
                        style={{ padding: '3px 10px', fontSize: '14px', fontFamily: 'var(--font-mono)', letterSpacing: '1px', background: 'var(--bg-elevated)', color: '#f59e0b', border: '1px solid #f59e0b33', borderRadius: '2px', cursor: 'pointer' }}
                      >
                        SNOOZE 1H
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </IntelCard>
  );
}
