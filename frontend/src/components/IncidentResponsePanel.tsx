import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';

interface Incident {
  id: number;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  category: string | null;
  assigned_to: string | null;
  source_alert_ids: number[];
  remediation_actions: number[];
  timeline: Array<{ event: string; actor: string; timestamp: string; [key: string]: unknown }>;
  notes: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string | null;
  resolved_at: string | null;
}

interface IncidentStats {
  total: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
}

const STATUS_COLORS: Record<string, string> = {
  open: 'var(--severity-critical)',
  investigating: 'var(--amber-primary)',
  contained: 'var(--cyan-primary)',
  resolved: 'var(--status-online)',
  closed: 'var(--text-muted)',
};

const SEVERITY_STAMPS: Record<string, string> = {
  critical: 'stamp-flash',
  high: 'stamp-immediate',
  medium: 'stamp-priority',
  low: 'stamp-routine',
};

export function IncidentResponsePanel() {
  const { showToast } = useToast();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<IncidentStats | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [showCreate, setShowCreate] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState('high');
  const [newDescription, setNewDescription] = useState('');
  const [noteText, setNoteText] = useState('');
  const [assignUser, setAssignUser] = useState('');
  const [linkAlertInput, setLinkAlertInput] = useState('');

  // Linked alerts from the API
  interface LinkedAlert {
    id: number;
    timestamp: string;
    severity: string;
    module_source: string;
    title: string;
    acknowledged: boolean;
  }
  const [linkedAlerts, setLinkedAlerts] = useState<LinkedAlert[]>([]);

  const load = useCallback(async () => {
    try {
      const [inc, st] = await Promise.all([
        api.getIncidents({ status: statusFilter || undefined, limit: 50 }),
        api.getIncidentStats(),
      ]);
      setIncidents(inc as Incident[]);
      setStats(st as IncidentStats);
    } catch (e: unknown) { showToast('error', 'Failed to load incidents', (e as Error).message); }
  }, [statusFilter, showToast]);

  useEffect(() => { load(); const i = setInterval(load, 15000); return () => clearInterval(i); }, [load]);

  const selected = incidents.find(i => i.id === selectedId) || null;

  const loadLinkedAlerts = useCallback(async (incidentId: number) => {
    try {
      const data = await api.getLinkedAlerts(incidentId);
      setLinkedAlerts((data as { alerts: LinkedAlert[] }).alerts || []);
    } catch { setLinkedAlerts([]); }
  }, []);

  useEffect(() => {
    if (selectedId) {
      loadLinkedAlerts(selectedId);
    } else {
      setLinkedAlerts([]);
    }
  }, [selectedId, loadLinkedAlerts]);

  const handleCreate = async () => {
    if (!newTitle) return;
    try {
      await api.createIncident({ title: newTitle, severity: newSeverity, description: newDescription });
      setShowCreate(false);
      setNewTitle('');
      setNewDescription('');
      load();
      showToast('success', 'Incident created');
    } catch (e: unknown) { showToast('error', 'Failed to create incident', (e as Error).message); }
  };

  const handleStatusChange = async (id: number, newStatus: string) => {
    try {
      await api.updateIncidentStatus(id, newStatus);
      load();
      showToast('success', `Incident status changed to ${newStatus}`);
    } catch (e: unknown) { showToast('error', 'Failed to update status', (e as Error).message); }
  };

  const handleAssign = async (id: number) => {
    if (!assignUser) return;
    try {
      await api.assignIncident(id, assignUser);
      setAssignUser('');
      load();
      showToast('success', `Incident assigned to ${assignUser}`);
    } catch (e: unknown) { showToast('error', 'Failed to assign incident', (e as Error).message); }
  };

  const handleLinkAlerts = async (id: number) => {
    if (!linkAlertInput.trim()) return;
    const alertIds = linkAlertInput.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    if (alertIds.length === 0) return;
    try {
      await api.linkAlertsToIncident(id, alertIds);
      setLinkAlertInput('');
      loadLinkedAlerts(id);
      showToast('success', `Linked ${alertIds.length} alert(s)`);
    } catch (e: unknown) { showToast('error', 'Failed to link alerts', (e as Error).message); }
  };

  const handleAddNote = async (id: number) => {
    if (!noteText) return;
    try {
      await api.addIncidentNote(id, noteText);
      setNoteText('');
      load();
      showToast('success', 'Note added');
    } catch (e: unknown) { showToast('error', 'Failed to add note', (e as Error).message); }
  };

  const statItems = [
    { label: 'TOTAL', value: stats?.total || 0, color: 'var(--text-primary)' },
    { label: 'OPEN', value: stats?.by_status?.open || 0, color: 'var(--severity-critical)' },
    { label: 'INVESTIGATING', value: stats?.by_status?.investigating || 0, color: 'var(--amber-primary)' },
    { label: 'CONTAINED', value: stats?.by_status?.contained || 0, color: 'var(--cyan-primary)' },
    { label: 'RESOLVED', value: stats?.by_status?.resolved || 0, color: 'var(--status-online)' },
  ];

  return (
    <IntelCard title="INCIDENT COMMAND" classification="SECRET // NOFORN">
      {/* Stats Bar */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {statItems.map(s => (
          <div key={s.label} className="instrument-readout" style={{ padding: '8px 14px', minWidth: '90px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '26px', fontWeight: 700, color: s.color }}>{s.value}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--text-muted)', letterSpacing: '1px' }}>{s.label}</div>
          </div>
        ))}
        <div style={{ flex: 1, display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '8px' }}>
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="terminal-input"
            style={{ padding: '4px 8px', fontSize: '16px', width: '130px' }}
          >
            <option value="">ALL STATUS</option>
            <option value="open">OPEN</option>
            <option value="investigating">INVESTIGATING</option>
            <option value="contained">CONTAINED</option>
            <option value="resolved">RESOLVED</option>
            <option value="closed">CLOSED</option>
          </select>
          <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowCreate(!showCreate)}>
            + NEW INCIDENT
          </button>
        </div>
      </div>

      {/* Create Form */}
      {showCreate && (
        <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '16px', borderRadius: '2px' }}>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
            <input className="terminal-input" placeholder="Incident title..." value={newTitle} onChange={e => setNewTitle(e.target.value)} style={{ flex: 1, padding: '6px 8px', fontSize: '17px' }} />
            <select className="terminal-input" value={newSeverity} onChange={e => setNewSeverity(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
              <option value="critical">CRITICAL</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
            </select>
          </div>
          <textarea className="terminal-input" placeholder="Description..." value={newDescription} onChange={e => setNewDescription(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '17px', minHeight: '60px', resize: 'vertical', boxSizing: 'border-box' }} />
          <div style={{ marginTop: '8px', display: 'flex', gap: '8px' }}>
            <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={handleCreate}>CREATE</button>
            <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowCreate(false)}>CANCEL</button>
          </div>
        </div>
      )}

      {/* Incidents Table */}
      <div style={{ display: 'flex', gap: '16px' }}>
        <div style={{ flex: selectedId ? 1 : 2 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '17px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-default)' }}>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '1px' }}>ID</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '1px' }}>SEVERITY</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '1px' }}>TITLE</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '1px' }}>STATUS</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '1px' }}>ASSIGNED</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px', letterSpacing: '1px' }}>CREATED</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map(inc => (
                <tr
                  key={inc.id}
                  onClick={() => setSelectedId(selectedId === inc.id ? null : inc.id)}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    background: selectedId === inc.id ? 'rgba(0,229,255,0.05)' : 'transparent',
                  }}
                >
                  <td style={{ padding: '6px', color: 'var(--text-muted)' }}>#{inc.id}</td>
                  <td style={{ padding: '6px' }}>
                    <span className={`stamp-badge ${SEVERITY_STAMPS[inc.severity] || 'stamp-routine'}`} style={{ fontSize: '14px' }}>
                      {inc.severity.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '6px', color: 'var(--text-primary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.title}</td>
                  <td style={{ padding: '6px' }}>
                    <span style={{ color: STATUS_COLORS[inc.status] || 'var(--text-muted)', fontWeight: 600, fontSize: '16px', letterSpacing: '1px' }}>
                      {inc.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '6px', color: 'var(--cyan-primary)' }}>{inc.assigned_to || '—'}</td>
                  <td style={{ padding: '6px', color: 'var(--text-muted)', fontSize: '16px' }}>
                    {inc.created_at ? new Date(inc.created_at).toLocaleString('en-US', { hour12: false }) : '—'}
                  </td>
                </tr>
              ))}
              {incidents.length === 0 && (
                <tr><td colSpan={6} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>NO INCIDENTS</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Detail Panel */}
        {selected && (
          <div style={{ flex: 1, background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', borderRadius: '2px', overflowY: 'auto', maxHeight: '500px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
              INCIDENT #{selected.id}: {selected.title}
            </div>
            {selected.description && (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-secondary)', marginBottom: '12px' }}>{selected.description}</div>
            )}

            {/* Status Transition */}
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '4px' }}>STATUS CONTROL</div>
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {['open', 'investigating', 'contained', 'resolved', 'closed'].map(s => (
                  <button
                    key={s}
                    disabled={selected.status === s}
                    onClick={() => handleStatusChange(selected.id, s)}
                    style={{
                      padding: '3px 8px', fontSize: '15px', fontFamily: 'var(--font-mono)', letterSpacing: '1px',
                      background: selected.status === s ? STATUS_COLORS[s] : 'transparent',
                      color: selected.status === s ? '#000' : STATUS_COLORS[s],
                      border: `1px solid ${STATUS_COLORS[s]}`, cursor: selected.status === s ? 'default' : 'pointer',
                      borderRadius: '2px', opacity: selected.status === s ? 1 : 0.7,
                    }}
                  >
                    {s.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Assign */}
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '4px' }}>
                ASSIGN TO: <span style={{ color: 'var(--cyan-primary)' }}>{selected.assigned_to || 'UNASSIGNED'}</span>
              </div>
              <div style={{ display: 'flex', gap: '4px' }}>
                <input className="terminal-input" placeholder="Username..." value={assignUser} onChange={e => setAssignUser(e.target.value)} style={{ flex: 1, padding: '4px 6px', fontSize: '16px' }} />
                <button className="stamp-badge stamp-advisory" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => handleAssign(selected.id)}>ASSIGN</button>
              </div>
            </div>

            {/* Add Note */}
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '4px' }}>ADD NOTE</div>
              <div style={{ display: 'flex', gap: '4px' }}>
                <input className="terminal-input" placeholder="Note..." value={noteText} onChange={e => setNoteText(e.target.value)} style={{ flex: 1, padding: '4px 6px', fontSize: '16px' }} />
                <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => handleAddNote(selected.id)}>ADD</button>
              </div>
            </div>

            {/* Timeline */}
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '4px' }}>TIMELINE</div>
              {selected.timeline.map((evt, i) => (
                <div key={i} className="cable-feed-item" style={{ padding: '4px 8px', marginBottom: '4px', fontSize: '16px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>{new Date(evt.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                  {' '}
                  <span style={{ color: 'var(--cyan-primary)' }}>[{evt.actor}]</span>
                  {' '}
                  <span style={{ color: 'var(--text-primary)' }}>{evt.event}</span>
                  {evt.note != null && <span style={{ color: 'var(--text-secondary)' }}> — {String(evt.note)}</span>}
                </div>
              ))}
            </div>

            {/* Linked Alerts */}
            <div style={{ marginTop: '8px' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '4px' }}>LINKED ALERTS</div>

              {/* Link new alerts */}
              <div style={{ display: 'flex', gap: '4px', marginBottom: '8px' }}>
                <input
                  className="terminal-input"
                  placeholder="Alert IDs (comma-separated)..."
                  value={linkAlertInput}
                  onChange={e => setLinkAlertInput(e.target.value)}
                  style={{ flex: 1, padding: '4px 6px', fontSize: '16px' }}
                />
                <button
                  className="stamp-badge stamp-advisory"
                  style={{ cursor: 'pointer', fontSize: '14px' }}
                  onClick={() => handleLinkAlerts(selected.id)}
                >
                  LINK
                </button>
              </div>

              {/* Source alert IDs (from incident creation) */}
              {selected.source_alert_ids.length > 0 && (
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: '6px' }}>
                  {selected.source_alert_ids.map(id => (
                    <span key={id} className="stamp-badge stamp-suspect" style={{ fontSize: '14px' }}>ALT-{id}</span>
                  ))}
                </div>
              )}

              {/* Fetched linked alerts with details */}
              {linkedAlerts.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {linkedAlerts.map(a => (
                    <div key={a.id} style={{
                      display: 'flex',
                      gap: '8px',
                      alignItems: 'center',
                      padding: '4px 8px',
                      background: 'var(--bg-secondary)',
                      borderRadius: '2px',
                      borderLeft: `2px solid ${
                        a.severity === 'critical' ? 'var(--severity-critical)' :
                        a.severity === 'high' ? 'var(--severity-high)' :
                        a.severity === 'medium' ? 'var(--severity-medium)' : 'var(--severity-low)'
                      }`,
                      fontSize: '15px',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      <span style={{ color: 'var(--text-muted)', minWidth: '50px' }}>#{a.id}</span>
                      <span className={`stamp-badge ${SEVERITY_STAMPS[a.severity] || 'stamp-routine'}`} style={{ fontSize: '12px' }}>
                        {a.severity.toUpperCase()}
                      </span>
                      <span style={{ color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.title}
                      </span>
                      <span style={{ color: 'var(--cyan-primary)', fontSize: '14px' }}>{a.module_source}</span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
                        {new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                      </span>
                      {a.acknowledged && (
                        <span style={{ color: 'var(--status-online)', fontSize: '13px' }}>ACK</span>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {linkedAlerts.length === 0 && selected.source_alert_ids.length === 0 && (
                <div style={{ color: 'var(--text-muted)', fontSize: '15px', fontFamily: 'var(--font-mono)' }}>NO ALERTS LINKED</div>
              )}
            </div>
          </div>
        )}
      </div>
    </IntelCard>
  );
}
