import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';

interface PlaybookRule {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  trigger_type: string;
  trigger_conditions: Record<string, unknown>;
  actions: Array<Record<string, unknown>>;
  cooldown_seconds: number;
  last_triggered: string | null;
  execution_count: number;
  requires_confirmation: boolean;
  created_by: string | null;
  created_at: string;
}

const TRIGGER_LABELS: Record<string, string> = {
  alert_severity: 'ALERT SEVERITY',
  anomaly_score: 'ANOMALY SCORE',
  threat_level: 'THREAT LEVEL',
  correlation_pattern: 'CORRELATION',
  module_event: 'MODULE EVENT',
};

const ACTION_LABELS: Record<string, string> = {
  block_ip: 'BLOCK IP',
  kill_process: 'KILL PROCESS',
  quarantine_file: 'QUARANTINE',
  isolate_network: 'ISOLATE NET',
  disable_user: 'DISABLE USER',
};

export function PlaybookPanel() {
  const { showToast } = useToast();
  const [rules, setRules] = useState<PlaybookRule[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newTriggerType, setNewTriggerType] = useState('alert_severity');
  const [newConditions, setNewConditions] = useState('{"severity": ["critical", "high"]}');
  const [newActions, setNewActions] = useState('[{"type": "block_ip", "target": "$details.ip", "duration": 3600}]');
  const [newCooldown, setNewCooldown] = useState(300);
  const [newRequiresConfirm, setNewRequiresConfirm] = useState(false);
  const [dryRunResult, setDryRunResult] = useState<unknown>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.getPlaybooks();
      setRules(data as PlaybookRule[]);
    } catch (e: unknown) { showToast('error', 'Failed to load playbooks', (e as Error).message); }
  }, [showToast]);

  useEffect(() => { load(); const i = setInterval(load, 30000); return () => clearInterval(i); }, [load]);

  const handleCreate = async () => {
    if (!newName) return;
    try {
      const conditions = JSON.parse(newConditions);
      const actions = JSON.parse(newActions);
      await api.createPlaybook({
        name: newName, description: newDesc, trigger_type: newTriggerType,
        trigger_conditions: conditions, actions, cooldown_seconds: newCooldown,
        requires_confirmation: newRequiresConfirm,
      });
      setShowCreate(false);
      setNewName('');
      setNewDesc('');
      load();
      showToast('success', 'Protocol created');
    } catch (e: unknown) { showToast('error', 'Failed to create protocol', (e as Error).message); }
  };

  const handleToggle = async (id: number) => {
    try { await api.togglePlaybook(id); load(); showToast('success', 'Protocol toggled'); } catch (e: unknown) { showToast('error', 'Failed to toggle protocol', (e as Error).message); }
  };

  const handleDelete = async (id: number) => {
    try { await api.deletePlaybook(id); load(); showToast('success', 'Protocol deleted'); } catch (e: unknown) { showToast('error', 'Failed to delete protocol', (e as Error).message); }
  };

  const handleDryRun = async (id: number) => {
    try {
      const result = await api.dryRunPlaybook(id, {});
      setDryRunResult(result);
      showToast('info', 'Dry run complete');
    } catch (e: unknown) { showToast('error', 'Dry run failed', (e as Error).message); }
  };

  const handleExecute = async (id: number) => {
    try { await api.executePlaybook(id, {}); load(); showToast('success', 'Protocol executed'); } catch (e: unknown) { showToast('error', 'Execution failed', (e as Error).message); }
  };

  return (
    <IntelCard title="DEFENSE PROTOCOLS" classification="TOP SECRET">
      {/* Header Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-muted)', letterSpacing: '1px' }}>
          {rules.length} PROTOCOLS | {rules.filter(r => r.enabled).length} ACTIVE
        </div>
        <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowCreate(!showCreate)}>
          + NEW PROTOCOL
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '16px', borderRadius: '2px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '8px' }}>
            <input className="terminal-input" placeholder="Protocol name..." value={newName} onChange={e => setNewName(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }} />
            <select className="terminal-input" value={newTriggerType} onChange={e => setNewTriggerType(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
              {Object.entries(TRIGGER_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <input className="terminal-input" placeholder="Description..." value={newDesc} onChange={e => setNewDesc(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '17px', marginBottom: '8px', boxSizing: 'border-box' }} />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '8px' }}>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--text-muted)', marginBottom: '2px' }}>TRIGGER CONDITIONS (JSON)</div>
              <textarea className="terminal-input" value={newConditions} onChange={e => setNewConditions(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '16px', minHeight: '60px', resize: 'vertical', boxSizing: 'border-box' }} />
            </div>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--text-muted)', marginBottom: '2px' }}>ACTIONS (JSON)</div>
              <textarea className="terminal-input" value={newActions} onChange={e => setNewActions(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '16px', minHeight: '60px', resize: 'vertical', boxSizing: 'border-box' }} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <label style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span>COOLDOWN (s):</span>
              <input className="terminal-input" type="number" value={newCooldown} onChange={e => setNewCooldown(Number(e.target.value))} style={{ width: '80px', padding: '4px 6px', fontSize: '16px' }} />
            </label>
            <label style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <input type="checkbox" checked={newRequiresConfirm} onChange={e => setNewRequiresConfirm(e.target.checked)} />
              REQUIRES CONFIRMATION
            </label>
            <div style={{ flex: 1 }} />
            <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={handleCreate}>CREATE</button>
            <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowCreate(false)}>CANCEL</button>
          </div>
        </div>
      )}

      {/* Rules List */}
      <div style={{ display: 'grid', gap: '8px' }}>
        {rules.map(rule => (
          <div
            key={rule.id}
            style={{
              background: 'var(--bg-tertiary)',
              border: `1px solid ${rule.enabled ? 'var(--border-default)' : 'var(--border-subtle)'}`,
              padding: '10px 14px',
              borderRadius: '2px',
              opacity: rule.enabled ? 1 : 0.6,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  backgroundColor: rule.enabled ? 'var(--status-online)' : 'var(--text-muted)',
                }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>{rule.name}</span>
                <span className={`stamp-badge ${rule.requires_confirmation ? 'stamp-priority' : 'stamp-cleared'}`} style={{ fontSize: '13px' }}>
                  {rule.requires_confirmation ? 'MANUAL CONFIRM' : 'AUTO-EXEC'}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button className="stamp-badge stamp-advisory" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => handleToggle(rule.id)}>
                  {rule.enabled ? 'DISABLE' : 'ENABLE'}
                </button>
                <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => handleDryRun(rule.id)}>DRY RUN</button>
                <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => handleExecute(rule.id)}>EXECUTE</button>
                <button className="stamp-badge stamp-hostile" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => handleDelete(rule.id)}>DELETE</button>
              </div>
            </div>
            {rule.description && <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-secondary)', marginBottom: '4px' }}>{rule.description}</div>}
            <div style={{ display: 'flex', gap: '12px', fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)' }}>
              <span>TRIGGER: <span style={{ color: 'var(--cyan-primary)' }}>{TRIGGER_LABELS[rule.trigger_type] || rule.trigger_type}</span></span>
              <span>COOLDOWN: {rule.cooldown_seconds}s</span>
              <span>EXECUTIONS: {rule.execution_count}</span>
              {rule.last_triggered && <span>LAST: {new Date(rule.last_triggered).toLocaleString('en-US', { hour12: false })}</span>}
            </div>
            <div style={{ marginTop: '4px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              {rule.actions.map((a, i) => (
                <span key={i} className="stamp-badge stamp-suspect" style={{ fontSize: '13px' }}>
                  {ACTION_LABELS[a.type as string] || String(a.type)} {a.target ? `→ ${String(a.target)}` : ''}
                </span>
              ))}
            </div>
          </div>
        ))}
        {rules.length === 0 && (
          <div style={{ padding: '30px', textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '17px', color: 'var(--text-muted)' }}>NO DEFENSE PROTOCOLS CONFIGURED</div>
        )}
      </div>

      {/* Dry Run Result */}
      {dryRunResult != null && (
        <div style={{ marginTop: '16px', background: 'var(--bg-tertiary)', border: '1px solid var(--cyan-primary)', padding: '12px', borderRadius: '2px' }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--cyan-primary)', marginBottom: '4px', letterSpacing: '1px' }}>DRY RUN RESULT</div>
          <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', margin: 0 }}>
            {JSON.stringify(dryRunResult, null, 2)}
          </pre>
          <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '14px', marginTop: '8px' }} onClick={() => setDryRunResult(null)}>DISMISS</button>
        </div>
      )}
    </IntelCard>
  );
}
