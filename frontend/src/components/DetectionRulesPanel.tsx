import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

// ── Types ──────────────────────────────────────────────────────

interface DetectionRule {
  id: string;
  name: string;
  severity: string;
  category: string;
  description: string;
  enabled: boolean;
}

interface RuleMatch {
  id: number;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  category: string;
  explanation: string;
}

interface RuleStats {
  total_matches: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  rules_enabled: number;
  rules_total: number;
}

// ── Constants ──────────────────────────────────────────────────

type TabKey = 'rules' | 'matches' | 'analytics';

const TABS: { key: TabKey; label: string }[] = [
  { key: 'rules', label: 'RULES' },
  { key: 'matches', label: 'MATCHES' },
  { key: 'analytics', label: 'ANALYTICS' },
];

const CATEGORY_COLORS: Record<string, string> = {
  credential_access: '#ef4444',
  lateral_movement: '#f97316',
  persistence: '#eab308',
  execution: '#22c55e',
  defense_evasion: '#3b82f6',
  exfiltration: '#8b5cf6',
  privilege_escalation: '#ec4899',
  reconnaissance: '#06b6d4',
  impact: '#dc2626',
  collection: '#f59e0b',
  command_and_control: '#6366f1',
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const MILITARY_LABELS: Record<string, { label: string; stampClass: string }> = {
  critical: { label: 'FLASH', stampClass: 'stamp-flash' },
  high: { label: 'IMMEDIATE', stampClass: 'stamp-immediate' },
  medium: { label: 'PRIORITY', stampClass: 'stamp-priority' },
  low: { label: 'ROUTINE', stampClass: 'stamp-routine' },
  info: { label: 'ADVISORY', stampClass: 'stamp-advisory' },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
};

// ── Component ──────────────────────────────────────────────────

export function DetectionRulesPanel() {
  const [tab, setTab] = useState<TabKey>('rules');
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [stats, setStats] = useState<RuleStats | null>(null);
  const [categoryFilter, setCategoryFilter] = useState('all');

  // ── Data loaders ─────────────────────────────────────────────

  const loadRules = () => {
    api.getDetectionRules().then((d: unknown) => setRules(d as DetectionRule[])).catch(() => {});
  };

  const loadMatches = () => {
    api.getDetectionRuleMatches(50).then((d: unknown) => setMatches(d as RuleMatch[])).catch(() => {});
  };

  const loadStats = () => {
    api.getDetectionRuleStats().then((d: unknown) => setStats(d as RuleStats)).catch(() => {});
  };

  useEffect(() => {
    if (tab === 'rules') loadRules();
    if (tab === 'matches') loadMatches();
    if (tab === 'analytics') loadStats();
  }, [tab]);

  // Auto-refresh: matches every 10s, analytics every 30s
  useEffect(() => {
    if (tab === 'matches') {
      const iv = setInterval(loadMatches, 10000);
      return () => clearInterval(iv);
    }
    if (tab === 'analytics') {
      const iv = setInterval(loadStats, 30000);
      return () => clearInterval(iv);
    }
  }, [tab]);

  // ── Derived data ─────────────────────────────────────────────

  const sortedRules = [...rules].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99),
  );

  const categories = Array.from(new Set(matches.map((m) => m.category)));

  const filteredMatches = categoryFilter === 'all'
    ? matches
    : matches.filter((m) => m.category === categoryFilter);

  const chartData = stats
    ? Object.entries(stats.by_category).map(([name, value]) => ({ name, value }))
    : [];

  // ── Shared styles ────────────────────────────────────────────

  const monoText: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    letterSpacing: '1px',
  };

  const tabBtnStyle = (active: boolean): React.CSSProperties => ({
    padding: '4px 12px',
    fontSize: '16px',
    fontFamily: 'var(--font-mono)',
    letterSpacing: '1px',
    textTransform: 'uppercase',
    background: active ? 'var(--red-dark)' : 'var(--bg-tertiary)',
    color: active ? '#fff' : 'var(--text-secondary)',
    border: `1px solid ${active ? 'transparent' : 'var(--border-default)'}`,
    borderRadius: '2px',
    cursor: 'pointer',
  });

  // ── Render helpers ───────────────────────────────────────────

  const renderBadge = (severity: string) => {
    const mil = MILITARY_LABELS[severity] || MILITARY_LABELS.info;
    return <span className={`stamp-badge ${mil.stampClass}`}>{mil.label}</span>;
  };

  const renderRulesTab = () => (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', ...monoText, fontSize: '15px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-default)' }}>
            {['ID', 'NAME', 'SEVERITY', 'CATEGORY', 'DESCRIPTION', 'ON'].map((h) => (
              <th key={h} style={{ padding: '8px 10px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '13px', letterSpacing: '2px' }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedRules.map((r) => (
            <tr key={r.id} style={{ borderBottom: '1px solid var(--border-default)' }}>
              <td style={{ padding: '8px 10px', color: 'var(--text-muted)' }}>{r.id}</td>
              <td style={{ padding: '8px 10px', color: 'var(--text-primary)' }}>{r.name}</td>
              <td style={{ padding: '8px 10px' }}>{renderBadge(r.severity)}</td>
              <td style={{ padding: '8px 10px', color: 'var(--cyan-primary)', textTransform: 'uppercase', fontSize: '13px', letterSpacing: '2px' }}>
                {r.category}
              </td>
              <td style={{ padding: '8px 10px', color: 'var(--text-secondary)', maxWidth: '320px' }}>{r.description}</td>
              <td style={{ padding: '8px 10px', textAlign: 'center' }}>
                <span style={{
                  display: 'inline-block',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: r.enabled ? '#22c55e' : 'var(--text-muted)',
                }} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rules.length === 0 && (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', ...monoText, fontSize: '17px', letterSpacing: '2px' }}>
          NO DETECTION RULES LOADED
        </div>
      )}
    </div>
  );

  const renderMatchesTab = () => (
    <div>
      {/* Category filter */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '14px', flexWrap: 'wrap' }}>
        <button onClick={() => setCategoryFilter('all')} style={tabBtnStyle(categoryFilter === 'all')}>ALL</button>
        {categories.map((cat) => (
          <button key={cat} onClick={() => setCategoryFilter(cat)} style={{
            ...tabBtnStyle(categoryFilter === cat),
            background: categoryFilter === cat ? (CATEGORY_COLORS[cat] || 'var(--red-dark)') : 'var(--bg-tertiary)',
          }}>
            {cat.replace(/_/g, ' ')}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {filteredMatches.length === 0 && (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', ...monoText, fontSize: '17px', letterSpacing: '2px' }}>
            NO MATCHES DETECTED
          </div>
        )}
        {filteredMatches.map((m) => (
          <div key={m.id} style={{
            background: 'var(--bg-tertiary)',
            border: '1px solid var(--border-default)',
            borderLeft: `3px solid ${CATEGORY_COLORS[m.category] || 'var(--border-default)'}`,
            borderRadius: '2px',
            padding: '10px 14px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              {renderBadge(m.severity)}
              <span style={{ fontSize: '15px', color: 'var(--text-primary)', ...monoText }}>
                [{m.rule_id}] {m.rule_name}
              </span>
              <span style={{ fontSize: '13px', color: 'var(--cyan-primary)', textTransform: 'uppercase', letterSpacing: '2px', ...monoText }}>
                {m.category}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: '14px', color: 'var(--text-muted)', ...monoText }}>
                {new Date(m.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })}Z
              </span>
            </div>
            <div style={{ marginTop: '6px', fontSize: '15px', color: 'var(--text-secondary)', ...monoText, lineHeight: 1.5 }}>
              {m.explanation}
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderAnalyticsTab = () => (
    <div>
      {/* Summary boxes */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '10px', marginBottom: '20px' }}>
        <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', borderRadius: '2px', padding: '14px', textAlign: 'center' }}>
          <div style={{ fontSize: '28px', color: 'var(--text-primary)', ...monoText }}>{stats?.total_matches ?? '-'}</div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', ...monoText, letterSpacing: '2px', marginTop: '4px' }}>TOTAL MATCHES</div>
        </div>
        <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', borderRadius: '2px', padding: '14px', textAlign: 'center' }}>
          <div style={{ fontSize: '28px', color: '#22c55e', ...monoText }}>{stats?.rules_enabled ?? '-'}<span style={{ fontSize: '16px', color: 'var(--text-muted)' }}>/{stats?.rules_total ?? '-'}</span></div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', ...monoText, letterSpacing: '2px', marginTop: '4px' }}>RULES ENABLED</div>
        </div>
      </div>

      {/* Severity breakdown */}
      <div style={{ marginBottom: '20px' }}>
        <div style={{ fontSize: '13px', color: 'var(--text-muted)', ...monoText, letterSpacing: '2px', marginBottom: '8px' }}>SEVERITY BREAKDOWN</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <div key={sev} style={{
              background: 'var(--bg-tertiary)',
              border: `1px solid ${SEVERITY_COLORS[sev]}`,
              borderRadius: '2px',
              padding: '12px',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: '24px', color: SEVERITY_COLORS[sev], ...monoText }}>
                {stats?.by_severity?.[sev] ?? 0}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', ...monoText, letterSpacing: '2px', marginTop: '4px', textTransform: 'uppercase' }}>
                {MILITARY_LABELS[sev]?.label || sev}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Category bar chart */}
      <div>
        <div style={{ fontSize: '13px', color: 'var(--text-muted)', ...monoText, letterSpacing: '2px', marginBottom: '8px' }}>MATCHES BY CATEGORY</div>
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 40 }}>
              <XAxis
                dataKey="name"
                tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                angle={-35}
                textAnchor="end"
                interval={0}
                tickFormatter={(v: string) => v.replace(/_/g, ' ')}
              />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                labelFormatter={(v: string) => v.replace(/_/g, ' ').toUpperCase()}
              />
              <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={CATEGORY_COLORS[entry.name] || '#6b7280'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', ...monoText, fontSize: '15px', letterSpacing: '2px' }}>
            NO ANALYTICS DATA
          </div>
        )}
      </div>
    </div>
  );

  // ── Main render ──────────────────────────────────────────────

  return (
    <IntelCard title="DETECTION ENGINE" classification="SECRET">
      {/* Tab buttons */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '16px' }}>
        {TABS.map((t) => (
          <button key={t.key} onClick={() => setTab(t.key)} style={tabBtnStyle(tab === t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'rules' && renderRulesTab()}
      {tab === 'matches' && renderMatchesTab()}
      {tab === 'analytics' && renderAnalyticsTab()}
    </IntelCard>
  );
}
