import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface Setting {
  id: number;
  key: string;
  value: string;
  category: string;
}

const CATEGORIES = ['general', 'vpn', 'network', 'security', 'integrity', 'alerting'];

const CATEGORY_LABELS: Record<string, string> = {
  general: 'GEN',
  vpn: 'VPN',
  network: 'NET',
  security: 'SEC',
  integrity: 'INT',
  alerting: 'ALR',
};

export function SettingsPanel() {
  const [settings, setSettings] = useState<Setting[]>([]);
  const [activeCategory, setActiveCategory] = useState('general');
  const [editValues, setEditValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);

  const load = (category?: string) => {
    api.getSettings(category).then((d: unknown) => {
      const s = d as Setting[];
      setSettings(s);
      const vals: Record<string, string> = {};
      s.forEach((setting) => { vals[setting.key] = setting.value; });
      setEditValues(vals);
    }).catch(() => {});
  };

  useEffect(() => {
    load(activeCategory);
  }, [activeCategory]);

  const handleSave = async (key: string) => {
    setSaving(key);
    try {
      await api.updateSetting(key, editValues[key]);
      load(activeCategory);
    } catch { /* ignore */ }
    setSaving(null);
  };

  const filtered = settings.filter((s) => s.category === activeCategory);

  return (
    <IntelCard title="SYSTEM CONFIGURATION" classification="UNCLASSIFIED//FOUO">
      {/* Category Tabs */}
      <div style={{ display: 'flex', gap: '4px', marginBottom: '20px', flexWrap: 'wrap' }}>
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            style={{
              padding: '5px 14px',
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '1px',
              textTransform: 'uppercase',
              background: activeCategory === cat ? 'var(--red-dark)' : 'var(--bg-tertiary)',
              color: activeCategory === cat ? '#fff' : 'var(--text-secondary)',
              border: `1px solid ${activeCategory === cat ? 'var(--red-primary)' : 'var(--border-default)'}`,
              borderRadius: '2px',
              cursor: 'pointer',
            }}
          >
            {CATEGORY_LABELS[cat] || cat.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Settings Form */}
      {filtered.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
          NO SETTINGS IN THIS CATEGORY
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {filtered.map((s) => (
            <div key={s.key}>
              <label style={{
                display: 'block',
                fontSize: '9px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                letterSpacing: '2px',
                marginBottom: '4px',
                textTransform: 'uppercase',
              }}>
                {s.key}
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="text"
                  value={editValues[s.key] || ''}
                  onChange={(e) => setEditValues({ ...editValues, [s.key]: e.target.value })}
                  className="terminal-input"
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    fontSize: '12px',
                    borderRadius: '2px',
                  }}
                />
                <button
                  onClick={() => handleSave(s.key)}
                  disabled={saving === s.key || editValues[s.key] === s.value}
                  style={{
                    padding: '8px 16px',
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '1px',
                    background: editValues[s.key] !== s.value ? 'var(--red-dark)' : 'var(--bg-tertiary)',
                    color: editValues[s.key] !== s.value ? '#fff' : 'var(--text-muted)',
                    border: `1px solid ${editValues[s.key] !== s.value ? 'var(--red-primary)' : 'var(--border-default)'}`,
                    borderRadius: '2px',
                    cursor: editValues[s.key] !== s.value ? 'pointer' : 'default',
                    textTransform: 'uppercase',
                  }}
                >
                  {saving === s.key ? '...' : 'APPLY'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </IntelCard>
  );
}
