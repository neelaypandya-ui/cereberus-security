import { useEffect, useState } from 'react';
import { api } from '../services/api';

interface Setting {
  id: number;
  key: string;
  value: string;
  category: string;
}

const CATEGORIES = ['general', 'vpn', 'network', 'security', 'integrity', 'alerting'];

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
    <div>
      {/* Category Tabs */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '24px', flexWrap: 'wrap' }}>
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            style={{
              padding: '6px 16px',
              fontSize: '11px',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              background: activeCategory === cat ? 'var(--red-primary)' : 'var(--bg-tertiary)',
              color: activeCategory === cat ? '#fff' : 'var(--text-secondary)',
              border: '1px solid var(--border-default)',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Settings Form */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        padding: '20px',
      }}>
        {filtered.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
            No settings in this category
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {filtered.map((s) => (
              <div key={s.key}>
                <label style={{
                  display: 'block',
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  letterSpacing: '0.5px',
                  marginBottom: '6px',
                  fontFamily: 'var(--font-mono)',
                }}>
                  {s.key}
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    value={editValues[s.key] || ''}
                    onChange={(e) => setEditValues({ ...editValues, [s.key]: e.target.value })}
                    style={{
                      flex: 1,
                      padding: '8px 12px',
                      fontSize: '12px',
                      fontFamily: 'var(--font-mono)',
                      background: 'var(--bg-tertiary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-default)',
                      borderRadius: '4px',
                      outline: 'none',
                    }}
                  />
                  <button
                    onClick={() => handleSave(s.key)}
                    disabled={saving === s.key || editValues[s.key] === s.value}
                    style={{
                      padding: '8px 16px',
                      fontSize: '11px',
                      background: editValues[s.key] !== s.value ? 'var(--red-primary)' : 'var(--bg-tertiary)',
                      color: editValues[s.key] !== s.value ? '#fff' : 'var(--text-muted)',
                      border: '1px solid var(--border-default)',
                      borderRadius: '4px',
                      cursor: editValues[s.key] !== s.value ? 'pointer' : 'default',
                    }}
                  >
                    {saving === s.key ? '...' : 'Save'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
