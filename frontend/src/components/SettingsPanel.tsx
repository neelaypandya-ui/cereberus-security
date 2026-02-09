import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface Setting {
  id: number;
  key: string;
  value: string;
  category: string;
}

interface ThresholdItem {
  key: string;
  category: string;
  description: string;
  current_value: number;
  default_value: number;
  type: string;
}

const CATEGORIES = ['general', 'vpn', 'network', 'security', 'integrity', 'alerting', 'thresholds'];

const CATEGORY_LABELS: Record<string, string> = {
  general: 'GEN',
  vpn: 'VPN',
  network: 'NET',
  security: 'SEC',
  integrity: 'INT',
  alerting: 'ALR',
  thresholds: 'THR',
};

export function SettingsPanel() {
  const [settings, setSettings] = useState<Setting[]>([]);
  const [activeCategory, setActiveCategory] = useState('general');
  const [editValues, setEditValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);

  // Threshold state
  const [thresholds, setThresholds] = useState<ThresholdItem[]>([]);
  const [thresholdEdits, setThresholdEdits] = useState<Record<string, string>>({});
  const [thresholdSaving, setThresholdSaving] = useState<string | null>(null);

  const load = (category?: string) => {
    api.getSettings(category).then((d: unknown) => {
      const s = d as Setting[];
      setSettings(s);
      const vals: Record<string, string> = {};
      s.forEach((setting) => { vals[setting.key] = setting.value; });
      setEditValues(vals);
    }).catch((err) => console.error('[CEREBERUS]', err));
  };

  const loadThresholds = () => {
    api.getThresholds().then((d: unknown) => {
      const items = d as ThresholdItem[];
      setThresholds(items);
      const vals: Record<string, string> = {};
      items.forEach((t) => { vals[t.key] = String(t.current_value); });
      setThresholdEdits(vals);
    }).catch((err) => console.error('[CEREBERUS]', err));
  };

  useEffect(() => {
    if (activeCategory === 'thresholds') {
      loadThresholds();
    } else {
      load(activeCategory);
    }
  }, [activeCategory]);

  const handleSave = async (key: string) => {
    setSaving(key);
    try {
      await api.updateSetting(key, editValues[key]);
      load(activeCategory);
    } catch (err) { console.error('[CEREBERUS]', err); }
    setSaving(null);
  };

  const handleThresholdSave = async (key: string) => {
    setThresholdSaving(key);
    try {
      const numValue = parseInt(thresholdEdits[key], 10);
      if (!isNaN(numValue)) {
        await api.updateThreshold(key, numValue);
        loadThresholds();
      }
    } catch (err) { console.error('[CEREBERUS]', err); }
    setThresholdSaving(null);
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
              fontSize: '16px',
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

      {/* Thresholds View */}
      {activeCategory === 'thresholds' ? (
        thresholds.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
            NO THRESHOLDS CONFIGURED
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {thresholds.map((t) => {
              const isChanged = thresholdEdits[t.key] !== String(t.current_value);
              return (
                <div key={t.key} style={{
                  padding: '12px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-default)',
                  borderRadius: '2px',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <label style={{
                      fontSize: '15px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-primary)',
                      letterSpacing: '2px',
                      textTransform: 'uppercase',
                    }}>
                      {t.key}
                    </label>
                    <span style={{
                      fontSize: '12px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-muted)',
                      letterSpacing: '1px',
                      textTransform: 'uppercase',
                      background: 'var(--bg-tertiary)',
                      padding: '2px 8px',
                      borderRadius: '2px',
                    }}>
                      {t.category}
                    </span>
                  </div>
                  <div style={{
                    fontSize: '13px',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-muted)',
                    marginBottom: '8px',
                  }}>
                    {t.description}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <input
                      type="number"
                      value={thresholdEdits[t.key] || ''}
                      onChange={(e) => setThresholdEdits({ ...thresholdEdits, [t.key]: e.target.value })}
                      className="terminal-input"
                      style={{
                        flex: 1,
                        padding: '8px 12px',
                        fontSize: '18px',
                        borderRadius: '2px',
                      }}
                    />
                    <span style={{
                      fontSize: '12px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-muted)',
                      whiteSpace: 'nowrap',
                    }}>
                      DEFAULT: {t.default_value}
                    </span>
                    <button
                      onClick={() => handleThresholdSave(t.key)}
                      disabled={thresholdSaving === t.key || !isChanged}
                      style={{
                        padding: '8px 16px',
                        fontSize: '16px',
                        fontFamily: 'var(--font-mono)',
                        letterSpacing: '1px',
                        background: isChanged ? 'var(--red-dark)' : 'var(--bg-tertiary)',
                        color: isChanged ? '#fff' : 'var(--text-muted)',
                        border: `1px solid ${isChanged ? 'var(--red-primary)' : 'var(--border-default)'}`,
                        borderRadius: '2px',
                        cursor: isChanged ? 'pointer' : 'default',
                        textTransform: 'uppercase',
                      }}
                    >
                      {thresholdSaving === t.key ? '...' : 'APPLY'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )
      ) : (
        /* Settings Form */
        filtered.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
            NO SETTINGS IN THIS CATEGORY
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {filtered.map((s) => (
              <div key={s.key}>
                <label style={{
                  display: 'block',
                  fontSize: '15px',
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
                      fontSize: '18px',
                      borderRadius: '2px',
                    }}
                  />
                  <button
                    onClick={() => handleSave(s.key)}
                    disabled={saving === s.key || editValues[s.key] === s.value}
                    style={{
                      padding: '8px 16px',
                      fontSize: '16px',
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
        )
      )}
    </IntelCard>
  );
}
