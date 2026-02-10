import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface CheckItem {
  key: string;
  label: string;
  description: string;
  passed: boolean;
  detail: string;
}

interface Category {
  key: string;
  label: string;
  icon: string;
  items: CheckItem[];
  passed_count: number;
  total_count: number;
}

interface VerificationResult {
  timestamp: string;
  categories: Category[];
  total_passed: number;
  total_items: number;
  completion_percent: number;
}

const ACCENT_COLORS: Record<string, string> = {
  situation_room: 'var(--text-secondary)',
  shield: 'var(--cyan-primary)',
  sword: '#d4a017',
  threat_assessment: 'var(--severity-high)',
  ai_warfare: '#b388ff',
  incident_response: 'var(--severity-critical)',
  combat_readiness: '#4caf50',
};

const POLL_INTERVAL = 30_000;

export function SecurityProtocolPanel() {
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem('cereberus_protocol_collapsed');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const data = await api.getChecklistVerification() as VerificationResult;
      setResult(data);
    } catch (e: unknown) {
      console.error('Failed to load security protocol verification', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    intervalRef.current = setInterval(fetchData, POLL_INTERVAL);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchData]);

  useEffect(() => {
    localStorage.setItem('cereberus_protocol_collapsed', JSON.stringify(collapsed));
  }, [collapsed]);

  const toggleCategory = (key: string) => {
    setCollapsed(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const utcDate = new Date().toISOString().split('T')[0];
  const pct = result?.completion_percent ?? 0;
  const passed = result?.total_passed ?? 0;
  const total = result?.total_items ?? 0;

  return (
    <IntelCard title="COMMAND CONSOLE \u2014 DAILY SECURITY PROTOCOL" classification="TOP SECRET">
      {/* Command header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 16, paddingBottom: 12,
        borderBottom: '1px solid var(--border-default)',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)',
          letterSpacing: 1,
        }}>
          UTC {utcDate}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 160, height: 6, background: 'var(--bg-tertiary)',
            borderRadius: 3, overflow: 'hidden',
          }}>
            <div style={{
              width: `${pct}%`, height: '100%',
              background: pct === 100 ? '#4caf50' : 'var(--cyan-primary)',
              borderRadius: 3, transition: 'width 0.5s ease',
            }} />
          </div>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 13,
            color: pct === 100 ? '#4caf50' : 'var(--cyan-primary)',
            fontWeight: 600, letterSpacing: 1,
          }}>
            {passed}/{total} VERIFIED ({pct}%)
          </span>
        </div>
      </div>

      {loading && !result && (
        <div style={{
          textAlign: 'center', padding: 40, color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)', fontSize: 13,
        }}>
          RUNNING VERIFICATION SWEEP...
        </div>
      )}

      {/* Category sections */}
      {result?.categories.map(cat => {
        const isCollapsed = collapsed[cat.key];
        const allPassed = cat.passed_count === cat.total_count;
        const accent = ACCENT_COLORS[cat.key] || 'var(--text-muted)';

        return (
          <div key={cat.key} style={{ marginBottom: 8 }}>
            {/* Category header */}
            <button
              onClick={() => toggleCategory(cat.key)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center',
                justifyContent: 'space-between', padding: '10px 12px',
                background: 'var(--bg-tertiary)', border: 'none',
                borderLeft: `3px solid ${accent}`,
                borderRadius: 2, cursor: 'pointer',
                transition: 'background 0.15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'var(--bg-tertiary)')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 16 }}>{cat.icon}</span>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 12,
                  letterSpacing: 1.5, color: 'var(--text-secondary)',
                  fontWeight: 600, textTransform: 'uppercase',
                }}>
                  {cat.label}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  padding: '2px 8px', borderRadius: 3,
                  background: allPassed ? 'rgba(76, 175, 80, 0.15)' : 'rgba(255, 23, 68, 0.15)',
                  color: allPassed ? '#4caf50' : '#ff1744',
                  fontWeight: 600,
                }}>
                  {cat.passed_count}/{cat.total_count}
                </span>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 14,
                  color: 'var(--text-muted)',
                  transform: isCollapsed ? 'rotate(-90deg)' : 'rotate(0deg)',
                  transition: 'transform 0.2s',
                  display: 'inline-block',
                }}>
                  &#9660;
                </span>
              </div>
            </button>

            {/* Items */}
            {!isCollapsed && (
              <div style={{
                borderLeft: `3px solid ${accent}`,
                borderBottomLeftRadius: 2,
                marginLeft: 0,
              }}>
                {cat.items.map(item => (
                  <div
                    key={item.key}
                    style={{
                      display: 'flex', alignItems: 'flex-start', gap: 10,
                      padding: '8px 12px 8px 16px',
                      background: item.passed ? 'transparent' : 'rgba(255, 23, 68, 0.04)',
                      borderBottom: '1px solid var(--border-subtle, rgba(255,255,255,0.04))',
                    }}
                  >
                    <span style={{
                      fontSize: 14, lineHeight: '20px', flexShrink: 0,
                      marginTop: 1,
                    }}>
                      {item.passed
                        ? <span style={{ color: '#4caf50' }}>&#10003;</span>
                        : <span style={{ color: '#ff1744' }}>&#10007;</span>
                      }
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontFamily: 'var(--font-mono)', fontSize: 12,
                        color: item.passed ? 'var(--text-secondary)' : '#ff1744',
                        fontWeight: 500,
                      }}>
                        {item.label}
                      </div>
                      <div style={{
                        fontFamily: 'var(--font-mono)', fontSize: 11,
                        color: 'var(--text-muted)', marginTop: 2,
                      }}>
                        {item.detail}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {/* Footer */}
      <div style={{
        marginTop: 20, paddingTop: 12,
        borderTop: '1px solid var(--border-default)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11,
          color: 'var(--text-muted)', letterSpacing: 1, fontStyle: 'italic',
        }}>
          All systems automated. Command observes.
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10,
          color: 'var(--text-muted)',
        }}>
          {result?.timestamp
            ? `LAST VERIFIED: ${new Date(result.timestamp).toLocaleTimeString('en-GB', { hour12: false })}`
            : 'VERIFYING...'
          }
        </span>
      </div>
    </IntelCard>
  );
}
