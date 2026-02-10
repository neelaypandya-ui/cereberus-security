import { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';
import type {
  SmithStatusResponse,
  SmithAttackEvent,
  SmithSessionResult,
} from '../bridge';

// ── Types (bridge-backed + local extensions) ──────────────────

type SmithStatusState = 'DORMANT' | 'CONFIGURING' | 'ACTIVE' | 'COMPLETING';

// Local alias: uses bridge contract directly (guardian fields now in contract)
type SmithStatus = SmithStatusResponse;

interface SmithCategory {
  id: string;
  name: string;
  description: string;
}

// Extend bridge attack event with legacy/optional fields
type AttackEvent = SmithAttackEvent & {
  _smith_simulation?: boolean;
  id?: string;
  detected?: boolean | null;
  smith_commentary?: string;
};

// Re-export bridge SessionResult with local verdict union
type SessionResult = SmithSessionResult;

// ── Constants ──────────────────────────────────────────────────

const INTENSITY_LABELS: Record<number, string> = {
  1: 'PROBE',
  2: 'SKIRMISH',
  3: 'ASSAULT',
  4: 'SIEGE',
  5: 'EVERYTHING',
};

const INTENSITY_COLORS: Record<number, string> = {
  1: '#00FF41',
  2: '#00FF41',
  3: '#f59e0b',
  4: '#ff6b35',
  5: 'var(--red-primary)',
};

const DEFAULT_CATEGORIES = [
  'malware',
  'c2_beaconing',
  'ransomware',
  'lolbin_abuse',
  'credential_dump',
  'lateral_movement',
  'exfiltration',
];

const DURATION_OPTIONS = [
  { label: '1 MIN', seconds: 60 },
  { label: '3 MIN', seconds: 180 },
  { label: '5 MIN', seconds: 300 },
  { label: '10 MIN', seconds: 600 },
];

const MATRIX_GREEN = '#00FF41';

// ── Helpers ────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function formatDate(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function verdictColor(verdict: unknown): string {
  // verdict can be {grade, comment} object or a string
  const grade = typeof verdict === 'object' && verdict !== null
    ? (verdict as Record<string, unknown>).grade
    : verdict;
  const g = String(grade ?? '').toUpperCase();
  if (g === 'S' || g === 'A') return MATRIX_GREEN;
  if (g === 'B' || g === 'C') return '#f59e0b';
  return 'var(--red-primary)';
}

function verdictLabel(verdict: unknown): string {
  if (typeof verdict === 'object' && verdict !== null) {
    const v = verdict as Record<string, unknown>;
    return `${v.grade ?? '?'} — ${v.comment ?? ''}`;
  }
  return String(verdict ?? '—');
}

function categoryLabel(id: string | undefined | null): string {
  return (id ?? '').replace(/_/g, ' ').toUpperCase();
}

/** Safely extract whether an attack was detected — handles both nested and flat shapes. */
function attackDetected(attack: AttackEvent): boolean | null {
  if (attack.detection && typeof attack.detection === 'object') {
    return attack.detection.detected ?? null;
  }
  return attack.detected ?? null;
}

/** Safely extract Smith's commentary from an attack event. */
function attackCommentary(attack: AttackEvent): string {
  if (attack.detection && typeof attack.detection === 'object') {
    return attack.detection.commentary ?? '';
  }
  return attack.smith_commentary ?? '';
}

/** Get an attack's unique key. */
function attackKey(attack: AttackEvent): string {
  return attack.attack_id || attack.id || '';
}

/** Get session date for display. */
function sessionDate(session: SessionResult): string {
  return session.timestamp ?? '';
}

/** Get session detected count. */
function sessionDetected(session: SessionResult): number {
  return session.detected_count ?? (session as unknown as Record<string, number>).detected ?? 0;
}

/** Get session missed count. */
function sessionMissed(session: SessionResult): number {
  return session.missed_count ?? (session as unknown as Record<string, number>).missed ?? 0;
}

/** Get session detection rate as a percentage (0-100). */
function sessionDetectionPct(session: SessionResult): number {
  const rate = session.detection_rate ?? 0;
  // Backend returns 0-1 (e.g., 0.75), convert to 0-100
  return rate <= 1 ? Math.round(rate * 100) : Math.round(rate);
}

/** Flatten category_results attacks into a single array for display. */
function sessionAttacks(session: SessionResult): Array<{ attack_id: string; category: string; description: string; detected: boolean; rule_matches: unknown[] }> {
  if (session.category_results) {
    const attacks: Array<{ attack_id: string; category: string; description: string; detected: boolean; rule_matches: unknown[] }> = [];
    for (const [cat, data] of Object.entries(session.category_results)) {
      if (data.attacks) {
        for (const atk of data.attacks) {
          attacks.push({ ...atk, category: cat });
        }
      }
    }
    return attacks;
  }
  return [];
}

// ── Spinner ────────────────────────────────────────────────────

function Spinner({ size = 12, color = 'currentColor' }: { size?: number; color?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      style={{ animation: 'smithSpin 1s linear infinite', flexShrink: 0 }}
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        fill="none"
        stroke={color}
        strokeWidth="3"
        strokeDasharray="31.4 31.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ── Section Header ─────────────────────────────────────────────

function SectionHeader({ label, color }: { label: string; color?: string }) {
  return (
    <div style={{ marginBottom: '12px' }}>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '17px',
          letterSpacing: '2px',
          color: color || MATRIX_GREEN,
          marginBottom: '6px',
        }}
      >
        {label}
      </div>
      <div style={{ height: '1px', background: 'var(--border-default)' }} />
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export function AgentSmithPanel() {
  // ── State ─────────────────────────────────────────────────────
  const [status, setStatus] = useState<SmithStatus | null>(null);
  const [categories, setCategories] = useState<SmithCategory[]>([]);
  const [results, setResults] = useState<SessionResult[]>([]);
  const [attackFeed, setAttackFeed] = useState<AttackEvent[]>([]);

  // Config state
  const [intensity, setIntensity] = useState(1);
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(
    new Set(DEFAULT_CATEGORIES)
  );
  const [duration, setDuration] = useState(60);

  // UI state
  const [loading, setLoading] = useState(true);
  const [engaging, setEngaging] = useState(false);
  const [disengaging, setDisengaging] = useState(false);
  const [confirmEngage, setConfirmEngage] = useState(false);
  const [expandedSession, setExpandedSession] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const feedRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isActive = status?.state === 'ACTIVE';
  const isCompleting = status?.state === 'COMPLETING';
  const isRunning = isActive || isCompleting;
  const isDormant = !status || status.state === 'DORMANT';

  // ── Data Loading ──────────────────────────────────────────────

  const loadStatus = async () => {
    try {
      const data = await api.getSmithStatus() as SmithStatus;
      setStatus(data);
    } catch {
      // Silent — status poll failures are non-critical
    }
  };

  const loadResults = async () => {
    try {
      const data = await api.getSmithResults() as SessionResult[];
      setResults(data);
    } catch {
      // Silent
    }
  };

  const loadCategories = async () => {
    try {
      const data = await api.getSmithCategories() as SmithCategory[];
      setCategories(data);
    } catch {
      // Use defaults if endpoint unavailable
    }
  };

  const loadAttackFeed = async () => {
    try {
      const data = await api.getSmithAttacks() as AttackEvent[];
      if (data && data.length > 0) {
        setAttackFeed(data);
      }
    } catch {
      // Silent
    }
  };

  // ── Initial Load ──────────────────────────────────────────────

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await Promise.all([loadStatus(), loadResults(), loadCategories()]);
      setLoading(false);
    };
    init();
  }, []);

  // ── Polling ───────────────────────────────────────────────────

  useEffect(() => {
    if (isRunning) {
      pollRef.current = setInterval(async () => {
        await loadStatus();
        await loadAttackFeed();
      }, 3000);
    } else {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [isRunning, status?.session_id]);

  // Auto-scroll attack feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [attackFeed]);

  // Refresh results when session fully finishes (COMPLETING → DORMANT)
  const prevState = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (prevState.current === 'COMPLETING' && status?.state === 'DORMANT') {
      loadResults();
      setAttackFeed([]);
    }
    prevState.current = status?.state;
  }, [status?.state]);

  // Reset confirm when config changes
  useEffect(() => {
    setConfirmEngage(false);
  }, [intensity, selectedCategories, duration]);

  // ── Actions ───────────────────────────────────────────────────

  const handleEngage = async () => {
    if (!confirmEngage) {
      setConfirmEngage(true);
      return;
    }
    setEngaging(true);
    setConfirmEngage(false);
    setError(null);
    try {
      await api.engageSmith({
        intensity,
        categories: Array.from(selectedCategories),
        duration,
      });
      setAttackFeed([]);
      await loadStatus();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Engagement failed';
      setError(msg);
    } finally {
      setEngaging(false);
    }
  };

  const handleDisengage = async () => {
    setDisengaging(true);
    setError(null);
    try {
      await api.disengageSmith();
      await loadStatus();
      await loadResults();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Disengagement failed';
      setError(msg);
    } finally {
      setDisengaging(false);
    }
  };

  const toggleCategory = (id: string) => {
    setSelectedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // ── Computed ──────────────────────────────────────────────────

  const remainingSeconds = status
    ? Math.max(0, status.duration_seconds - (status.elapsed_seconds ?? 0))
    : 0;

  const detectionPercent = status && status.attacks_launched > 0
    ? Math.round((status.attacks_detected / status.attacks_launched) * 100)
    : 0;

  const displayCategories = categories.length > 0
    ? categories
    : DEFAULT_CATEGORIES.map((id) => ({ id, name: categoryLabel(id), description: '' }));

  // ── Render ────────────────────────────────────────────────────

  return (
    <IntelCard title="AGENT SMITH" classification="TOP SECRET" status={isRunning ? 'critical' : 'active'}>
      <style>{`
        @keyframes smithSpin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes smithPulse {
          0%, 100% { box-shadow: 0 0 8px rgba(220, 38, 38, 0.3); }
          50% { box-shadow: 0 0 20px rgba(220, 38, 38, 0.7); }
        }
        @keyframes smithGlow {
          0%, 100% { box-shadow: 0 0 8px rgba(0, 255, 65, 0.2); }
          50% { box-shadow: 0 0 16px rgba(0, 255, 65, 0.5); }
        }
        @keyframes smithFadeIn {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes smithBlink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>

      {loading ? (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '16px',
          color: 'var(--text-muted)',
          textAlign: 'center',
          padding: '40px 0',
          letterSpacing: '2px',
        }}>
          <Spinner size={16} color={MATRIX_GREEN} />{' '}
          INITIALIZING AGENT SMITH...
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

          {/* ── Master Toggle ──────────────────────────────────── */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
            {isDormant ? (
              <>
                <button
                  onClick={() => setStatus((prev) => prev ? { ...prev, state: 'CONFIGURING' } : {
                    state: 'CONFIGURING' as SmithStatusState,
                    active: false,
                    session_id: null,
                    intensity: 1,
                    categories: [],
                    events_injected: 0,
                    elapsed_seconds: 0,
                    duration_seconds: 0,
                    attacks_launched: 0,
                    attacks_detected: 0,
                    attacks_missed: 0,
                    attacks_pending: 0,
                    sessions_completed: 0,
                    unique_attacks_generated: 0,
                  })}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '18px',
                    fontWeight: 700,
                    letterSpacing: '3px',
                    padding: '16px 48px',
                    background: 'transparent',
                    border: `2px solid ${MATRIX_GREEN}`,
                    color: MATRIX_GREEN,
                    borderRadius: '2px',
                    cursor: 'pointer',
                    transition: 'all 0.3s',
                    animation: 'smithGlow 2s ease-in-out infinite',
                  }}
                >
                  ACTIVATE AGENT SMITH
                </button>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '15px',
                  color: 'var(--text-muted)',
                  letterSpacing: '1px',
                  textAlign: 'center',
                  maxWidth: '420px',
                  lineHeight: '1.5',
                }}>
                  Adversary simulation — stress test Cereberus defenses
                </div>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '14px',
                  letterSpacing: '2px',
                  color: 'var(--text-muted)',
                  opacity: 0.6,
                }}>
                  STATUS: DORMANT
                </div>
              </>
            ) : (
              <button
                onClick={handleDisengage}
                disabled={disengaging}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '18px',
                  fontWeight: 700,
                  letterSpacing: '3px',
                  padding: '16px 48px',
                  background: isRunning ? 'rgba(220, 38, 38, 0.08)' : 'transparent',
                  border: '2px solid var(--red-primary)',
                  color: 'var(--red-primary)',
                  borderRadius: '2px',
                  cursor: disengaging ? 'not-allowed' : 'pointer',
                  transition: 'all 0.3s',
                  animation: isRunning ? 'smithPulse 1.5s ease-in-out infinite' : 'none',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                {disengaging && <Spinner size={14} color="var(--red-primary)" />}
                DEACTIVATE AGENT SMITH
              </button>
            )}
          </div>

          {/* ── Error Banner ──────────────────────────────────── */}
          {error && (
            <div style={{
              padding: '12px 16px',
              background: 'rgba(220, 38, 38, 0.06)',
              borderLeft: '3px solid var(--red-primary)',
              borderRadius: '2px',
              fontFamily: 'var(--font-mono)',
              fontSize: '17px',
              letterSpacing: '1px',
              color: 'var(--red-primary)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              animation: 'smithFadeIn 0.3s ease',
            }}>
              <span>SMITH ERROR &mdash; {error}</span>
              <button
                onClick={() => setError(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--red-primary)',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '18px',
                }}
              >
                &times;
              </button>
            </div>
          )}

          {/* ── Configuration (when not dormant and not active) ── */}
          {status?.state === 'CONFIGURING' && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '20px',
              animation: 'smithFadeIn 0.3s ease',
            }}>
              {/* Intensity Slider */}
              <div>
                <SectionHeader label="INTENSITY" />
                <div style={{ padding: '0 4px' }}>
                  <input
                    type="range"
                    min={1}
                    max={5}
                    step={1}
                    value={intensity}
                    onChange={(e) => setIntensity(Number(e.target.value))}
                    style={{
                      width: '100%',
                      accentColor: INTENSITY_COLORS[intensity],
                      cursor: 'pointer',
                    }}
                  />
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '13px',
                    letterSpacing: '1px',
                    marginTop: '4px',
                  }}>
                    {[1, 2, 3, 4, 5].map((lvl) => (
                      <span
                        key={lvl}
                        style={{
                          color: intensity === lvl ? INTENSITY_COLORS[lvl] : 'var(--text-muted)',
                          fontWeight: intensity === lvl ? 700 : 400,
                          transition: 'all 0.2s',
                        }}
                      >
                        {INTENSITY_LABELS[lvl]}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Category Checkboxes */}
              <div>
                <SectionHeader label="ATTACK CATEGORIES" />
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                  gap: '8px',
                }}>
                  {displayCategories.map((cat) => {
                    const isSelected = selectedCategories.has(cat.id);
                    return (
                      <div
                        key={cat.id}
                        onClick={() => toggleCategory(cat.id)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          padding: '8px 12px',
                          background: isSelected ? 'rgba(0, 255, 65, 0.05)' : '#1a1a1a',
                          border: `1px solid ${isSelected ? MATRIX_GREEN : '#2d2d2d'}`,
                          borderRadius: '2px',
                          cursor: 'pointer',
                          transition: 'all 0.2s',
                        }}
                      >
                        <div style={{
                          width: '14px',
                          height: '14px',
                          border: `1px solid ${isSelected ? MATRIX_GREEN : '#555'}`,
                          borderRadius: '2px',
                          background: isSelected ? 'rgba(0, 255, 65, 0.15)' : 'transparent',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0,
                          transition: 'all 0.2s',
                        }}>
                          {isSelected && (
                            <svg width="10" height="10" viewBox="0 0 10 10">
                              <polyline
                                points="2,5 4,7 8,3"
                                fill="none"
                                stroke={MATRIX_GREEN}
                                strokeWidth="1.5"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                              />
                            </svg>
                          )}
                        </div>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '14px',
                          letterSpacing: '1px',
                          color: isSelected ? MATRIX_GREEN : 'var(--text-secondary)',
                        }}>
                          {categoryLabel(cat.id)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Duration Selector */}
              <div>
                <SectionHeader label="DURATION" />
                <div style={{ display: 'flex', gap: '10px' }}>
                  {DURATION_OPTIONS.map((opt) => (
                    <button
                      key={opt.seconds}
                      onClick={() => setDuration(opt.seconds)}
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '15px',
                        letterSpacing: '2px',
                        padding: '8px 20px',
                        background: duration === opt.seconds ? 'rgba(0, 255, 65, 0.1)' : 'transparent',
                        border: `1px solid ${duration === opt.seconds ? MATRIX_GREEN : '#2d2d2d'}`,
                        color: duration === opt.seconds ? MATRIX_GREEN : 'var(--text-muted)',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        transition: 'all 0.2s',
                        fontWeight: duration === opt.seconds ? 700 : 400,
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Engage Button */}
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <button
                  onClick={handleEngage}
                  disabled={engaging || selectedCategories.size === 0}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '16px',
                    fontWeight: 700,
                    letterSpacing: '3px',
                    padding: '12px 36px',
                    background: confirmEngage ? 'rgba(220, 38, 38, 0.1)' : 'rgba(0, 255, 65, 0.08)',
                    border: `2px solid ${confirmEngage ? 'var(--red-primary)' : MATRIX_GREEN}`,
                    color: confirmEngage ? 'var(--red-primary)' : MATRIX_GREEN,
                    borderRadius: '2px',
                    cursor: engaging || selectedCategories.size === 0 ? 'not-allowed' : 'pointer',
                    opacity: selectedCategories.size === 0 ? 0.4 : 1,
                    transition: 'all 0.3s',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                  }}
                >
                  {engaging && <Spinner size={14} color={MATRIX_GREEN} />}
                  {confirmEngage ? 'CONFIRM — THIS WILL SIMULATE ATTACKS' : 'ENGAGE'}
                </button>
                {confirmEngage && (
                  <button
                    onClick={() => setConfirmEngage(false)}
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '14px',
                      letterSpacing: '1px',
                      padding: '8px 16px',
                      background: 'transparent',
                      border: '1px solid var(--text-muted)',
                      color: 'var(--text-muted)',
                      borderRadius: '2px',
                      cursor: 'pointer',
                    }}
                  >
                    CANCEL
                  </button>
                )}
              </div>
            </div>
          )}

          {/* ── Active Session Dashboard ─────────────────────── */}
          {isRunning && status && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              animation: 'smithFadeIn 0.3s ease',
            }}>
              {/* Timer + Emergency Kill */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '32px',
                  fontWeight: 700,
                  letterSpacing: '4px',
                  color: MATRIX_GREEN,
                  animation: 'smithBlink 2s ease-in-out infinite',
                }}>
                  {formatDuration(remainingSeconds)}
                </div>
                <button
                  onClick={handleDisengage}
                  disabled={disengaging}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '14px',
                    fontWeight: 700,
                    letterSpacing: '2px',
                    padding: '10px 24px',
                    background: 'rgba(220, 38, 38, 0.15)',
                    border: '2px solid var(--red-primary)',
                    color: 'var(--red-primary)',
                    borderRadius: '2px',
                    cursor: disengaging ? 'not-allowed' : 'pointer',
                    animation: 'smithPulse 1.5s ease-in-out infinite',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  {disengaging && <Spinner size={12} color="var(--red-primary)" />}
                  EMERGENCY KILL
                </button>
              </div>

              {/* Detection Scoreboard */}
              <div>
                <SectionHeader label="DETECTION SCOREBOARD" />
                <div style={{
                  display: 'flex',
                  gap: '16px',
                  marginBottom: '12px',
                }}>
                  {[
                    { label: 'DETECTED', value: status.attacks_detected, color: MATRIX_GREEN },
                    { label: 'MISSED', value: status.attacks_missed, color: 'var(--red-primary)' },
                    { label: 'PENDING', value: status.attacks_pending, color: '#f59e0b' },
                    { label: 'TOTAL', value: status.attacks_launched, color: 'var(--text-primary)' },
                  ].map((stat) => (
                    <div key={stat.label} style={{
                      flex: 1,
                      background: '#1a1a1a',
                      border: '1px solid #2d2d2d',
                      borderRadius: '2px',
                      padding: '10px 12px',
                      textAlign: 'center',
                    }}>
                      <div style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '24px',
                        fontWeight: 700,
                        color: stat.color,
                        letterSpacing: '2px',
                      }}>
                        {stat.value}
                      </div>
                      <div style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                        letterSpacing: '2px',
                        marginTop: '4px',
                      }}>
                        {stat.label}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Detection Rate Bar */}
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                }}>
                  <div style={{
                    flex: 1,
                    height: '8px',
                    background: '#2d2d2d',
                    borderRadius: '4px',
                    overflow: 'hidden',
                  }}>
                    <div style={{
                      width: `${detectionPercent}%`,
                      height: '100%',
                      background: detectionPercent >= 80 ? MATRIX_GREEN
                        : detectionPercent >= 50 ? '#f59e0b'
                        : 'var(--red-primary)',
                      borderRadius: '4px',
                      transition: 'width 0.6s ease',
                    }} />
                  </div>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '16px',
                    fontWeight: 700,
                    color: detectionPercent >= 80 ? MATRIX_GREEN
                      : detectionPercent >= 50 ? '#f59e0b'
                      : 'var(--red-primary)',
                    letterSpacing: '1px',
                    minWidth: '48px',
                    textAlign: 'right',
                  }}>
                    {detectionPercent}%
                  </span>
                </div>
              </div>

              {/* Live Attack Feed */}
              <div>
                <SectionHeader label="LIVE ATTACK FEED" />
                <div
                  ref={feedRef}
                  style={{
                    maxHeight: '280px',
                    overflowY: 'auto',
                    background: '#0a0a0a',
                    border: '1px solid #1a1a1a',
                    borderRadius: '2px',
                    padding: '8px',
                  }}
                >
                  {attackFeed.length === 0 ? (
                    <div style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '14px',
                      color: MATRIX_GREEN,
                      padding: '16px',
                      textAlign: 'center',
                      animation: 'smithBlink 1.5s ease-in-out infinite',
                    }}>
                      AWAITING ATTACK TELEMETRY...
                    </div>
                  ) : (
                    attackFeed.map((attack, idx) => {
                      const det = attackDetected(attack);
                      const commentary = attackCommentary(attack);
                      return (
                      <div
                        key={attackKey(attack) || idx}
                        style={{
                          padding: '8px 10px',
                          borderBottom: idx < attackFeed.length - 1 ? '1px solid #1a1a1a' : 'none',
                          animation: 'smithFadeIn 0.3s ease',
                        }}
                      >
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '10px',
                          marginBottom: '4px',
                        }}>
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '12px',
                            color: 'var(--text-muted)',
                            letterSpacing: '1px',
                          }}>
                            {attack.timestamp ? formatTimestamp(attack.timestamp) : '--:--:--'}
                          </span>
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            letterSpacing: '1px',
                            padding: '1px 6px',
                            borderRadius: '2px',
                            background: 'rgba(0, 255, 65, 0.08)',
                            border: `1px solid ${MATRIX_GREEN}40`,
                            color: MATRIX_GREEN,
                          }}>
                            {categoryLabel(attack.category)}
                          </span>
                          {det !== null && (
                            <span style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              letterSpacing: '1px',
                              padding: '1px 6px',
                              borderRadius: '2px',
                              background: det
                                ? 'rgba(0, 255, 65, 0.1)'
                                : 'rgba(220, 38, 38, 0.1)',
                              border: `1px solid ${det ? MATRIX_GREEN : 'var(--red-primary)'}40`,
                              color: det ? MATRIX_GREEN : 'var(--red-primary)',
                            }}>
                              {det ? 'DETECTED' : 'MISSED'}
                            </span>
                          )}
                        </div>
                        <div style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '13px',
                          color: 'var(--text-secondary)',
                          lineHeight: '1.4',
                        }}>
                          {attack.description}
                        </div>
                        {commentary && (
                          <div style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '12px',
                            color: MATRIX_GREEN,
                            marginTop: '4px',
                            paddingLeft: '12px',
                            borderLeft: `2px solid ${MATRIX_GREEN}40`,
                            lineHeight: '1.4',
                            fontStyle: 'italic',
                          }}>
                            {commentary}
                          </div>
                        )}
                      </div>
                      );
                    }))
                  }
                </div>
              </div>
            </div>
          )}

          {/* ── Session History ───────────────────────────────── */}
          <div>
            <SectionHeader label="SESSION HISTORY" />
            {results.length === 0 ? (
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '14px',
                color: 'var(--text-muted)',
                letterSpacing: '1px',
                textAlign: 'center',
                padding: '24px 0',
              }}>
                NO PREVIOUS SESSIONS
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '14px',
                }}>
                  <thead>
                    <tr>
                      {['DATE', 'INTENSITY', 'DURATION', 'DETECTION', 'VERDICT', ''].map((col) => (
                        <th
                          key={col}
                          style={{
                            textAlign: 'left',
                            padding: '8px 10px',
                            borderBottom: '1px solid var(--border-default)',
                            color: 'var(--text-muted)',
                            letterSpacing: '2px',
                            fontSize: '12px',
                            fontWeight: 600,
                          }}
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((session) => {
                      const isExpanded = expandedSession === session.session_id;
                      const pct = sessionDetectionPct(session);
                      const flatAttacks = sessionAttacks(session);
                      return (
                        <tr key={session.session_id} style={{ verticalAlign: 'top' }}>
                          <td colSpan={6} style={{ padding: 0 }}>
                            {/* Row */}
                            <div
                              onClick={() => setExpandedSession(isExpanded ? null : session.session_id)}
                              style={{
                                display: 'grid',
                                gridTemplateColumns: '1fr 1fr 1fr 1fr 1fr auto',
                                padding: '8px 10px',
                                borderBottom: '1px solid rgba(45, 45, 45, 0.5)',
                                cursor: 'pointer',
                                transition: 'background 0.15s',
                                background: isExpanded ? 'rgba(0, 255, 65, 0.03)' : 'transparent',
                              }}
                            >
                              <span style={{ color: 'var(--text-secondary)' }}>
                                {formatDate(sessionDate(session))}
                              </span>
                              <span style={{
                                color: INTENSITY_COLORS[session.intensity] || MATRIX_GREEN,
                                fontWeight: 700,
                              }}>
                                {INTENSITY_LABELS[session.intensity] || `LVL ${session.intensity}`}
                              </span>
                              <span style={{ color: 'var(--text-muted)' }}>
                                {formatDuration(Math.round(session.duration_seconds ?? 0))}
                              </span>
                              <span style={{
                                color: pct >= 80 ? MATRIX_GREEN
                                  : pct >= 50 ? '#f59e0b'
                                  : 'var(--red-primary)',
                                fontWeight: 700,
                              }}>
                                {pct}%
                              </span>
                              <span style={{
                                color: verdictColor(session.verdict),
                                fontWeight: 700,
                              }}>
                                {verdictLabel(session.verdict)}
                              </span>
                              <span style={{
                                color: 'var(--text-muted)',
                                fontSize: '12px',
                                transform: isExpanded ? 'rotate(90deg)' : 'none',
                                transition: 'transform 0.2s',
                                display: 'inline-block',
                              }}>
                                &#9654;
                              </span>
                            </div>

                            {/* Expanded Details */}
                            {isExpanded && (
                              <div style={{
                                padding: '12px 16px',
                                background: 'rgba(0, 255, 65, 0.02)',
                                borderBottom: '1px solid rgba(45, 45, 45, 0.5)',
                                animation: 'smithFadeIn 0.2s ease',
                              }}>
                                {/* Per-attack breakdown */}
                                <div style={{ marginBottom: '12px' }}>
                                  <div style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: '12px',
                                    letterSpacing: '2px',
                                    color: MATRIX_GREEN,
                                    marginBottom: '8px',
                                  }}>
                                    ATTACK BREAKDOWN
                                  </div>
                                  {flatAttacks.length > 0 ? (
                                    flatAttacks.map((atk, aidx) => (
                                      <div key={atk.attack_id || aidx} style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '10px',
                                        padding: '4px 0',
                                        borderBottom: aidx < flatAttacks.length - 1
                                          ? '1px solid #1a1a1a' : 'none',
                                      }}>
                                        <span style={{
                                          width: '8px',
                                          height: '8px',
                                          borderRadius: '50%',
                                          background: atk.detected ? MATRIX_GREEN : 'var(--red-primary)',
                                          flexShrink: 0,
                                        }} />
                                        <span style={{
                                          fontFamily: 'var(--font-mono)',
                                          fontSize: '12px',
                                          color: 'var(--text-muted)',
                                          minWidth: '110px',
                                        }}>
                                          {categoryLabel(atk.category)}
                                        </span>
                                        <span style={{
                                          fontFamily: 'var(--font-mono)',
                                          fontSize: '12px',
                                          color: 'var(--text-secondary)',
                                          flex: 1,
                                        }}>
                                          {atk.description}
                                        </span>
                                        <span style={{
                                          fontFamily: 'var(--font-mono)',
                                          fontSize: '11px',
                                          color: atk.detected ? MATRIX_GREEN : 'var(--red-primary)',
                                          letterSpacing: '1px',
                                          minWidth: '70px',
                                          textAlign: 'right',
                                        }}>
                                          {atk.detected ? 'DETECTED' : 'MISSED'}
                                        </span>
                                      </div>
                                    ))
                                  ) : (
                                    <div style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '12px',
                                      color: 'var(--text-muted)',
                                    }}>
                                      {sessionDetected(session)} detected / {sessionMissed(session)} missed of {session.total_attacks} total
                                    </div>
                                  )}
                                </div>

                                {/* Recommendations */}
                                {session.recommendations && session.recommendations.length > 0 && (
                                  <div>
                                    <div style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '12px',
                                      letterSpacing: '2px',
                                      color: '#f59e0b',
                                      marginBottom: '8px',
                                    }}>
                                      RECOMMENDATIONS
                                    </div>
                                    {session.recommendations.map((rec, ridx) => (
                                      <div key={ridx} style={{
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: '12px',
                                        color: 'var(--text-secondary)',
                                        padding: '3px 0 3px 16px',
                                        borderLeft: `2px solid ${MATRIX_GREEN}40`,
                                        lineHeight: '1.4',
                                        marginBottom: '4px',
                                      }}>
                                        {rec}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

        </div>
      )}
    </IntelCard>
  );
}
