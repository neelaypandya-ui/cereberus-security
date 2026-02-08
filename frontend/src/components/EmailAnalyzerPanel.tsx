import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface AnalysisResult {
  threat_score: number;
  verdict: string;
  indicators: string[];
  component_scores: Record<string, number>;
}

interface RecentAnalysis {
  id: number;
  timestamp: string;
  threat_score: number;
  verdict: string;
  text_preview: string;
}

const VERDICT_STAMPS: Record<string, { label: string; stampClass: string }> = {
  malicious: { label: 'HOSTILE', stampClass: 'stamp-hostile' },
  phishing: { label: 'HOSTILE', stampClass: 'stamp-hostile' },
  suspicious: { label: 'SUSPECT', stampClass: 'stamp-suspect' },
  safe: { label: 'CLEARED', stampClass: 'stamp-cleared' },
  clean: { label: 'CLEARED', stampClass: 'stamp-cleared' },
};

function ThreatGauge({ score }: { score: number }) {
  const size = 180;
  const radius = 68;
  const cx = size / 2;
  const cy = size / 2 + 15;
  const startAngle = -180;
  const endAngle = 0;
  const range = endAngle - startAngle;
  const angle = startAngle + (range * Math.min(score, 100)) / 100;

  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const arcX = (a: number) => cx + radius * Math.cos(toRad(a));
  const arcY = (a: number) => cy + radius * Math.sin(toRad(a));

  const bgPath = `M ${arcX(startAngle)} ${arcY(startAngle)} A ${radius} ${radius} 0 0 1 ${arcX(endAngle)} ${arcY(endAngle)}`;
  const valuePath = `M ${arcX(startAngle)} ${arcY(startAngle)} A ${radius} ${radius} 0 ${score > 50 ? 1 : 0} 1 ${arcX(angle)} ${arcY(angle)}`;

  const color = score >= 70 ? '#ff1744' : score >= 40 ? '#ff9800' : '#4caf50';

  return (
    <svg width={size} height={size / 2 + 44} viewBox={`0 0 ${size} ${size / 2 + 44}`}>
      <path d={bgPath} fill="none" stroke="#2d2d2d" strokeWidth="12" strokeLinecap="round" />
      <path d={valuePath} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" />
      <text x={cx} y={cy - 8} textAnchor="middle" fill="#e8e8e8" fontSize="32" fontWeight="700" fontFamily="var(--font-mono)">
        {Math.round(score)}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="#666" fontSize="9" letterSpacing="2" fontFamily="var(--font-mono)">
        THREAT SCORE
      </text>
    </svg>
  );
}

export function EmailAnalyzerPanel() {
  const [emailText, setEmailText] = useState('');
  const [urls, setUrls] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [recent, setRecent] = useState<RecentAnalysis[]>([]);

  useEffect(() => {
    api.getRecentEmailAnalyses(10).then((d: unknown) => setRecent(d as RecentAnalysis[])).catch(() => {});
  }, []);

  const handleAnalyze = async () => {
    if (!emailText.trim()) return;
    setAnalyzing(true);
    try {
      const urlList = urls.split(/[,\n]/).map((u) => u.trim()).filter(Boolean);
      const data = await api.analyzeEmail(emailText, urlList);
      setResult(data as AnalysisResult);
      api.getRecentEmailAnalyses(10).then((d: unknown) => setRecent(d as RecentAnalysis[])).catch(() => {});
    } catch { /* */ }
    setAnalyzing(false);
  };

  const verdictStamp = (v: string) => VERDICT_STAMPS[v] || { label: v.toUpperCase(), stampClass: 'stamp-routine' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Input + Results Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        {/* Input */}
        <IntelCard title="INTERCEPT INPUT" classification="SECRET//COMINT">
          <textarea
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
            rows={8}
            placeholder="Paste intercepted communication..."
            style={{
              width: '100%',
              background: 'var(--bg-primary)',
              color: 'var(--status-online)',
              border: '1px solid var(--border-default)',
              borderRadius: '2px',
              padding: '10px',
              fontSize: '18px',
              fontFamily: 'var(--font-mono)',
              resize: 'vertical',
              caretColor: 'var(--status-online)',
            }}
          />
          <div style={{ marginTop: '10px' }}>
            <label style={{ fontSize: '15px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '2px' }}>
              URLS (COMMA OR NEWLINE SEPARATED)
            </label>
            <input
              type="text"
              value={urls}
              onChange={(e) => setUrls(e.target.value)}
              placeholder="https://..."
              className="terminal-input"
              style={{
                width: '100%',
                borderRadius: '2px',
                padding: '8px 10px',
                fontSize: '18px',
                marginTop: '4px',
              }}
            />
          </div>
          <button
            onClick={handleAnalyze}
            disabled={analyzing || !emailText.trim()}
            style={{
              marginTop: '12px',
              padding: '8px 20px',
              fontSize: '17px',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '2px',
              fontWeight: 600,
              background: analyzing ? 'var(--bg-tertiary)' : 'var(--cyan-dark)',
              color: analyzing ? 'var(--text-muted)' : '#fff',
              border: 'none',
              borderRadius: '2px',
              cursor: analyzing ? 'wait' : 'pointer',
            }}
          >
            {analyzing ? 'ANALYZING...' : 'ANALYZE INTERCEPT'}
          </button>
        </IntelCard>

        {/* Results */}
        <IntelCard title="ANALYSIS RESULT" classification="SECRET//COMINT">
          {result ? (
            <div>
              <div style={{ textAlign: 'center', marginBottom: '16px' }}>
                <ThreatGauge score={result.threat_score} />
                <div style={{ marginTop: '8px' }}>
                  <span
                    className={`stamp-badge ${verdictStamp(result.verdict).stampClass}`}
                    style={{ fontSize: '18px', padding: '4px 16px', transform: 'rotate(-2deg)', display: 'inline-block' }}
                  >
                    {verdictStamp(result.verdict).label}
                  </span>
                </div>
              </div>

              {/* Evidence Markers */}
              {result.indicators.length > 0 && (
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '15px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: '6px', letterSpacing: '2px' }}>
                    EVIDENCE MARKERS
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {result.indicators.map((ind, i) => (
                      <span key={i} style={{
                        padding: '3px 10px',
                        borderRadius: '2px',
                        fontSize: '16px',
                        fontFamily: 'var(--font-mono)',
                        background: 'var(--bg-tertiary)',
                        color: 'var(--severity-high)',
                        border: '1px solid var(--border-default)',
                        letterSpacing: '1px',
                      }}>
                        #{i + 1} {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Component Scores */}
              {result.component_scores && Object.keys(result.component_scores).length > 0 && (
                <div>
                  <div style={{ fontSize: '15px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: '6px', letterSpacing: '2px' }}>
                    COMPONENT ANALYSIS
                  </div>
                  {Object.entries(result.component_scores).map(([key, val]) => (
                    <div key={key} style={{ marginBottom: '6px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '16px', marginBottom: '2px', fontFamily: 'var(--font-mono)' }}>
                        <span style={{ color: 'var(--text-secondary)', letterSpacing: '1px' }}>{key.toUpperCase()}</span>
                        <span style={{ color: 'var(--text-muted)' }}>{Math.round(val)}%</span>
                      </div>
                      <div style={{ height: '6px', background: 'var(--bg-tertiary)', borderRadius: '1px', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${Math.min(val, 100)}%`, background: val > 70 ? '#ff1744' : val > 40 ? '#ff9800' : '#4caf50', borderRadius: '1px' }} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', textAlign: 'center', padding: '40px 0', letterSpacing: '2px' }}>
              SUBMIT INTERCEPT FOR ANALYSIS
            </div>
          )}
        </IntelCard>
      </div>

      {/* Recent Analyses */}
      <IntelCard title="RECENT ANALYSES" classification="SECRET//COMINT">
        {recent.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
            NO RECENT ANALYSES
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {recent.map((r, i) => (
              <div key={i} className="cable-feed-item" style={{ alignItems: 'center' }}>
                <span style={{
                  fontSize: '20px',
                  fontWeight: 700,
                  fontFamily: 'var(--font-mono)',
                  color: r.threat_score >= 70 ? '#ff1744' : r.threat_score >= 40 ? '#ff9800' : '#4caf50',
                  minWidth: '32px',
                }}>
                  {Math.round(r.threat_score)}
                </span>
                <span className={`stamp-badge ${verdictStamp(r.verdict).stampClass}`} style={{ minWidth: '60px', textAlign: 'center' }}>
                  {verdictStamp(r.verdict).label}
                </span>
                <span style={{ fontSize: '17px', color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.text_preview}
                </span>
                <span style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {r.timestamp ? new Date(r.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }) + 'Z' : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </IntelCard>
    </div>
  );
}
