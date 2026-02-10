import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';
import { GaugeChart } from './charts/GaugeChart';
import { DonutChart } from './charts/DonutChart';
import { BarChart as CereberusBarChart } from './charts/BarChart';

interface ModelInfo {
  initialized: boolean;
  has_model?: boolean;
  has_baseline?: boolean;
  threshold?: number;
  sample_count?: number;
}

interface AiStatusData {
  detectors: Record<string, ModelInfo>;
  ensemble: { last_score: number | null; last_is_anomaly: boolean | null; drift_score: number };
  baseline: { total_buckets: number; total_possible: number; coverage_percent: number; total_samples: number };
}

interface ModelRegistry {
  id: number;
  model_name: string;
  version: number;
  trained_at: string;
  samples_count: number;
  epochs: number;
  final_loss: number;
  status: string;
  is_current: boolean;
}

interface AnomalyEventRecord {
  id: number;
  timestamp: string;
  detector_type: string;
  anomaly_score: number;
  threshold: number;
  is_anomaly: boolean;
  explanation: string;
  confidence: number;
  detector_scores: Record<string, number>;
  feature_attribution: Record<string, number>;
}

interface FeedbackStats {
  total_true_positive: number;
  total_false_positive: number;
  accuracy: number;
  by_module: Record<string, { true_positive: number; false_positive: number }>;
}

interface TrainingState {
  model: string;
  loading: boolean;
  epoch?: number;
  totalEpochs?: number;
  loss?: number;
}

interface AiOpsPanelProps {
  aiStatus?: {
    ensemble_score: number | null;
    drift_score: number;
    baseline_progress: { coverage_percent: number; total_samples: number };
    detector_scores: Record<string, number>;
  } | null;
  trainingProgress?: { model_name: string; epoch: number; total_epochs: number; loss: number } | null;
}

export function AiOpsPanel({ aiStatus: wsAiStatus, trainingProgress }: AiOpsPanelProps) {
  const [status, setStatus] = useState<AiStatusData | null>(null);
  const [models, setModels] = useState<ModelRegistry[]>([]);
  const [anomalyEvents, setAnomalyEvents] = useState<AnomalyEventRecord[]>([]);
  const [feedbackStats, setFeedbackStats] = useState<FeedbackStats | null>(null);
  const [training, setTraining] = useState<TrainingState>({ model: '', loading: false });
  const [expandedEvent, setExpandedEvent] = useState<number | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [s, m, e, f] = await Promise.all([
        api.getAiStatus(),
        api.getAiModels(),
        api.getAnomalyEvents({ limit: 20 }),
        api.getFeedbackStats(),
      ]);
      setStatus(s as AiStatusData);
      setModels(m as ModelRegistry[]);
      setAnomalyEvents(e as AnomalyEventRecord[]);
      setFeedbackStats(f as FeedbackStats);
    } catch (err) { console.error('[CEREBERUS]', err); }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Update training state from WebSocket
  useEffect(() => {
    if (trainingProgress) {
      setTraining({
        model: trainingProgress.model_name,
        loading: trainingProgress.epoch < trainingProgress.total_epochs,
        epoch: trainingProgress.epoch,
        totalEpochs: trainingProgress.total_epochs,
        loss: trainingProgress.loss,
      });
    }
  }, [trainingProgress]);

  const handleTrain = async (type: 'anomaly' | 'baseline') => {
    setTraining({ model: type, loading: true });
    try {
      if (type === 'anomaly') await api.trainAnomalyModels();
      else await api.trainBaseline();
      await loadData();
    } catch (err) { console.error('[CEREBERUS]', err); }
    setTraining({ model: '', loading: false });
  };

  const modelCards = [
    { name: 'AUTOENCODER', key: 'autoencoder', color: '#00e5ff' },
  ];

  // Feature attribution for bar chart
  const topAttrs: Array<{ name: string; value: number }> = [];
  if (anomalyEvents.length > 0 && anomalyEvents[0].feature_attribution) {
    const attrs = anomalyEvents[0].feature_attribution;
    Object.entries(attrs)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .forEach(([name, value]) => {
        topAttrs.push({ name: name.replace(/_/g, ' ').substring(0, 12), value: Math.round(value * 100) });
      });
  }

  // Feedback donut data
  const feedbackDonut = feedbackStats
    ? [
        { name: 'True Positive', value: feedbackStats.total_true_positive, color: '#4caf50' },
        { name: 'False Positive', value: feedbackStats.total_false_positive, color: '#ff1744' },
      ]
    : [];

  const driftScore = wsAiStatus?.drift_score ?? status?.ensemble?.drift_score ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* SECTION I: MODEL STATUS MATRIX */}
      <IntelCard title="MODEL STATUS MATRIX" classification="SECTION I" status="active">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
          {modelCards.map((mc) => {
            const detectorInfo = status?.detectors?.[mc.key];
            const initialized = detectorInfo?.initialized;
            const hasModel = detectorInfo?.has_model ?? detectorInfo?.has_baseline;
            const registry = models.find((m) => m.model_name === mc.key && m.is_current);

            return (
              <div
                key={mc.key}
                style={{
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-default)',
                  borderRadius: '4px',
                  padding: '12px',
                  borderTop: `2px solid ${mc.color}`,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                  <div style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    backgroundColor: initialized ? '#4caf50' : 'var(--text-muted)',
                  }} />
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '15px',
                    letterSpacing: '1px',
                    color: mc.color,
                  }}>
                    {mc.name}
                  </span>
                </div>
                <div className="instrument-readout" style={{ fontSize: '16px', lineHeight: '1.6' }}>
                  <div>STATUS: {initialized ? 'ONLINE' : 'OFFLINE'}</div>
                  <div>MODEL: {hasModel ? 'LOADED' : 'NONE'}</div>
                  {registry && (
                    <>
                      <div>VERSION: v{registry.version}</div>
                      <div>LOSS: {registry.final_loss.toFixed(4)}</div>
                      <div>SAMPLES: {registry.samples_count}</div>
                    </>
                  )}
                  {!registry && <div>VERSION: --</div>}
                </div>
              </div>
            );
          })}
        </div>
      </IntelCard>

      {/* SECTION II: DRIFT MONITOR */}
      <IntelCard title="DRIFT MONITOR" classification="SECTION II" status={driftScore > 0.6 ? 'critical' : driftScore > 0.3 ? 'warning' : 'active'}>
        <GaugeChart value={driftScore} max={1} height={140} label="Model Drift" />
      </IntelCard>

      {/* SECTION III: TRAINING COMMAND */}
      <IntelCard title="TRAINING COMMAND" classification="SECTION III" status="active">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
          {[
            { label: 'TRAIN ANOMALY DETECTOR', type: 'anomaly' as const, desc: 'Autoencoder network anomaly detection' },
            { label: 'BUILD BASELINES', type: 'baseline' as const, desc: 'Behavioral baseline from history' },
          ].map((btn) => (
            <div key={btn.type} style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-default)',
              borderRadius: '4px',
              padding: '12px',
            }}>
              <button
                onClick={() => handleTrain(btn.type)}
                disabled={training.loading}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: training.loading && training.model === btn.type ? 'var(--bg-primary)' : 'transparent',
                  border: '1px solid var(--cyan-primary)',
                  borderRadius: '2px',
                  color: 'var(--cyan-primary)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  letterSpacing: '1px',
                  cursor: training.loading ? 'wait' : 'pointer',
                  opacity: training.loading && training.model !== btn.type ? 0.5 : 1,
                }}
              >
                {training.loading && training.model === btn.type ? 'TRAINING...' : btn.label}
              </button>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '14px',
                color: 'var(--text-muted)',
                marginTop: '6px',
                letterSpacing: '0.5px',
              }}>
                {btn.desc}
              </div>
              {training.loading && training.model === btn.type && training.epoch !== undefined && (
                <div style={{ marginTop: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--text-secondary)' }}>
                      EPOCH {training.epoch}/{training.totalEpochs}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--amber-primary)' }}>
                      LOSS: {training.loss?.toFixed(4)}
                    </span>
                  </div>
                  <div style={{ height: '3px', background: 'var(--bg-primary)', borderRadius: '2px' }}>
                    <div style={{
                      height: '100%',
                      width: `${((training.epoch || 0) / (training.totalEpochs || 1)) * 100}%`,
                      background: 'var(--cyan-primary)',
                      borderRadius: '2px',
                      transition: 'width 0.3s ease',
                    }} />
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </IntelCard>

      {/* SECTION IV: FEATURE ATTRIBUTION + FEEDBACK */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <IntelCard title="FEATURE ATTRIBUTION" classification="SECTION IV-A" status="active">
          {topAttrs.length > 0 ? (
            <CereberusBarChart
              data={topAttrs}
              dataKey="value"
              height={180}
              color="#00e5ff"
            />
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '30px',
              fontFamily: 'var(--font-mono)',
              fontSize: '16px',
              color: 'var(--text-muted)',
            }}>
              NO ANOMALY DATA AVAILABLE
            </div>
          )}
        </IntelCard>

        <IntelCard title="FEEDBACK ANALYSIS" classification="SECTION IV-B" status="active">
          {feedbackDonut.some((d) => d.value > 0) ? (
            <>
              <DonutChart
                data={feedbackDonut}
                height={150}
                centerLabel="accuracy"
                centerValue={feedbackStats ? `${(feedbackStats.accuracy * 100).toFixed(0)}%` : '—'}
              />
              <div style={{
                textAlign: 'center',
                fontFamily: 'var(--font-mono)',
                fontSize: '15px',
                color: 'var(--text-secondary)',
                marginTop: '4px',
              }}>
                TP: {feedbackStats?.total_true_positive || 0} | FP: {feedbackStats?.total_false_positive || 0}
              </div>
            </>
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '30px',
              fontFamily: 'var(--font-mono)',
              fontSize: '16px',
              color: 'var(--text-muted)',
            }}>
              NO FEEDBACK SUBMITTED YET
            </div>
          )}
        </IntelCard>
      </div>

      {/* SECTION V: ANOMALY EVENT LOG */}
      <IntelCard title="ANOMALY EVENT LOG" classification="SECTION V" status="active">
        <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '16px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-default)' }}>
                {['TIMESTAMP', 'DETECTOR', 'SCORE', 'CONF', 'STATUS'].map((h) => (
                  <th key={h} style={{
                    padding: '6px 8px',
                    textAlign: 'left',
                    color: 'var(--text-muted)',
                    fontSize: '14px',
                    letterSpacing: '1px',
                    fontWeight: 400,
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {anomalyEvents.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    NO ANOMALY EVENTS RECORDED
                  </td>
                </tr>
              )}
              {anomalyEvents.map((evt) => (
                <>
                  <tr
                    key={evt.id}
                    onClick={() => setExpandedEvent(expandedEvent === evt.id ? null : evt.id)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      cursor: 'pointer',
                      background: expandedEvent === evt.id ? 'var(--bg-tertiary)' : 'transparent',
                    }}
                  >
                    <td style={{ padding: '6px 8px', color: 'var(--text-secondary)' }}>
                      {new Date(evt.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                    </td>
                    <td style={{ padding: '6px 8px', color: 'var(--cyan-primary)' }}>
                      {evt.detector_type.toUpperCase()}
                    </td>
                    <td style={{ padding: '6px 8px', color: evt.anomaly_score > 0.7 ? '#ff1744' : evt.anomaly_score > 0.4 ? '#ff9800' : '#4caf50' }}>
                      {evt.anomaly_score.toFixed(3)}
                    </td>
                    <td style={{ padding: '6px 8px', color: 'var(--text-secondary)' }}>
                      {(evt.confidence * 100).toFixed(0)}%
                    </td>
                    <td style={{ padding: '6px 8px' }}>
                      <span className={evt.is_anomaly ? 'stamp-badge stamp-hostile' : 'stamp-badge stamp-cleared'} style={{ fontSize: '13px' }}>
                        {evt.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                      </span>
                    </td>
                  </tr>
                  {expandedEvent === evt.id && (
                    <tr key={`${evt.id}-detail`}>
                      <td colSpan={5} style={{
                        padding: '8px 12px',
                        background: 'var(--bg-tertiary)',
                        borderBottom: '1px solid var(--border-default)',
                      }}>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                          {evt.explanation || 'No explanation available.'}
                        </div>
                        {evt.detector_scores && Object.keys(evt.detector_scores).length > 0 && (
                          <div style={{ marginTop: '6px', display: 'flex', gap: '12px' }}>
                            {Object.entries(evt.detector_scores).map(([k, v]) => (
                              <span key={k} style={{ color: 'var(--text-muted)', fontSize: '15px' }}>
                                {k.toUpperCase()}: {(v as number).toFixed(3)}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </IntelCard>
    </div>
  );
}
