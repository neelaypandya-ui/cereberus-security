import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useToast } from '../hooks/useToast';
import { IntelCard } from './ui/IntelCard';

interface ResourceSnapshot {
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  memory_used_gb: number;
  memory_total_gb: number;
  disk_percent: number;
  disk_used_gb: number;
  disk_total_gb: number;
  net_bytes_sent: number;
  net_bytes_recv: number;
  alert_triggered: boolean;
}

interface ResourceAlert {
  timestamp: string;
  breaches: string[];
  cpu: number;
  memory: number;
  disk: number;
}

function GaugeArc({ percent, label, color, size = 130 }: { percent: number; label: string; color: string; size?: number }) {
  const radius = (size - 24) / 2;
  const cx = size / 2;
  const cy = size / 2 + 12;
  const startAngle = -210;
  const endAngle = 30;
  const range = endAngle - startAngle;
  const angle = startAngle + (range * Math.min(percent, 100)) / 100;

  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const arcX = (a: number) => cx + radius * Math.cos(toRad(a));
  const arcY = (a: number) => cy + radius * Math.sin(toRad(a));

  const bgPath = `M ${arcX(startAngle)} ${arcY(startAngle)} A ${radius} ${radius} 0 1 1 ${arcX(endAngle)} ${arcY(endAngle)}`;
  const valuePath = `M ${arcX(startAngle)} ${arcY(startAngle)} A ${radius} ${radius} 0 ${range * percent / 100 > 180 ? 1 : 0} 1 ${arcX(angle)} ${arcY(angle)}`;

  // Tick marks at 0, 25, 50, 75, 100
  const ticks = [0, 25, 50, 75, 100].map((t) => {
    const ta = startAngle + (range * t) / 100;
    const outerR = radius + 6;
    return {
      x1: cx + radius * Math.cos(toRad(ta)),
      y1: cy + radius * Math.sin(toRad(ta)),
      x2: cx + outerR * Math.cos(toRad(ta)),
      y2: cy + outerR * Math.sin(toRad(ta)),
      label: `${t}`,
      lx: cx + (outerR + 8) * Math.cos(toRad(ta)),
      ly: cy + (outerR + 8) * Math.sin(toRad(ta)),
    };
  });

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size + 20}`}>
        <path d={bgPath} fill="none" stroke="var(--border-default)" strokeWidth="8" strokeLinecap="round" />
        <path d={valuePath} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" />
        {/* Tick marks */}
        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} stroke="var(--text-muted)" strokeWidth={1} />
            <text x={t.lx} y={t.ly} textAnchor="middle" dominantBaseline="middle" fill="var(--text-muted)" fontSize="13" fontFamily="var(--font-mono)">
              {t.label}
            </text>
          </g>
        ))}
        <text x={cx} y={cy - 6} textAnchor="middle" fill="var(--text-primary)" fontSize="28" fontWeight="700" fontFamily="var(--font-mono)">
          {Math.round(percent)}%
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="var(--text-muted)" fontSize="15" letterSpacing="2" fontFamily="var(--font-mono)">
          {label.toUpperCase()}
        </text>
      </svg>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + ' GB';
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(0) + ' KB';
  return bytes + ' B';
}

export function ResourcePanel() {
  const { showToast } = useToast();
  const [current, setCurrent] = useState<ResourceSnapshot | null>(null);
  const [alerts, setAlerts] = useState<ResourceAlert[]>([]);

  const load = () => {
    api.getResourceCurrent().then((d: unknown) => setCurrent(d as ResourceSnapshot)).catch((e: Error) => showToast('error', 'Failed to load resource data', e.message));
    api.getResourceAlerts().then((d: unknown) => setAlerts(d as ResourceAlert[])).catch((e: Error) => showToast('error', 'Failed to load resource alerts', e.message));
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  const getColor = (percent: number) => {
    if (percent >= 90) return 'var(--severity-critical)';
    if (percent >= 75) return 'var(--severity-high)';
    if (percent >= 60) return 'var(--severity-medium)';
    return 'var(--cyan-primary)';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Gauge Row */}
      {current && (
        <IntelCard title="SYSTEM GAUGES" classification="UNCLASSIFIED">
          <div style={{ display: 'flex', gap: '24px', justifyContent: 'center' }}>
            <GaugeArc percent={current.cpu_percent} label="CPU" color={getColor(current.cpu_percent)} />
            <GaugeArc percent={current.memory_percent} label="Memory" color={getColor(current.memory_percent)} />
            <GaugeArc percent={current.disk_percent} label="Disk" color={getColor(current.disk_percent)} />
          </div>
        </IntelCard>
      )}

      {/* Memory & Disk Details */}
      {current && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <IntelCard title="MEMORY" classification="UNCLASSIFIED">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '1px' }}>
                {current.memory_used_gb} / {current.memory_total_gb} GB
              </div>
            </div>
          </IntelCard>
          <IntelCard title="DISK" classification="UNCLASSIFIED">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '1px' }}>
                {current.disk_used_gb} / {current.disk_total_gb} GB
              </div>
            </div>
          </IntelCard>
        </div>
      )}

      {/* Network I/O */}
      {current && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <IntelCard title="NET SENT" classification="UNCLASSIFIED">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '26px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-primary)', letterSpacing: '2px' }}>
                {formatBytes(current.net_bytes_sent)}
              </div>
            </div>
          </IntelCard>
          <IntelCard title="NET RECV" classification="UNCLASSIFIED">
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '26px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-primary)', letterSpacing: '2px' }}>
                {formatBytes(current.net_bytes_recv)}
              </div>
            </div>
          </IntelCard>
        </div>
      )}

      {/* Threshold Breach Log */}
      <IntelCard title="THRESHOLD BREACH LOG" classification="UNCLASSIFIED" status={alerts.length > 0 ? 'warning' : 'active'}>
        {alerts.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', letterSpacing: '2px' }}>
            NO THRESHOLD BREACHES
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '300px', overflow: 'auto' }}>
            {alerts.slice().reverse().slice(0, 20).map((a, i) => (
              <div key={i} style={{
                padding: '8px 12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '2px',
                borderLeft: '3px solid var(--severity-critical)',
              }}>
                <div style={{ fontSize: '16px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '4px', letterSpacing: '1px' }}>
                  {new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })} UTC
                </div>
                {a.breaches.map((b, j) => (
                  <div key={j} style={{ fontSize: '17px', color: 'var(--severity-high)', fontFamily: 'var(--font-mono)' }}>{b}</div>
                ))}
              </div>
            ))}
          </div>
        )}
      </IntelCard>
    </div>
  );
}
