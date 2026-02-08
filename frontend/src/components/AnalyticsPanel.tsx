import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { TimelineChart } from './charts/TimelineChart';
import { DonutChart } from './charts/DonutChart';
import { BarChart } from './charts/BarChart';
import { IntelCard } from './ui/IntelCard';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff1744',
  high: '#ff5722',
  medium: '#ff9800',
  low: '#ffc107',
  info: '#2196f3',
};

export function AnalyticsPanel() {
  const [alertTrend, setAlertTrend] = useState<Array<{ timestamp: string; count: number }>>([]);
  const [severityDist, setSeverityDist] = useState<Array<{ severity: string; count: number }>>([]);
  const [moduleActivity, setModuleActivity] = useState<Array<{ module: string; count: number }>>([]);

  useEffect(() => {
    api.getAlertTrend(24).then((d: unknown) => setAlertTrend(d as typeof alertTrend)).catch(() => {});
    api.getSeverityDistribution().then((d: unknown) => setSeverityDist(d as typeof severityDist)).catch(() => {});
    api.getModuleActivity().then((d: unknown) => setModuleActivity(d as typeof moduleActivity)).catch(() => {});

    const interval = setInterval(() => {
      api.getAlertTrend(24).then((d: unknown) => setAlertTrend(d as typeof alertTrend)).catch(() => {});
    }, 60000);
    return () => clearInterval(interval);
  }, []);

  const donutData = severityDist.map((s) => ({
    name: s.severity,
    value: s.count,
    color: SEVERITY_COLORS[s.severity] || '#666',
  }));

  const barData = moduleActivity.map((m) => ({
    name: m.module.replace(/_/g, ' '),
    value: m.count,
  }));

  const now = new Date().toLocaleString('en-US', { timeZone: 'UTC' });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Section I: Alert Trend */}
      <IntelCard title="SECTION I: ALERT TREND ANALYSIS" classification="SECRET">
        {alertTrend.length > 0 ? (
          <TimelineChart data={alertTrend} dataKey="count" color="#ff5722" height={220} />
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)', textAlign: 'center', padding: '40px', letterSpacing: '2px' }}>
            NO ALERT DATA AVAILABLE
          </div>
        )}
      </IntelCard>

      {/* Section II & III */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <IntelCard title="SECTION II: SEVERITY DISTRIBUTION" classification="SECRET">
          {donutData.length > 0 ? (
            <>
              <DonutChart data={donutData} centerLabel="Total" height={220} />
              <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap', marginTop: '8px' }}>
                {donutData.map((d) => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '16px', fontFamily: 'var(--font-mono)' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '2px', backgroundColor: d.color }} />
                    <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>{d.name}: {d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '17px', textAlign: 'center', padding: '40px', fontFamily: 'var(--font-mono)' }}>
              NO DATA
            </div>
          )}
        </IntelCard>

        <IntelCard title="SECTION III: SOURCE ACTIVITY" classification="SECRET">
          {barData.length > 0 ? (
            <BarChart data={barData} color="#00e5ff" height={220} />
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '17px', textAlign: 'center', padding: '40px', fontFamily: 'var(--font-mono)' }}>
              NO DATA
            </div>
          )}
        </IntelCard>
      </div>

      {/* Footer */}
      <div style={{
        textAlign: 'right',
        fontFamily: 'var(--font-mono)',
        fontSize: '15px',
        color: 'var(--text-muted)',
        letterSpacing: '1px',
        padding: '8px 0',
        borderTop: '1px solid var(--border-default)',
      }}>
        PREPARED BY: CEREBERUS AI &nbsp;|&nbsp; {now} UTC
      </div>
    </div>
  );
}
