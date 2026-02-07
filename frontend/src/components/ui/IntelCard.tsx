import { ReactNode } from 'react';
import { CornerBrackets } from './CornerBrackets';

interface IntelCardProps {
  title: string;
  classification?: string;
  status?: 'active' | 'warning' | 'critical' | 'offline';
  children: ReactNode;
  style?: React.CSSProperties;
}

const statusColors: Record<string, string> = {
  active: 'var(--cyan-primary)',
  warning: 'var(--amber-primary)',
  critical: 'var(--severity-critical)',
  offline: 'var(--text-muted)',
};

const accentClasses: Record<string, string> = {
  active: 'intel-accent-active',
  warning: 'intel-accent-warning',
  critical: 'intel-accent-critical',
  offline: 'intel-accent-offline',
};

export function IntelCard({ title, classification, status = 'active', children, style }: IntelCardProps) {
  return (
    <div
      className={`intel-card ${accentClasses[status] || 'intel-accent-active'}`}
      style={{ padding: 0, ...style }}
    >
      <CornerBrackets color={statusColors[status] || 'var(--cyan-primary)'} />

      {/* Header bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '8px 14px',
        borderBottom: '1px solid var(--border-default)',
        background: 'var(--bg-tertiary)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {status && (
            <div
              className={status === 'active' ? 'status-dot-glow' : ''}
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: statusColors[status] || 'var(--text-muted)',
                flexShrink: 0,
              }}
            />
          )}
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            color: 'var(--text-secondary)',
          }}>
            {title}
          </span>
        </div>
        {classification && (
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '9px',
            letterSpacing: '1px',
            color: 'var(--red-primary)',
            opacity: 0.7,
            textTransform: 'uppercase',
          }}>
            {classification}
          </span>
        )}
      </div>

      {/* Content */}
      <div style={{ padding: '16px' }}>
        {children}
      </div>
    </div>
  );
}
