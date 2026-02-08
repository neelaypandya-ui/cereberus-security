import { Notification } from '../../hooks/useNotifications';

interface ToastProps {
  notification: Notification;
  onDismiss: (id: string) => void;
  index: number;
}

const severityColors: Record<string, string> = {
  critical: '#ff1744',
  high: '#ff5722',
  medium: '#ff9800',
  low: '#ffc107',
  info: '#2196f3',
};

export function Toast({ notification, onDismiss, index }: ToastProps) {
  const barColor = severityColors[notification.severity] || '#666';

  return (
    <div
      className="toast-slide-in"
      style={{
        position: 'relative',
        width: '340px',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-default)',
        borderRadius: '8px',
        overflow: 'hidden',
        marginBottom: '8px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
        animationDelay: `${index * 50}ms`,
      }}
    >
      {/* Severity color bar */}
      <div style={{
        position: 'absolute',
        left: 0,
        top: 0,
        bottom: 0,
        width: '4px',
        background: barColor,
      }} />

      <div style={{ padding: '12px 12px 12px 16px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
            {notification.title}
          </div>
          <div style={{ fontSize: '17px', color: 'var(--text-muted)', lineHeight: 1.4 }}>
            {notification.message}
          </div>
        </div>
        <button
          onClick={() => onDismiss(notification.id)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            fontSize: '20px',
            padding: '0 4px',
            lineHeight: 1,
          }}
        >
          x
        </button>
      </div>
    </div>
  );
}
