import { useState, useRef, useEffect } from 'react';
import { Notification } from '../../hooks/useNotifications';

interface NotificationBellProps {
  notifications: Notification[];
  unreadCount: number;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
}

export function NotificationBell({ notifications, unreadCount, onMarkRead, onMarkAllRead }: NotificationBellProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const severityColor = (s: string) => {
    const map: Record<string, string> = {
      critical: '#ff1744', high: '#ff5722', medium: '#ff9800', low: '#ffc107', info: '#2196f3',
    };
    return map[s] || '#666';
  };

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        className={unreadCount > 0 ? 'bell-pulse' : ''}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          position: 'relative',
          padding: '4px 8px',
          fontSize: '18px',
          color: 'var(--text-secondary)',
        }}
      >
        {'\u{1F514}'}
        {unreadCount > 0 && (
          <span style={{
            position: 'absolute',
            top: 0,
            right: 0,
            background: 'var(--severity-critical)',
            color: '#fff',
            fontSize: '9px',
            fontWeight: 700,
            borderRadius: '50%',
            width: '16px',
            height: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="notification-dropdown" style={{
          position: 'absolute',
          top: '100%',
          right: 0,
          width: '360px',
          maxHeight: '400px',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border-default)',
          borderRadius: '8px',
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          zIndex: 10001,
          overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '12px 16px',
            borderBottom: '1px solid var(--border-default)',
          }}>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '1px' }}>
              NOTIFICATIONS
            </span>
            {unreadCount > 0 && (
              <button
                onClick={onMarkAllRead}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--cyan-primary)',
                  fontSize: '11px',
                  cursor: 'pointer',
                }}
              >
                Mark all read
              </button>
            )}
          </div>

          {/* Notification list */}
          <div style={{ maxHeight: '340px', overflow: 'auto' }}>
            {notifications.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                No notifications
              </div>
            ) : (
              notifications.slice(0, 20).map((n) => (
                <div
                  key={n.id}
                  onClick={() => onMarkRead(n.id)}
                  style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-default)',
                    cursor: 'pointer',
                    background: n.read ? 'transparent' : 'rgba(0, 229, 255, 0.03)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    {!n.read && (
                      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--cyan-primary)', flexShrink: 0 }} />
                    )}
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      color: severityColor(n.severity),
                      textTransform: 'uppercase',
                    }}>
                      {n.severity}
                    </span>
                    <span style={{ fontSize: '12px', color: 'var(--text-primary)', flex: 1 }}>{n.title}</span>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {new Date(n.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', paddingLeft: n.read ? 0 : '14px' }}>
                    {n.message}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
