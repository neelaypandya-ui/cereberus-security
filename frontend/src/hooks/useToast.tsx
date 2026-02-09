import { createContext, useContext, useState, useCallback, useEffect, ReactNode } from 'react';

interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  action?: { label: string; onClick: () => void };
  createdAt: number;
}

interface ToastContextValue {
  toasts: Toast[];
  showToast: (type: Toast['type'], title: string, message?: string, action?: Toast['action']) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const TOAST_COLORS = {
  success: 'var(--status-online)',
  error: 'var(--severity-critical)',
  warning: 'var(--amber-primary)',
  info: 'var(--cyan-primary)',
};

const AUTO_DISMISS_MS = { success: 5000, error: 8000, warning: 5000, info: 5000 };
const MAX_TOASTS = 5;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const showToast = useCallback((type: Toast['type'], title: string, message?: string, action?: Toast['action']) => {
    const id = `toast_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const toast: Toast = { id, type, title, message, action, createdAt: Date.now() };
    setToasts(prev => [...prev.slice(-(MAX_TOASTS - 1)), toast]);
  }, []);

  // Auto-dismiss
  useEffect(() => {
    const timers = toasts.map(toast => {
      const elapsed = Date.now() - toast.createdAt;
      const remaining = AUTO_DISMISS_MS[toast.type] - elapsed;
      if (remaining <= 0) {
        dismissToast(toast.id);
        return null;
      }
      return setTimeout(() => dismissToast(toast.id), remaining);
    });
    return () => timers.forEach(t => t && clearTimeout(t));
  }, [toasts, dismissToast]);

  return (
    <ToastContext.Provider value={{ toasts, showToast, dismissToast }}>
      {children}
      {/* Toast container */}
      <div style={{
        position: 'fixed', top: '60px', right: '20px',
        zIndex: 10001, display: 'flex', flexDirection: 'column',
        gap: '8px', maxWidth: '400px',
      }}>
        {toasts.map(toast => (
          <div key={toast.id} style={{
            background: 'var(--bg-elevated)',
            border: `1px solid ${TOAST_COLORS[toast.type]}`,
            borderLeft: `3px solid ${TOAST_COLORS[toast.type]}`,
            borderRadius: '4px', padding: '12px 16px',
            fontFamily: 'var(--font-mono)', fontSize: '13px',
            animation: 'toastSlideIn 0.2s ease-out',
            display: 'flex', flexDirection: 'column', gap: '4px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: TOAST_COLORS[toast.type], fontWeight: 700, letterSpacing: '1px', fontSize: '12px' }}>
                {toast.type.toUpperCase()}
              </span>
              <button onClick={() => dismissToast(toast.id)} style={{
                background: 'none', border: 'none', color: 'var(--text-muted)',
                cursor: 'pointer', fontSize: '14px', padding: '0 4px',
              }}>{'\u00D7'}</button>
            </div>
            <div style={{ color: 'var(--text-primary)' }}>{toast.title}</div>
            {toast.message && <div style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>{toast.message}</div>}
            {toast.action && (
              <button onClick={toast.action.onClick} style={{
                background: 'transparent', border: `1px solid ${TOAST_COLORS[toast.type]}`,
                color: TOAST_COLORS[toast.type], padding: '4px 8px', cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: '11px', borderRadius: '2px',
                marginTop: '4px', alignSelf: 'flex-start',
              }}>
                {toast.action.label}
              </button>
            )}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}
