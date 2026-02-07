import { Notification } from '../../hooks/useNotifications';
import { Toast } from './Toast';

interface ToastContainerProps {
  toasts: Notification[];
  onDismiss: (id: string) => void;
}

export function ToastContainer({ toasts, onDismiss }: ToastContainerProps) {
  if (toasts.length === 0) return null;

  return (
    <div style={{
      position: 'fixed',
      bottom: '24px',
      right: '24px',
      zIndex: 10000,
      display: 'flex',
      flexDirection: 'column-reverse',
    }}>
      {toasts.map((toast, i) => (
        <Toast key={toast.id} notification={toast} onDismiss={onDismiss} index={i} />
      ))}
    </div>
  );
}
