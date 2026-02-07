import { useState, useCallback, useRef } from 'react';

export interface Notification {
  id: string;
  severity: string;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}

let notificationIdCounter = 0;

export function useNotifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [toasts, setToasts] = useState<Notification[]>([]);
  const maxToasts = 5;
  const maxNotifications = 100;
  const toastTimers = useRef<Map<string, number>>(new Map());

  const addNotification = useCallback((severity: string, title: string, message: string) => {
    const id = `notif-${++notificationIdCounter}-${Date.now()}`;
    const notif: Notification = {
      id,
      severity,
      title,
      message,
      timestamp: new Date().toISOString(),
      read: false,
    };

    setNotifications((prev) => [notif, ...prev].slice(0, maxNotifications));
    setToasts((prev) => [notif, ...prev].slice(0, maxToasts));

    // Auto-dismiss toast after 5s
    const timer = window.setTimeout(() => {
      dismissToast(id);
    }, 5000);
    toastTimers.current.set(id, timer);

    return id;
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = toastTimers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      toastTimers.current.delete(id);
    }
  }, []);

  const markRead = useCallback((id: string) => {
    setNotifications((prev) => prev.map((n) => n.id === id ? { ...n, read: true } : n));
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return {
    notifications,
    toasts,
    unreadCount,
    addNotification,
    dismissToast,
    markRead,
    markAllRead,
  };
}
