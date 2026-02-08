/**
 * Ghost Protocol — session self-destructs after inactivity.
 * 15-minute inactivity timeout. When the operator goes silent, the session ends.
 */

import { useEffect, useRef, useCallback } from 'react';

const TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
const ACTIVITY_EVENTS = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'] as const;

export function useSessionTimeout(onTimeout?: () => void) {
  const timerRef = useRef<number | null>(null);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('cereberus_token');
    if (onTimeout) {
      onTimeout();
    } else {
      window.location.href = '/login';
    }
  }, [onTimeout]);

  const resetTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    timerRef.current = window.setTimeout(handleLogout, TIMEOUT_MS);
  }, [handleLogout]);

  useEffect(() => {
    // Only activate if user is authenticated
    const token = localStorage.getItem('cereberus_token');
    if (!token) return;

    resetTimer();

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, resetTimer, { passive: true });
    }

    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, resetTimer);
      }
    };
  }, [resetTimer]);
}
