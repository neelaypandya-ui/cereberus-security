import { useEffect } from 'react';

interface ShortcutHandlers {
  onFocusSearch?: () => void;
  onPanelSwitch?: (index: number) => void;
  onCloseModal?: () => void;
  onExport?: () => void;
  onToggleSidebar?: () => void;
  onShowShortcuts?: () => void;
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in inputs
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT') {
        if (e.key === 'Escape') {
          target.blur();
          handlers.onCloseModal?.();
        }
        return;
      }

      // Ctrl+K — Focus search
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        handlers.onFocusSearch?.();
      }

      // Ctrl+B — Toggle sidebar
      if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        handlers.onToggleSidebar?.();
      }

      // Ctrl+? — Show shortcuts overlay (Ctrl+Shift+/)
      if (e.ctrlKey && e.shiftKey && e.key === '?') {
        e.preventDefault();
        handlers.onShowShortcuts?.();
      }

      // 1-9 — Panel switch
      if (!e.ctrlKey && !e.altKey && !e.metaKey && e.key >= '1' && e.key <= '9') {
        const index = parseInt(e.key) - 1;
        handlers.onPanelSwitch?.(index);
      }

      // Escape — Close modals
      if (e.key === 'Escape') {
        handlers.onCloseModal?.();
      }

      // Ctrl+E — Export
      if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        handlers.onExport?.();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handlers]);
}
