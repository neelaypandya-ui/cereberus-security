interface KeyboardShortcutsOverlayProps {
  isOpen: boolean;
  onClose: () => void;
}

export function KeyboardShortcutsOverlay({ isOpen, onClose }: KeyboardShortcutsOverlayProps) {
  if (!isOpen) return null;

  const shortcuts = [
    { keys: 'Ctrl + B', action: 'Toggle sidebar' },
    { keys: 'Ctrl + K', action: 'Focus search' },
    { keys: 'Ctrl + ?', action: 'Show this help' },
    { keys: 'Ctrl + 1-9', action: 'Switch to panel 1-9' },
    { keys: 'Ctrl + E', action: 'Export data' },
    { keys: 'Escape', action: 'Close modals / overlays' },
  ];

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 10000,
    }} onClick={onClose}>
      <div className="intel-card" style={{
        padding: '24px', minWidth: '400px', maxWidth: '500px',
      }} onClick={e => e.stopPropagation()}>
        <div className="classification-banner" style={{ marginBottom: '16px' }}>
          OPERATOR MANUAL // KEYBOARD SHORTCUTS
        </div>
        {shortcuts.map(s => (
          <div key={s.keys} style={{
            display: 'flex', justifyContent: 'space-between',
            padding: '8px 0', borderBottom: '1px solid var(--border-default)',
            fontFamily: 'var(--font-mono)', fontSize: '14px',
          }}>
            <span style={{ color: 'var(--cyan-primary)' }}>{s.keys}</span>
            <span style={{ color: 'var(--text-secondary)' }}>{s.action}</span>
          </div>
        ))}
        <div style={{ textAlign: 'center', marginTop: '16px', color: 'var(--text-muted)', fontSize: '12px' }}>
          Press ESC or click outside to close
        </div>
      </div>
    </div>
  );
}
