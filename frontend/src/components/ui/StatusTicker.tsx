interface TickerEvent {
  time: string;
  module: string;
  message: string;
}

interface StatusTickerProps {
  events: TickerEvent[];
}

export function StatusTicker({ events }: StatusTickerProps) {
  if (events.length === 0) return null;

  const tickerText = events
    .map((e) => `[${e.time} UTC] ${e.module} \u2014 ${e.message}`)
    .join('     \u2502     ');

  return (
    <div style={{
      position: 'fixed',
      bottom: 0,
      left: 'var(--sidebar-width)',
      right: 0,
      height: 'var(--ticker-height)',
      background: '#0a0a0a',
      borderTop: '1px solid var(--border-default)',
      overflow: 'hidden',
      display: 'flex',
      alignItems: 'center',
      zIndex: 100,
    }}>
      <div
        className="ticker-scroll"
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '16px',
          color: 'var(--cyan-primary)',
          paddingLeft: '100%',
        }}
      >
        {tickerText}
      </div>
    </div>
  );
}
