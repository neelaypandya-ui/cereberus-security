interface ThreatLevelBannerProps {
  level: string;
}

const THREAT_CONFIG: Record<string, { label: string; defcon: string; color: string; bg: string; glow: string }> = {
  none: {
    label: 'ALL CLEAR',
    defcon: 'DEFCON 5',
    color: 'var(--cyan-primary)',
    bg: 'rgba(0, 229, 255, 0.05)',
    glow: 'rgba(0, 229, 255, 0.15)',
  },
  low: {
    label: 'LOW THREAT',
    defcon: 'DEFCON 4',
    color: 'var(--status-online)',
    bg: 'rgba(76, 175, 80, 0.05)',
    glow: 'rgba(76, 175, 80, 0.15)',
  },
  medium: {
    label: 'ELEVATED',
    defcon: 'DEFCON 3',
    color: 'var(--amber-primary)',
    bg: 'rgba(255, 171, 0, 0.05)',
    glow: 'rgba(255, 171, 0, 0.15)',
  },
  high: {
    label: 'HIGH THREAT',
    defcon: 'DEFCON 2',
    color: 'var(--severity-high)',
    bg: 'rgba(255, 87, 34, 0.08)',
    glow: 'rgba(255, 87, 34, 0.2)',
  },
  critical: {
    label: 'CRITICAL',
    defcon: 'DEFCON 1',
    color: 'var(--severity-critical)',
    bg: 'rgba(255, 23, 68, 0.1)',
    glow: 'rgba(255, 23, 68, 0.3)',
  },
};

export function ThreatLevelBanner({ level }: ThreatLevelBannerProps) {
  const config = THREAT_CONFIG[level] || THREAT_CONFIG.none;
  const isPulsing = level === 'high' || level === 'critical';

  return (
    <div
      className={isPulsing ? 'threat-banner-pulse' : ''}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 20px',
        background: config.bg,
        border: `1px solid ${config.color}`,
        borderRadius: '8px',
        marginBottom: '20px',
        boxShadow: isPulsing ? `0 0 20px ${config.glow}` : 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          width: '10px',
          height: '10px',
          borderRadius: '50%',
          backgroundColor: config.color,
          boxShadow: `0 0 8px ${config.color}`,
        }} />
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '13px',
          fontWeight: 700,
          color: config.color,
          letterSpacing: '2px',
        }}>
          {config.defcon}
        </span>
      </div>
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        color: config.color,
        letterSpacing: '3px',
      }}>
        {config.label}
      </span>
    </div>
  );
}
