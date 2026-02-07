interface Blip {
  angle: number;
  distance: number;
  severity: string;
}

interface RadarSweepProps {
  size?: number;
  blips?: Blip[];
  sweepColor?: string;
}

const severityBlipColors: Record<string, string> = {
  critical: '#ff1744',
  high: '#ff5722',
  medium: '#ff9800',
  low: '#ffc107',
  info: '#2196f3',
};

export function RadarSweep({ size = 240, blips = [], sweepColor = '#00e5ff' }: RadarSweepProps) {
  const cx = size / 2;
  const cy = size / 2;
  const maxRadius = size / 2 - 20;
  const rings = [0.25, 0.5, 0.75, 1.0];
  const ringLabels = ['LOCAL', 'LAN', 'WAN', 'EXT'];

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* Background */}
      <circle cx={cx} cy={cy} r={maxRadius} fill="rgba(0,0,0,0.4)" stroke="none" />

      {/* Concentric rings */}
      {rings.map((r, i) => (
        <g key={i}>
          <circle
            cx={cx}
            cy={cy}
            r={maxRadius * r}
            fill="none"
            stroke={sweepColor}
            strokeWidth={0.5}
            opacity={0.2}
          />
          <text
            x={cx + maxRadius * r - 4}
            y={cy - 4}
            fill={sweepColor}
            fontSize="7"
            fontFamily="var(--font-mono)"
            opacity={0.3}
            textAnchor="end"
          >
            {ringLabels[i]}
          </text>
        </g>
      ))}

      {/* Cross lines */}
      <line x1={cx} y1={cy - maxRadius} x2={cx} y2={cy + maxRadius} stroke={sweepColor} strokeWidth={0.3} opacity={0.15} />
      <line x1={cx - maxRadius} y1={cy} x2={cx + maxRadius} y2={cy} stroke={sweepColor} strokeWidth={0.3} opacity={0.15} />

      {/* Sweep line with glow */}
      <defs>
        <linearGradient id="sweepGrad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={sweepColor} stopOpacity="0" />
          <stop offset="100%" stopColor={sweepColor} stopOpacity="0.8" />
        </linearGradient>
        <filter id="sweepGlow">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Sweep wedge (trailing glow) */}
      <g className="radar-sweep">
        <path
          d={`M ${cx} ${cy} L ${cx} ${cy - maxRadius} A ${maxRadius} ${maxRadius} 0 0 1 ${cx + maxRadius * Math.sin(Math.PI / 6)} ${cy - maxRadius * Math.cos(Math.PI / 6)} Z`}
          fill="url(#sweepGrad)"
          opacity={0.15}
        />
        <line
          x1={cx}
          y1={cy}
          x2={cx}
          y2={cy - maxRadius}
          stroke={sweepColor}
          strokeWidth={1.5}
          filter="url(#sweepGlow)"
          opacity={0.9}
        />
      </g>

      {/* Blips */}
      {blips.map((blip, i) => {
        const rad = (blip.angle * Math.PI) / 180;
        const dist = maxRadius * Math.min(blip.distance, 1);
        const bx = cx + dist * Math.cos(rad);
        const by = cy + dist * Math.sin(rad);
        const color = severityBlipColors[blip.severity] || sweepColor;
        return (
          <g key={i}>
            <circle cx={bx} cy={by} r={3} fill={color} opacity={0.8} />
            <circle cx={bx} cy={by} r={6} fill={color} opacity={0.2} />
          </g>
        );
      })}

      {/* Center dot */}
      <circle cx={cx} cy={cy} r={3} fill={sweepColor} />
      <circle cx={cx} cy={cy} r={6} fill={sweepColor} opacity={0.2} />
    </svg>
  );
}
