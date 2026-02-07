import { ResponsiveContainer } from 'recharts';

interface GaugeChartProps {
  value: number;
  max?: number;
  height?: number;
  label?: string;
  zones?: { green: number; yellow: number; red: number };
}

export function GaugeChart({ value, max = 1, height = 160, label, zones }: GaugeChartProps) {
  const defaultZones = zones || { green: 0.3, yellow: 0.6, red: 1.0 };
  const pct = Math.min(value / max, 1.0);
  const angle = pct * 180; // 0-180 degrees for semi-circle

  const getColor = () => {
    if (pct <= defaultZones.green) return '#4caf50';
    if (pct <= defaultZones.yellow) return '#ff9800';
    return '#ff1744';
  };

  const getLabel = () => {
    if (pct <= defaultZones.green) return 'NOMINAL';
    if (pct <= defaultZones.yellow) return 'ELEVATED';
    return 'CRITICAL';
  };

  const cx = 100;
  const cy = 90;
  const r = 70;

  const polarToCartesian = (angleDeg: number) => {
    const rad = (angleDeg * Math.PI) / 180;
    return {
      x: cx - r * Math.cos(rad),
      y: cy - r * Math.sin(rad),
    };
  };

  const arcEnd = polarToCartesian(angle);
  const largeArc = angle > 90 ? 1 : 0;

  return (
    <ResponsiveContainer width="100%" height={height}>
      <svg viewBox="0 0 200 120" style={{ overflow: 'visible' }}>
        {/* Background arc */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="#2d2d2d"
          strokeWidth="10"
          strokeLinecap="round"
        />

        {/* Green zone */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${polarToCartesian(defaultZones.green * 180).x} ${polarToCartesian(defaultZones.green * 180).y}`}
          fill="none"
          stroke="rgba(76, 175, 80, 0.2)"
          strokeWidth="10"
          strokeLinecap="round"
        />

        {/* Yellow zone */}
        <path
          d={`M ${polarToCartesian(defaultZones.green * 180).x} ${polarToCartesian(defaultZones.green * 180).y} A ${r} ${r} 0 0 1 ${polarToCartesian(defaultZones.yellow * 180).x} ${polarToCartesian(defaultZones.yellow * 180).y}`}
          fill="none"
          stroke="rgba(255, 152, 0, 0.2)"
          strokeWidth="10"
        />

        {/* Red zone */}
        <path
          d={`M ${polarToCartesian(defaultZones.yellow * 180).x} ${polarToCartesian(defaultZones.yellow * 180).y} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="rgba(255, 23, 68, 0.2)"
          strokeWidth="10"
        />

        {/* Value arc */}
        {pct > 0 && (
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 ${largeArc} 1 ${arcEnd.x} ${arcEnd.y}`}
            fill="none"
            stroke={getColor()}
            strokeWidth="10"
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 4px ${getColor()})` }}
          />
        )}

        {/* Needle */}
        <line
          x1={cx}
          y1={cy}
          x2={arcEnd.x}
          y2={arcEnd.y}
          stroke={getColor()}
          strokeWidth="2"
          strokeLinecap="round"
        />
        <circle cx={cx} cy={cy} r="4" fill={getColor()} />

        {/* Value text */}
        <text
          x={cx}
          y={cy - 15}
          textAnchor="middle"
          fill="#e8e8e8"
          fontSize="18"
          fontWeight="700"
          fontFamily="'Cascadia Code', monospace"
        >
          {(value * 100).toFixed(0)}%
        </text>

        {/* Status label */}
        <text
          x={cx}
          y={cy + 10}
          textAnchor="middle"
          fill={getColor()}
          fontSize="9"
          letterSpacing="2"
          fontFamily="'Cascadia Code', monospace"
        >
          {getLabel()}
        </text>

        {/* Bottom label */}
        {label && (
          <text
            x={cx}
            y={115}
            textAnchor="middle"
            fill="#666"
            fontSize="8"
            letterSpacing="1"
            fontFamily="'Cascadia Code', monospace"
          >
            {label.toUpperCase()}
          </text>
        )}
      </svg>
    </ResponsiveContainer>
  );
}
