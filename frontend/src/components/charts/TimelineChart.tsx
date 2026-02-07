import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';

interface TimelineChartProps {
  data: Array<{ timestamp?: string; name?: string; [key: string]: unknown }>;
  dataKey: string;
  color?: string;
  height?: number;
  type?: 'area' | 'line';
  showGrid?: boolean;
  xKey?: string;
}

export function TimelineChart({
  data,
  dataKey,
  color = 'var(--cyan-primary)',
  height = 200,
  type = 'area',
  showGrid = true,
  xKey = 'timestamp',
}: TimelineChartProps) {
  const formatXAxis = (value: string) => {
    if (!value) return '';
    try {
      const d = new Date(value);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return value;
    }
  };

  const resolvedColor = color.startsWith('var(') ? '#00e5ff' : color;

  if (type === 'line') {
    return (
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          {showGrid && <CartesianGrid strokeDasharray="3 3" stroke="#2d2d2d" />}
          <XAxis dataKey={xKey} tickFormatter={formatXAxis} stroke="#666" fontSize={10} />
          <YAxis stroke="#666" fontSize={10} />
          <Tooltip
            contentStyle={{ background: '#161616', border: '1px solid #2d2d2d', borderRadius: '6px', fontSize: '12px' }}
            labelStyle={{ color: '#a0a0a0' }}
          />
          <Line type="monotone" dataKey={dataKey} stroke={resolvedColor} strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
        {showGrid && <CartesianGrid strokeDasharray="3 3" stroke="#2d2d2d" />}
        <XAxis dataKey={xKey} tickFormatter={formatXAxis} stroke="#666" fontSize={10} />
        <YAxis stroke="#666" fontSize={10} />
        <Tooltip
          contentStyle={{ background: '#161616', border: '1px solid #2d2d2d', borderRadius: '6px', fontSize: '12px' }}
          labelStyle={{ color: '#a0a0a0' }}
        />
        <Area type="monotone" dataKey={dataKey} stroke={resolvedColor} fill={resolvedColor} fillOpacity={0.15} strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
