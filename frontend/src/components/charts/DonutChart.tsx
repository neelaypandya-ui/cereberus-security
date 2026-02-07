import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

interface DonutChartProps {
  data: Array<{ name: string; value: number; color?: string }>;
  height?: number;
  centerLabel?: string;
  centerValue?: string | number;
}

const DEFAULT_COLORS = ['#ff1744', '#ff5722', '#ff9800', '#ffc107', '#2196f3', '#4caf50', '#00e5ff'];

export function DonutChart({ data, height = 200, centerLabel, centerValue }: DonutChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={80}
          paddingAngle={2}
          strokeWidth={0}
        >
          {data.map((entry, index) => (
            <Cell key={index} fill={entry.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: '#161616', border: '1px solid #2d2d2d', borderRadius: '6px', fontSize: '12px' }}
        />
        {centerLabel && (
          <text x="50%" y="47%" textAnchor="middle" fill="#e8e8e8" fontSize="20" fontWeight="700" fontFamily="'Cascadia Code', monospace">
            {centerValue ?? total}
          </text>
        )}
        {centerLabel && (
          <text x="50%" y="58%" textAnchor="middle" fill="#666" fontSize="10" letterSpacing="1">
            {centerLabel.toUpperCase()}
          </text>
        )}
      </PieChart>
    </ResponsiveContainer>
  );
}
