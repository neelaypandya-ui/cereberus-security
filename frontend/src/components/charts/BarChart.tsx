import { BarChart as RechartsBarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface BarChartProps {
  data: Array<{ name: string; value: number; [key: string]: unknown }>;
  dataKey?: string;
  color?: string;
  height?: number;
  xKey?: string;
}

export function BarChart({ data, dataKey = 'value', color = '#00e5ff', height = 200, xKey = 'name' }: BarChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsBarChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2d2d2d" />
        <XAxis dataKey={xKey} stroke="#666" fontSize={10} />
        <YAxis stroke="#666" fontSize={10} />
        <Tooltip
          contentStyle={{ background: '#161616', border: '1px solid #2d2d2d', borderRadius: '6px', fontSize: '12px' }}
        />
        <Bar dataKey={dataKey} fill={color} radius={[4, 4, 0, 0]} />
      </RechartsBarChart>
    </ResponsiveContainer>
  );
}
