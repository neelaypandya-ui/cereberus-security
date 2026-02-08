import {
  ComposedChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';

interface DualLineChartProps {
  data: Array<Record<string, unknown>>;
  actualKey: string;
  predictedKey: string;
  xKey?: string;
  height?: number;
  actualColor?: string;
  predictedColor?: string;
  thresholdValue?: number;
  thresholdLabel?: string;
}

export function DualLineChart({
  data,
  actualKey,
  predictedKey,
  xKey = 'label',
  height = 200,
  actualColor = '#00e5ff',
  predictedColor = '#ff9800',
  thresholdValue,
  thresholdLabel,
}: DualLineChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2d2d2d" />
        <XAxis dataKey={xKey} stroke="#666" fontSize={16} />
        <YAxis stroke="#666" fontSize={16} />
        <Tooltip
          contentStyle={{
            background: '#161616',
            border: '1px solid #2d2d2d',
            borderRadius: '6px',
            fontSize: '18px',
          }}
          labelStyle={{ color: '#a0a0a0' }}
        />
        <Line
          type="monotone"
          dataKey={actualKey}
          stroke={actualColor}
          strokeWidth={2}
          dot={false}
          name="Actual"
        />
        <Line
          type="monotone"
          dataKey={predictedKey}
          stroke={predictedColor}
          strokeWidth={2}
          strokeDasharray="5 3"
          dot={false}
          name="Predicted"
        />
        {thresholdValue !== undefined && (
          <ReferenceLine
            y={thresholdValue}
            stroke="#ff1744"
            strokeDasharray="3 3"
            strokeWidth={1}
            label={{
              value: thresholdLabel || 'Threshold',
              position: 'right',
              fill: '#ff1744',
              fontSize: 15,
            }}
          />
        )}
      </ComposedChart>
    </ResponsiveContainer>
  );
}
