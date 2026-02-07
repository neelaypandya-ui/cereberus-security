interface CornerBracketsProps {
  color?: string;
  size?: number;
}

export function CornerBrackets({ color = 'var(--cyan-primary)', size = 14 }: CornerBracketsProps) {
  const strokeWidth = 2;

  const bracket = (rotation: number, top: string, left: string, right: string, bottom: string) => (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      style={{
        position: 'absolute',
        top,
        left,
        right,
        bottom,
        transform: `rotate(${rotation}deg)`,
        pointerEvents: 'none',
      }}
    >
      <path
        d={`M 0 ${size} L 0 0 L ${size} 0`}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
      />
    </svg>
  );

  return (
    <>
      {bracket(0, '-1px', '-1px', 'auto', 'auto')}
      {bracket(90, '-1px', 'auto', '-1px', 'auto')}
      {bracket(270, 'auto', '-1px', 'auto', '-1px')}
      {bracket(180, 'auto', 'auto', '-1px', '-1px')}
    </>
  );
}
