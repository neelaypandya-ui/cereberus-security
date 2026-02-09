export function PanelSkeleton() {
  return (
    <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header skeleton */}
      <div style={{ display: 'flex', gap: '16px' }}>
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="skeleton-shimmer" style={{
            height: '80px', flex: 1, borderRadius: '4px',
            background: 'var(--bg-tertiary)',
          }} />
        ))}
      </div>
      {/* Table skeleton */}
      {[1, 2, 3, 4, 5].map(i => (
        <div key={i} className="skeleton-shimmer" style={{
          height: '40px', borderRadius: '4px',
          background: 'var(--bg-tertiary)',
          animationDelay: `${i * 0.1}s`,
        }} />
      ))}
    </div>
  );
}
