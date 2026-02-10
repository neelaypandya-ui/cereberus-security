import { useState } from 'react';
import { api } from '../services/api';

export function ReportButton() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    try {
      const blob = await api.generateReport();
      if (!blob || blob.size === 0) {
        setError('REPORT EMPTY');
        setLoading(false);
        return;
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cereberus-report-${new Date().toISOString().slice(0, 10)}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[ReportButton] generation failed:', err);
      setError('GENERATION FAILED');
    }
    setLoading(false);
  };

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
      <button
        onClick={handleGenerate}
        disabled={loading}
        style={{
          padding: '6px 16px',
          fontSize: '17px',
          fontWeight: 600,
          background: loading ? 'var(--bg-tertiary)' : error ? 'rgba(255,23,68,0.2)' : 'var(--red-primary)',
          color: '#fff',
          border: error ? '1px solid var(--severity-critical)' : 'none',
          borderRadius: '4px',
          cursor: loading ? 'wait' : 'pointer',
          letterSpacing: '1px',
          opacity: loading ? 0.6 : 1,
          transition: 'opacity 0.2s',
        }}
      >
        {loading ? 'GENERATING...' : error ? error : 'GENERATE REPORT'}
      </button>
    </div>
  );
}
