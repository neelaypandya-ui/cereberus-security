import { useState } from 'react';
import { api } from '../services/api';

export function ReportButton() {
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const blob = await api.generateReport();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cereberus-report-${new Date().toISOString().slice(0, 10)}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      // Could show error toast in future
    }
    setLoading(false);
  };

  return (
    <button
      onClick={handleGenerate}
      disabled={loading}
      style={{
        padding: '6px 16px',
        fontSize: '11px',
        fontWeight: 600,
        background: loading ? 'var(--bg-tertiary)' : 'var(--red-primary)',
        color: '#fff',
        border: 'none',
        borderRadius: '4px',
        cursor: loading ? 'wait' : 'pointer',
        letterSpacing: '1px',
        opacity: loading ? 0.6 : 1,
        transition: 'opacity 0.2s',
      }}
    >
      {loading ? 'GENERATING...' : 'GENERATE REPORT'}
    </button>
  );
}
