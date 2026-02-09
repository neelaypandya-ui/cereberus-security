import { useCallback } from 'react';

interface CsvExportButtonProps {
  data: Record<string, unknown>[];
  filename: string;
  columns?: { key: string; label: string }[];
}

export function CsvExportButton({ data, filename, columns }: CsvExportButtonProps) {
  const handleExport = useCallback(() => {
    if (!data || data.length === 0) return;

    const cols = columns || Object.keys(data[0]).map(key => ({ key, label: key }));

    const escapeCell = (val: unknown): string => {
      const str = val === null || val === undefined ? '' : String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const header = cols.map(c => escapeCell(c.label)).join(',');
    const rows = data.map(row =>
      cols.map(c => escapeCell(row[c.key])).join(',')
    );
    const csv = [header, ...rows].join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data, filename, columns]);

  return (
    <button
      onClick={handleExport}
      disabled={!data || data.length === 0}
      aria-label={`Export ${filename} as CSV`}
      style={{
        background: 'transparent',
        border: '1px solid var(--border-default)',
        color: 'var(--text-secondary)',
        padding: '4px 10px',
        cursor: data && data.length > 0 ? 'pointer' : 'not-allowed',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        letterSpacing: '1px',
        borderRadius: '2px',
        display: 'flex',
        alignItems: 'center',
        gap: '4px',
        opacity: data && data.length > 0 ? 1 : 0.5,
      }}
    >
      {'\u{1F4E5}'} CSV
    </button>
  );
}
