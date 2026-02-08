import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

// ── Types ──────────────────────────────────────────────────────

interface DiskUsage {
  total: number;
  used: number;
  free: number;
  percent: number;
}

interface CleanupCategory {
  id: string;
  name: string;
  description: string;
  security_note: string;
  size_bytes: number;
  file_count: number;
}

interface AnalysisResult {
  disk_usage: DiskUsage;
  categories: CleanupCategory[];
  total_cleanable_bytes: number;
}

interface CleanResult {
  results: Record<string, { freed_bytes: number; files_deleted: number; errors: string[] }>;
  total_freed: number;
}

interface LargeFile {
  path: string;
  size_bytes: number;
  modified: string;
  extension: string;
}

interface LargeFilesResult {
  files: LargeFile[];
}

// ── Helpers ────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB';
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB';
  return bytes + ' B';
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function truncatePath(path: string, maxLen: number = 60): string {
  if (path.length <= maxLen) return path;
  return '...' + path.slice(path.length - maxLen);
}

function usageColor(percent: number): string {
  if (percent > 85) return 'var(--red-primary)';
  if (percent > 70) return '#f59e0b';
  return 'var(--status-online)';
}

function sizeIndicatorColor(bytes: number): string {
  if (bytes > 500 * 1e6) return 'var(--red-primary)';
  if (bytes > 100 * 1e6) return '#f59e0b';
  return 'var(--status-online)';
}

// ── Skeleton Loader ────────────────────────────────────────────

function SkeletonBlock({ width, height }: { width: string; height: string }) {
  return (
    <div
      style={{
        width,
        height,
        background: '#2d2d2d',
        borderRadius: '4px',
        animation: 'pulse 1.5s ease-in-out infinite',
      }}
    />
  );
}

function LoadingSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <SkeletonBlock width="100%" height="8px" />
      <div style={{ display: 'flex', gap: '8px' }}>
        <SkeletonBlock width="30%" height="14px" />
        <SkeletonBlock width="30%" height="14px" />
        <SkeletonBlock width="30%" height="14px" />
      </div>
      <div style={{ display: 'flex', gap: '12px' }}>
        <SkeletonBlock width="120px" height="32px" />
        <SkeletonBlock width="140px" height="32px" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        {[1, 2, 3, 4].map((i) => (
          <SkeletonBlock key={i} width="100%" height="80px" />
        ))}
      </div>
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 0.8; }
        }
      `}</style>
    </div>
  );
}

// ── Section Header ─────────────────────────────────────────────

function SectionHeader({ label }: { label: string }) {
  return (
    <div style={{ marginBottom: '12px' }}>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '17px',
          letterSpacing: '2px',
          color: 'var(--cyan-primary)',
          marginBottom: '6px',
        }}
      >
        {label}
      </div>
      <div style={{ height: '1px', background: 'var(--border-default)' }} />
    </div>
  );
}

// ── Spinner ────────────────────────────────────────────────────

function Spinner({ size = 12, color = 'currentColor' }: { size?: number; color?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      style={{ animation: 'spin 1s linear infinite', flexShrink: 0 }}
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        fill="none"
        stroke={color}
        strokeWidth="3"
        strokeDasharray="31.4 31.4"
        strokeLinecap="round"
      />
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </svg>
  );
}

// ── Main Component ─────────────────────────────────────────────

export function DiskCleanupPanel() {
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [largeFiles, setLargeFiles] = useState<LargeFile[] | null>(null);
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [cleaning, setCleaning] = useState(false);
  const [scanningFiles, setScanningFiles] = useState(false);
  const [cleanResult, setCleanResult] = useState<CleanResult | null>(null);
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastAnalyzed, setLastAnalyzed] = useState<Date | null>(null);
  const [scanComplete, setScanComplete] = useState(false);
  const [deletingFile, setDeletingFile] = useState<string | null>(null);

  // ── Data Loading ─────────────────────────────────────────────

  const loadAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDiskAnalysis() as AnalysisResult;
      setAnalysis(data);
      setLastAnalyzed(new Date());
      setScanComplete(true);
      setTimeout(() => setScanComplete(false), 3000);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Analysis failed';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAnalysis();
  }, [loadAnalysis]);

  // Auto-clear clean result after 10 seconds
  useEffect(() => {
    if (!cleanResult) return;
    const timer = setTimeout(() => setCleanResult(null), 10000);
    return () => clearTimeout(timer);
  }, [cleanResult]);

  // Reset confirm if selection changes
  useEffect(() => {
    setConfirmPurge(false);
  }, [selectedCategories]);

  // ── Actions ──────────────────────────────────────────────────

  const handleAnalyze = async () => {
    setCleanResult(null);
    await loadAnalysis();
  };

  const handlePurge = async () => {
    if (!confirmPurge) {
      setConfirmPurge(true);
      return;
    }
    setCleaning(true);
    setConfirmPurge(false);
    try {
      const result = await api.cleanDisk(Array.from(selectedCategories)) as CleanResult;
      setCleanResult(result);
      setSelectedCategories(new Set());
      // Reload analysis to get updated numbers
      await loadAnalysis();
      // Refresh large files list if it was scanned
      if (largeFiles) handleScanLargeFiles();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Cleanup failed';
      setError(msg);
    } finally {
      setCleaning(false);
    }
  };

  const handleScanLargeFiles = async () => {
    setScanningFiles(true);
    try {
      const data = await api.getLargeFiles(100, 20) as LargeFilesResult;
      setLargeFiles(data.files.sort((a, b) => b.size_bytes - a.size_bytes));
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Large file scan failed';
      setError(msg);
    } finally {
      setScanningFiles(false);
    }
  };

  const handleDeleteFile = async (path: string) => {
    setDeletingFile(path);
    setError(null);
    try {
      await api.deleteFile(path);
      // Remove from local list immediately
      setLargeFiles((prev) => prev ? prev.filter((f) => f.path !== path) : prev);
      // Refresh categories + disk usage in background
      loadAnalysis();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Delete failed';
      setError(msg);
    } finally {
      setDeletingFile(null);
    }
  };

  const toggleCategory = (id: string) => {
    setSelectedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // ── Computed ─────────────────────────────────────────────────

  const totalFreed = cleanResult
    ? cleanResult.total_freed
    : 0;

  const totalFilesRemoved = cleanResult
    ? Object.values(cleanResult.results).reduce((sum, r) => sum + r.files_deleted, 0)
    : 0;

  // ── Render ───────────────────────────────────────────────────

  return (
    <IntelCard title="DISK SANITATION" classification="RESTRICTED" status="active">
      {loading && !analysis ? (
        <LoadingSkeleton />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', opacity: loading && analysis ? 0.5 : 1, transition: 'opacity 0.3s' }}>

          {/* ── Section 1: Disk Usage Bar ─────────────────────── */}
          {analysis && (
            <div>
              <SectionHeader label="DISK USAGE" />
              <div
                style={{
                  height: '8px',
                  background: '#2d2d2d',
                  borderRadius: '4px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${Math.min(analysis.disk_usage.percent, 100)}%`,
                    height: '100%',
                    background: usageColor(analysis.disk_usage.percent),
                    borderRadius: '4px',
                    transition: 'width 0.6s ease',
                  }}
                />
              </div>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginTop: '8px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  letterSpacing: '1px',
                  color: 'var(--text-secondary)',
                }}
              >
                <span>
                  USED{' '}
                  <span style={{ color: 'var(--text-primary)', fontWeight: 700 }}>
                    {formatBytes(analysis.disk_usage.used)}
                  </span>
                </span>
                <span>
                  FREE{' '}
                  <span style={{ color: 'var(--status-online)', fontWeight: 700 }}>
                    {formatBytes(analysis.disk_usage.free)}
                  </span>
                </span>
                <span>
                  TOTAL{' '}
                  <span style={{ color: 'var(--text-primary)', fontWeight: 700 }}>
                    {formatBytes(analysis.disk_usage.total)}
                  </span>
                </span>
              </div>
              <div
                style={{
                  textAlign: 'center',
                  marginTop: '4px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '24px',
                  fontWeight: 700,
                  color: usageColor(analysis.disk_usage.percent),
                  letterSpacing: '2px',
                }}
              >
                {analysis.disk_usage.percent.toFixed(1)}%
              </div>
            </div>
          )}

          {/* ── Section 2: Action Buttons ─────────────────────── */}
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '16px',
                letterSpacing: '2px',
                padding: '8px 20px',
                background: 'transparent',
                border: '1px solid var(--cyan-primary)',
                color: 'var(--cyan-primary)',
                borderRadius: '2px',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.5 : 1,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'all 0.2s',
              }}
            >
              {loading && <Spinner size={12} color="var(--cyan-primary)" />}
              {loading ? 'SCANNING DISK...' : 'ANALYZE'}
            </button>
            <button
              onClick={handlePurge}
              disabled={selectedCategories.size === 0 || cleaning}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '16px',
                letterSpacing: '2px',
                padding: '8px 20px',
                background: confirmPurge ? 'rgba(220, 38, 38, 0.1)' : 'transparent',
                border: `1px solid var(--red-primary)`,
                color: 'var(--red-primary)',
                borderRadius: '2px',
                cursor: selectedCategories.size === 0 || cleaning ? 'not-allowed' : 'pointer',
                opacity: selectedCategories.size === 0 && !cleaning ? 0.4 : 1,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'all 0.2s',
              }}
            >
              {cleaning && <Spinner size={12} color="var(--red-primary)" />}
              {confirmPurge ? 'CONFIRM PURGE?' : 'PURGE SELECTED'}
            </button>
          </div>

          {/* ── Error Banner ────────────────────────────────── */}
          {error && (
            <div
              style={{
                padding: '12px 16px',
                background: 'rgba(220, 38, 38, 0.06)',
                borderLeft: '3px solid var(--red-primary)',
                borderRadius: '2px',
                fontFamily: 'var(--font-mono)',
                fontSize: '17px',
                letterSpacing: '1px',
                color: 'var(--red-primary)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <span>ANALYSIS ERROR &mdash; {error}</span>
              <button
                onClick={() => setError(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--red-primary)',
                  cursor: 'pointer',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '18px',
                }}
              >
                &times;
              </button>
            </div>
          )}

          {/* ── Scan Complete Banner ─────────────────────────── */}
          {scanComplete && (
            <div
              style={{
                padding: '12px 16px',
                background: 'rgba(0, 229, 255, 0.06)',
                borderLeft: '3px solid var(--cyan-primary)',
                borderRadius: '2px',
                fontFamily: 'var(--font-mono)',
                fontSize: '17px',
                letterSpacing: '1px',
                color: 'var(--cyan-primary)',
                animation: 'fadeIn 0.3s ease',
              }}
            >
              SCAN COMPLETE &mdash; {analysis?.categories.length ?? 0} categories analyzed &middot; {lastAnalyzed?.toLocaleTimeString()}
            </div>
          )}

          {/* ── Section 4: Results Banner ─────────────────────── */}
          {cleanResult && (
            <div
              style={{
                padding: '12px 16px',
                background: 'rgba(76, 175, 80, 0.06)',
                borderLeft: '3px solid var(--status-online)',
                borderRadius: '2px',
                fontFamily: 'var(--font-mono)',
                fontSize: '17px',
                letterSpacing: '1px',
                color: 'var(--status-online)',
                animation: 'fadeIn 0.3s ease',
              }}
            >
              PURGE COMPLETE &mdash; {formatBytes(totalFreed)} freed &middot; {totalFilesRemoved} files removed
              <style>{`
                @keyframes fadeIn {
                  from { opacity: 0; transform: translateY(-4px); }
                  to { opacity: 1; transform: translateY(0); }
                }
              `}</style>
            </div>
          )}

          {/* ── Section 3: Cleanup Categories Grid ────────────── */}
          {analysis && analysis.categories.length > 0 && (
            <div>
              <SectionHeader label="CLEANUP CATEGORIES" />
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '10px',
                }}
              >
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '16px',
                    letterSpacing: '1px',
                    color: 'var(--text-muted)',
                  }}
                >
                  {selectedCategories.size} of {analysis.categories.length} selected &middot;{' '}
                  TOTAL CLEANABLE: {formatBytes(analysis.total_cleanable_bytes)}
                </span>
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '12px',
                }}
              >
                {analysis.categories.map((cat) => {
                  const isSelected = selectedCategories.has(cat.id);
                  return (
                    <div
                      key={cat.id}
                      onClick={() => toggleCategory(cat.id)}
                      style={{
                        background: '#1a1a1a',
                        border: `1px solid ${isSelected ? 'var(--cyan-primary)' : '#2d2d2d'}`,
                        borderRadius: '4px',
                        padding: '12px',
                        cursor: 'pointer',
                        transition: 'border-color 0.2s',
                        display: 'flex',
                        gap: '10px',
                        alignItems: 'flex-start',
                      }}
                    >
                      {/* Checkbox */}
                      <div
                        style={{
                          width: '16px',
                          height: '16px',
                          border: `1px solid ${isSelected ? 'var(--cyan-primary)' : '#555'}`,
                          borderRadius: '2px',
                          background: isSelected ? 'rgba(0, 229, 255, 0.15)' : 'transparent',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0,
                          marginTop: '1px',
                          transition: 'all 0.2s',
                        }}
                      >
                        {isSelected && (
                          <svg width="10" height="10" viewBox="0 0 10 10">
                            <polyline
                              points="2,5 4,7 8,3"
                              fill="none"
                              stroke="var(--cyan-primary)"
                              strokeWidth="1.5"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            />
                          </svg>
                        )}
                      </div>

                      {/* Content */}
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            marginBottom: '4px',
                          }}
                        >
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '18px',
                              fontWeight: 700,
                              color: 'var(--text-primary)',
                              letterSpacing: '1px',
                            }}
                          >
                            {cat.name}
                          </span>
                          {/* Size indicator dot */}
                          <div
                            style={{
                              width: '6px',
                              height: '6px',
                              borderRadius: '50%',
                              background: sizeIndicatorColor(cat.size_bytes),
                              flexShrink: 0,
                            }}
                          />
                        </div>
                        <div
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '17px',
                            color: 'var(--text-secondary)',
                            marginBottom: '4px',
                          }}
                        >
                          {formatBytes(cat.size_bytes)} &middot; {cat.file_count.toLocaleString()} files
                        </div>
                        <div
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '16px',
                            color: 'var(--text-muted)',
                            fontStyle: 'italic',
                            lineHeight: '1.4',
                          }}
                        >
                          {cat.security_note}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── Section 5: Large Files Table ──────────────────── */}
          <div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '6px',
              }}
            >
              <SectionHeader label="LARGE FILES" />
              <button
                onClick={handleScanLargeFiles}
                disabled={scanningFiles}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  letterSpacing: '2px',
                  padding: '6px 16px',
                  background: 'transparent',
                  border: '1px solid var(--cyan-primary)',
                  color: 'var(--cyan-primary)',
                  borderRadius: '2px',
                  cursor: scanningFiles ? 'not-allowed' : 'pointer',
                  opacity: scanningFiles ? 0.5 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  transition: 'all 0.2s',
                  flexShrink: 0,
                }}
              >
                {scanningFiles && <Spinner size={10} color="var(--cyan-primary)" />}
                SCAN
              </button>
            </div>

            {largeFiles === null && !scanningFiles && (
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  letterSpacing: '1px',
                  color: 'var(--text-muted)',
                  padding: '20px 0',
                  textAlign: 'center',
                }}
              >
                CLICK SCAN TO DETECT LARGE FILES (&gt;100 MB)
              </div>
            )}

            {scanningFiles && (
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  letterSpacing: '1px',
                  color: 'var(--text-muted)',
                  padding: '20px 0',
                  textAlign: 'center',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                }}
              >
                <Spinner size={12} color="var(--text-muted)" />
                SCANNING FILESYSTEM...
              </div>
            )}

            {largeFiles && largeFiles.length === 0 && !scanningFiles && (
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  letterSpacing: '1px',
                  color: 'var(--text-muted)',
                  padding: '20px 0',
                  textAlign: 'center',
                }}
              >
                NO LARGE FILES DETECTED
              </div>
            )}

            {largeFiles && largeFiles.length > 0 && !scanningFiles && (
              <div style={{ overflowX: 'auto' }}>
                <table
                  style={{
                    width: '100%',
                    borderCollapse: 'collapse',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '16px',
                  }}
                >
                  <thead>
                    <tr>
                      {['PATH', 'SIZE', 'MODIFIED', 'TYPE', ''].map((col) => (
                        <th
                          key={col}
                          style={{
                            textAlign: 'left',
                            padding: '8px 10px',
                            borderBottom: '1px solid var(--border-default)',
                            color: 'var(--text-muted)',
                            letterSpacing: '2px',
                            fontSize: '15px',
                            fontWeight: 600,
                          }}
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {largeFiles.slice(0, 20).map((file, idx) => (
                      <tr
                        key={idx}
                        style={{
                          borderBottom: '1px solid rgba(45, 45, 45, 0.5)',
                        }}
                      >
                        <td
                          style={{
                            padding: '7px 10px',
                            color: 'var(--text-secondary)',
                            maxWidth: '350px',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={file.path}
                        >
                          {truncatePath(file.path)}
                        </td>
                        <td
                          style={{
                            padding: '7px 10px',
                            color: 'var(--text-primary)',
                            fontWeight: 700,
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {formatBytes(file.size_bytes)}
                        </td>
                        <td
                          style={{
                            padding: '7px 10px',
                            color: 'var(--text-muted)',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {formatDate(file.modified)}
                        </td>
                        <td
                          style={{
                            padding: '7px 10px',
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                          }}
                        >
                          {file.extension || '--'}
                        </td>
                        <td style={{ padding: '7px 10px', textAlign: 'right' }}>
                          <button
                            onClick={(e) => { e.stopPropagation(); handleDeleteFile(file.path); }}
                            disabled={deletingFile === file.path}
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '15px',
                              letterSpacing: '1px',
                              padding: '3px 10px',
                              background: 'transparent',
                              border: '1px solid var(--red-primary)',
                              color: 'var(--red-primary)',
                              borderRadius: '2px',
                              cursor: deletingFile === file.path ? 'not-allowed' : 'pointer',
                              opacity: deletingFile === file.path ? 0.5 : 0.7,
                              transition: 'all 0.2s',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            {deletingFile === file.path ? <Spinner size={8} color="var(--red-primary)" /> : null}
                            {deletingFile === file.path ? 'DELETING' : 'DELETE'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </IntelCard>
  );
}
