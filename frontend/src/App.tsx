import { Component, ReactNode, useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import ChangePassword from './pages/ChangePassword';
import Dashboard from './pages/Dashboard';
import { api, setCsrfToken, getCsrfToken } from './services/api';
import { ToastProvider } from './hooks/useToast';

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: '40px', color: '#ff4444', fontFamily: 'monospace', background: '#0a0a0a', minHeight: '100vh' }}>
          <h2>CEREBERUS RENDER ERROR</h2>
          <pre style={{ color: '#e8e8e8', whiteSpace: 'pre-wrap', marginTop: '20px' }}>
            {this.state.error.message}
          </pre>
          <pre style={{ color: '#888', whiteSpace: 'pre-wrap', marginTop: '10px', fontSize: '18px' }}>
            {this.state.error.stack}
          </pre>
          <button
            onClick={() => { setCsrfToken(null); window.location.href = '/login'; }}
            style={{ marginTop: '20px', padding: '10px 20px', background: '#333', color: '#fff', border: '1px solid #666', cursor: 'pointer' }}
          >
            Clear Session &amp; Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function AuthGate({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking');

  useEffect(() => {
    // If CSRF token exists in memory, we just logged in — skip the round trip
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      setStatus('authenticated');
      return;
    }
    api.getMe()
      .then(() => setStatus('authenticated'))
      .catch(() => setStatus('unauthenticated'));
  }, []);

  if (status === 'checking') {
    return (
      <div style={{
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-primary, #0a0a0a)',
        fontFamily: 'var(--font-mono, monospace)',
      }}>
        <div style={{
          fontSize: '28px',
          fontWeight: 700,
          letterSpacing: '8px',
          color: 'var(--status-online, #00e676)',
          marginBottom: '16px',
        }}>
          CEREBERUS
        </div>
        <div style={{
          fontSize: '14px',
          letterSpacing: '4px',
          color: 'var(--cyan-primary, #00e5ff)',
          animation: 'pulse 1.5s ease-in-out infinite',
        }}>
          INITIALIZING SECURE SESSION
        </div>
      </div>
    );
  }
  if (status === 'unauthenticated') return <Navigate to="/login" />;
  return <>{children}</>;
}

function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/change-password" element={<ChangePassword />} />
          <Route
            path="/dashboard"
            element={<AuthGate><Dashboard /></AuthGate>}
          />
          <Route path="*" element={<Navigate to="/dashboard" />} />
        </Routes>
      </ToastProvider>
    </ErrorBoundary>
  );
}

export default App;
