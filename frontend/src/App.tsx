import { Component, ReactNode, useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import { api } from './services/api';
import { setCsrfToken } from './services/api';

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
          <pre style={{ color: '#888', whiteSpace: 'pre-wrap', marginTop: '10px', fontSize: '12px' }}>
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
    api.getMe()
      .then(() => setStatus('authenticated'))
      .catch(() => setStatus('unauthenticated'));
  }, []);

  if (status === 'checking') return null;
  if (status === 'unauthenticated') return <Navigate to="/login" />;
  return <>{children}</>;
}

function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={<AuthGate><Dashboard /></AuthGate>}
        />
        <Route path="*" element={<Navigate to="/dashboard" />} />
      </Routes>
    </ErrorBoundary>
  );
}

export default App;
