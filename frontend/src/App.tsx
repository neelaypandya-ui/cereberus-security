import { Component, ReactNode } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

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
            onClick={() => { localStorage.clear(); window.location.href = '/login'; }}
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

function App() {
  const token = localStorage.getItem('cereberus_token');

  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={token ? <Dashboard /> : <Navigate to="/login" />}
        />
        <Route path="*" element={<Navigate to={token ? '/dashboard' : '/login'} />} />
      </Routes>
    </ErrorBoundary>
  );
}

export default App;
