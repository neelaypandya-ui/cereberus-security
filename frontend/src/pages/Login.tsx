import { useState, FormEvent } from 'react';
import { api } from '../services/api';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.login(username, password);
      // JWT is now in httpOnly cookie, CSRF token in memory — no localStorage needed
      window.location.href = '/dashboard';
    } catch {
      setError('Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
      <div className="particle-bg" />

      <div style={{ position: 'relative', zIndex: 1, textAlign: 'center', width: '100%', maxWidth: '400px', padding: '0 20px' }}>
        {/* Logo */}
        <img
          src="/logo.jpg"
          alt="CEREBERUS"
          style={{ width: '320px', marginBottom: '48px', borderRadius: '8px', filter: 'drop-shadow(0 0 20px rgba(13, 26, 45, 0.6))' }}
        />

        {/* Login Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={{
              padding: '12px 16px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '20px',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{
              padding: '12px 16px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '20px',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
          />

          {error && (
            <div style={{ color: 'var(--red-primary)', fontSize: '19px', fontFamily: 'var(--font-mono)' }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '12px',
              background: loading ? 'var(--bg-tertiary)' : 'var(--red-dark)',
              border: '1px solid var(--red-primary)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '20px',
              fontWeight: 600,
              fontFamily: 'var(--font-sans)',
              cursor: loading ? 'wait' : 'pointer',
              letterSpacing: '2px',
              textTransform: 'uppercase',
              transition: 'all 0.2s ease',
            }}
          >
            {loading ? 'Authenticating...' : 'Enter'}
          </button>
        </form>

        <div style={{ marginTop: '32px', color: 'var(--text-muted)', fontSize: '17px', fontFamily: 'var(--font-mono)' }}>
          CEREBERUS v1.1.0 // AI-POWERED DEFENSE
        </div>
      </div>
    </div>
  );
}

export default Login;
