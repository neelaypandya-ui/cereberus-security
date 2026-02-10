import { useState, useEffect, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  const utcStr = time.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' });
  const dateStr = time.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: '2-digit', timeZone: 'UTC' }).toUpperCase();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.login(username, password);
      if (data.must_change_password) {
        navigate('/change-password', { replace: true });
      } else {
        navigate('/dashboard', { replace: true });
      }
    } catch {
      setError('AUTHENTICATION FAILED — INVALID CREDENTIALS');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
      {/* Overlays */}
      <div className="scan-line-overlay" />
      <div className="hex-grid-overlay" />
      <div className="particle-bg" />

      {/* Classification Banner */}
      <div className="classification-banner" style={{ flexShrink: 0, position: 'relative', zIndex: 2 }}>
        TOP SECRET // SCI // CEREBERUS DEFENSE NETWORK // NOFORN
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1 }}>
        <div style={{ textAlign: 'center', width: '100%', maxWidth: '440px', padding: '0 24px' }}>

          {/* Logo with pulse ring */}
          <div className="logo-ring" style={{ display: 'inline-block', marginBottom: '16px' }}>
            <img
              src="/logo.jpg"
              alt="CEREBERUS"
              style={{ width: '100px', borderRadius: '50%', display: 'block' }}
            />
          </div>

          {/* Title */}
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '36px',
            fontWeight: 700,
            letterSpacing: '8px',
            color: 'var(--status-online)',
            marginBottom: '4px',
          }}>
            CEREBERUS
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '14px',
            letterSpacing: '4px',
            color: 'var(--text-muted)',
            marginBottom: '4px',
          }}>
            AI-POWERED CYBERSECURITY DEFENSE
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            letterSpacing: '3px',
            color: 'var(--text-muted)',
            marginBottom: '32px',
          }}>
            DEFENSE NETWORK
          </div>

          {/* Login Card — intel card style */}
          <div className="intel-card intel-accent-active" style={{
            padding: 0,
            position: 'relative',
            textAlign: 'left',
          }}>
            {/* Card header */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '8px 14px',
              borderBottom: '1px solid var(--border-default)',
              background: 'var(--bg-tertiary)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div className="status-dot-glow" style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  backgroundColor: 'var(--cyan-primary)', flexShrink: 0,
                }} />
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: '15px',
                  letterSpacing: '2px', color: 'var(--text-secondary)',
                }}>
                  AUTHENTICATION
                </span>
              </div>
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: '13px',
                letterSpacing: '1px', color: 'var(--red-primary)', opacity: 0.7,
              }}>
                RESTRICTED
              </span>
            </div>

            {/* Form content */}
            <div style={{ padding: '20px' }}>
              <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {/* Username */}
                <div>
                  <label style={{
                    fontFamily: 'var(--font-mono)', fontSize: '13px',
                    letterSpacing: '2px', color: 'var(--text-muted)',
                    display: 'block', marginBottom: '4px',
                  }}>
                    OPERATOR ID
                  </label>
                  <input
                    className="terminal-input"
                    type="text"
                    placeholder="Enter callsign..."
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    style={{
                      width: '100%',
                      padding: '10px 14px',
                      fontSize: '18px',
                      borderRadius: '2px',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>

                {/* Password */}
                <div>
                  <label style={{
                    fontFamily: 'var(--font-mono)', fontSize: '13px',
                    letterSpacing: '2px', color: 'var(--text-muted)',
                    display: 'block', marginBottom: '4px',
                  }}>
                    ACCESS CODE
                  </label>
                  <input
                    className="terminal-input"
                    type="password"
                    placeholder="Enter access code..."
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    style={{
                      width: '100%',
                      padding: '10px 14px',
                      fontSize: '18px',
                      borderRadius: '2px',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>

                {/* Error */}
                {error && (
                  <div style={{
                    padding: '8px 12px',
                    background: 'rgba(255,23,68,0.1)',
                    border: '1px solid var(--severity-critical)',
                    borderRadius: '2px',
                    color: 'var(--severity-critical)',
                    fontSize: '15px',
                    fontFamily: 'var(--font-mono)',
                    letterSpacing: '1px',
                  }}>
                    {error}
                  </div>
                )}

                {/* Submit */}
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    padding: '12px',
                    background: loading ? 'var(--bg-tertiary)' : 'rgba(0, 229, 255, 0.1)',
                    border: '1px solid var(--cyan-primary)',
                    borderRadius: '2px',
                    color: 'var(--cyan-primary)',
                    fontSize: '18px',
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    cursor: loading ? 'wait' : 'pointer',
                    letterSpacing: '3px',
                    textTransform: 'uppercase',
                    transition: 'all 0.2s ease',
                    marginTop: '4px',
                  }}
                >
                  {loading ? 'AUTHENTICATING...' : 'AUTHORIZE ACCESS'}
                </button>
              </form>
            </div>
          </div>

          {/* UTC Clock + Status */}
          <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'center', gap: '20px', alignItems: 'center' }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: '20px',
              fontWeight: 700, color: 'var(--cyan-primary)', letterSpacing: '2px',
            }}>
              {utcStr}
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: '14px',
              color: 'var(--text-muted)', letterSpacing: '1px',
            }}>
              UTC | {dateStr}
            </div>
          </div>

          <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <span className="stamp-badge stamp-cleared" style={{ fontSize: '12px' }}>SYSTEM ONLINE</span>
            <span className="stamp-badge stamp-routine" style={{ fontSize: '12px' }}>v1.6.0</span>
          </div>

          <div style={{
            marginTop: '16px', fontFamily: 'var(--font-mono)',
            fontSize: '13px', letterSpacing: '2px', color: 'var(--text-muted)',
          }}>
            CEREBERUS DEFENSE NETWORK
          </div>
        </div>
      </div>

      {/* Bottom classification banner */}
      <div className="classification-banner" style={{ flexShrink: 0, position: 'relative', zIndex: 2 }}>
        TOP SECRET // SCI // CEREBERUS DEFENSE NETWORK // NOFORN
      </div>
    </div>
  );
}

export default Login;
