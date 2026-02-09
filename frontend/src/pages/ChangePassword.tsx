import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

function ChangePassword() {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('NEW PASSWORDS DO NOT MATCH');
      return;
    }

    setLoading(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      navigate('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'PASSWORD CHANGE FAILED');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
      <div className="scan-line-overlay" />
      <div className="hex-grid-overlay" />
      <div className="particle-bg" />

      <div className="classification-banner" style={{ flexShrink: 0, position: 'relative', zIndex: 2 }}>
        TOP SECRET // SCI // CEREBERUS DEFENSE NETWORK // NOFORN
      </div>

      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1 }}>
        <div style={{ textAlign: 'center', width: '100%', maxWidth: '440px', padding: '0 24px' }}>
          <div className="logo-ring" style={{ display: 'inline-block', marginBottom: '16px' }}>
            <img src="/logo.jpg" alt="CEREBERUS" style={{ width: '80px', borderRadius: '50%', display: 'block' }} />
          </div>

          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: '24px', fontWeight: 700,
            letterSpacing: '4px', color: 'var(--amber-primary)', marginBottom: '8px',
          }}>
            PASSWORD CHANGE REQUIRED
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: '13px', letterSpacing: '2px',
            color: 'var(--text-muted)', marginBottom: '24px',
          }}>
            DEFAULT CREDENTIALS DETECTED — UPDATE TO CONTINUE
          </div>

          <div className="intel-card intel-accent-active" style={{ padding: 0, textAlign: 'left' }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '8px 14px', borderBottom: '1px solid var(--border-default)',
              background: 'var(--bg-tertiary)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div className="status-dot-glow" style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  backgroundColor: 'var(--amber-primary)', flexShrink: 0,
                }} />
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: '15px',
                  letterSpacing: '2px', color: 'var(--text-secondary)',
                }}>
                  CREDENTIAL UPDATE
                </span>
              </div>
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: '13px',
                letterSpacing: '1px', color: 'var(--amber-primary)', opacity: 0.7,
              }}>
                MANDATORY
              </span>
            </div>

            <div style={{ padding: '20px' }}>
              <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <label style={{
                    fontFamily: 'var(--font-mono)', fontSize: '13px',
                    letterSpacing: '2px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px',
                  }}>
                    CURRENT ACCESS CODE
                  </label>
                  <input
                    className="terminal-input"
                    type="password"
                    placeholder="Enter current password..."
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    required
                    style={{ width: '100%', padding: '10px 14px', fontSize: '18px', borderRadius: '2px', boxSizing: 'border-box' }}
                  />
                </div>

                <div>
                  <label style={{
                    fontFamily: 'var(--font-mono)', fontSize: '13px',
                    letterSpacing: '2px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px',
                  }}>
                    NEW ACCESS CODE
                  </label>
                  <input
                    className="terminal-input"
                    type="password"
                    placeholder="Min 12 chars, upper/lower/digit/special..."
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    style={{ width: '100%', padding: '10px 14px', fontSize: '18px', borderRadius: '2px', boxSizing: 'border-box' }}
                  />
                </div>

                <div>
                  <label style={{
                    fontFamily: 'var(--font-mono)', fontSize: '13px',
                    letterSpacing: '2px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px',
                  }}>
                    CONFIRM NEW ACCESS CODE
                  </label>
                  <input
                    className="terminal-input"
                    type="password"
                    placeholder="Re-enter new password..."
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    style={{ width: '100%', padding: '10px 14px', fontSize: '18px', borderRadius: '2px', boxSizing: 'border-box' }}
                  />
                </div>

                {error && (
                  <div style={{
                    padding: '8px 12px', background: 'rgba(255,23,68,0.1)',
                    border: '1px solid var(--severity-critical)', borderRadius: '2px',
                    color: 'var(--severity-critical)', fontSize: '15px',
                    fontFamily: 'var(--font-mono)', letterSpacing: '1px',
                  }}>
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    padding: '12px', background: loading ? 'var(--bg-tertiary)' : 'rgba(255, 171, 0, 0.1)',
                    border: '1px solid var(--amber-primary)', borderRadius: '2px',
                    color: 'var(--amber-primary)', fontSize: '18px', fontWeight: 700,
                    fontFamily: 'var(--font-mono)', cursor: loading ? 'wait' : 'pointer',
                    letterSpacing: '3px', textTransform: 'uppercase', transition: 'all 0.2s ease', marginTop: '4px',
                  }}
                >
                  {loading ? 'UPDATING...' : 'UPDATE CREDENTIALS'}
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      <div className="classification-banner" style={{ flexShrink: 0, position: 'relative', zIndex: 2 }}>
        TOP SECRET // SCI // CEREBERUS DEFENSE NETWORK // NOFORN
      </div>
    </div>
  );
}

export default ChangePassword;
