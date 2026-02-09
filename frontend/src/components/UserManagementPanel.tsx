import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { IntelCard } from './ui/IntelCard';

interface UserData {
  id: number;
  username: string;
  role: string;
  created_at: string;
  last_login: string | null;
  roles: Array<{ id: number; name: string }>;
}

interface RoleData {
  id: number;
  name: string;
  description: string;
  permissions: string[];
}

interface ApiKeyData {
  id: number;
  key_prefix: string;
  name: string;
  last_used: string | null;
  expires_at: string | null;
  created_at: string;
  revoked: boolean;
}

export function UserManagementPanel() {
  const [users, setUsers] = useState<UserData[]>([]);
  const [roles, setRoles] = useState<RoleData[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKeyData[]>([]);
  const [selectedUser, setSelectedUser] = useState<number | null>(null);
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [showGenKey, setShowGenKey] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('viewer');
  const [keyName, setKeyName] = useState('');
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [u, r, k] = await Promise.all([
        api.getUsers(),
        api.getRoles(),
        api.getApiKeys(),
      ]);
      setUsers(u as UserData[]);
      setRoles(r as RoleData[]);
      setApiKeys(k as ApiKeyData[]);
    } catch (err) { console.error('[CEREBERUS]', err); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const createUser = async () => {
    if (!newUsername || !newPassword) return;
    try {
      await api.createUser({ username: newUsername, password: newPassword, role: newRole });
      setShowCreateUser(false);
      setNewUsername('');
      setNewPassword('');
      load();
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const assignRole = async (userId: number, roleName: string) => {
    const role = roles.find(r => r.name === roleName);
    if (!role) return;
    try { await api.assignUserRole(userId, role.id); load(); } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const generateApiKey = async () => {
    if (!keyName) return;
    try {
      const result = await api.generateApiKey({ name: keyName }) as { key: string };
      setGeneratedKey(result.key);
      setShowGenKey(false);
      setKeyName('');
      load();
    } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const revokeApiKey = async (keyId: number) => {
    try { await api.revokeApiKey(keyId); load(); } catch (err) { console.error('[CEREBERUS]', err); }
  };

  const selected = users.find(u => u.id === selectedUser) || null;

  return (
    <IntelCard title="PERSONNEL" classification="TOP SECRET">
      <div style={{ display: 'flex', gap: '16px' }}>
        {/* Users List */}
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-muted)' }}>{users.length} OPERATORS</span>
            <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowCreateUser(!showCreateUser)}>+ ADD OPERATOR</button>
          </div>

          {showCreateUser && (
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '12px', borderRadius: '2px' }}>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                <input className="terminal-input" placeholder="Username..." value={newUsername} onChange={e => setNewUsername(e.target.value)} style={{ flex: 1, padding: '6px 8px', fontSize: '17px' }} />
                <input className="terminal-input" type="password" placeholder="Password..." value={newPassword} onChange={e => setNewPassword(e.target.value)} style={{ flex: 1, padding: '6px 8px', fontSize: '17px' }} />
                <select className="terminal-input" value={newRole} onChange={e => setNewRole(e.target.value)} style={{ padding: '6px 8px', fontSize: '17px' }}>
                  {roles.map(r => <option key={r.name} value={r.name}>{r.name.toUpperCase()}</option>)}
                </select>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={createUser}>CREATE</button>
                <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowCreateUser(false)}>CANCEL</button>
              </div>
            </div>
          )}

          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '17px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-default)' }}>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>USERNAME</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>ROLE</th>
                <th style={{ padding: '6px', textAlign: 'left', color: 'var(--text-muted)', fontSize: '15px' }}>LAST LOGIN</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} onClick={() => setSelectedUser(selectedUser === u.id ? null : u.id)}
                  style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', background: selectedUser === u.id ? 'rgba(0,229,255,0.05)' : 'transparent' }}>
                  <td style={{ padding: '6px', color: 'var(--text-primary)' }}>{u.username}</td>
                  <td style={{ padding: '6px' }}>
                    <span className="stamp-badge stamp-advisory" style={{ fontSize: '14px' }}>{u.role.toUpperCase()}</span>
                  </td>
                  <td style={{ padding: '6px', color: 'var(--text-muted)', fontSize: '16px' }}>
                    {u.last_login ? new Date(u.last_login).toLocaleString('en-US', { hour12: false }) : 'NEVER'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Selected User Detail */}
          {selected && (
            <div style={{ marginTop: '12px', background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', borderRadius: '2px' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
                OPERATOR: {selected.username}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', marginBottom: '8px' }}>ASSIGN ROLE:</div>
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {roles.map(r => (
                  <button key={r.name} className={`stamp-badge ${selected.role === r.name ? 'stamp-flash' : 'stamp-routine'}`}
                    style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => assignRole(selected.id, r.name)}>
                    {r.name.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* API Keys */}
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--text-muted)' }}>API KEYS</span>
            <button className="stamp-badge stamp-immediate" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowGenKey(!showGenKey)}>+ GENERATE KEY</button>
          </div>

          {showGenKey && (
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '12px', marginBottom: '12px', borderRadius: '2px' }}>
              <input className="terminal-input" placeholder="Key name..." value={keyName} onChange={e => setKeyName(e.target.value)} style={{ width: '100%', padding: '6px 8px', fontSize: '17px', marginBottom: '8px', boxSizing: 'border-box' }} />
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="stamp-badge stamp-flash" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={generateApiKey}>GENERATE</button>
                <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '15px' }} onClick={() => setShowGenKey(false)}>CANCEL</button>
              </div>
            </div>
          )}

          {generatedKey && (
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--status-online)', padding: '12px', marginBottom: '12px', borderRadius: '2px' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--status-online)', marginBottom: '4px' }}>KEY GENERATED — COPY NOW (shown once)</div>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: '17px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{generatedKey}</code>
              <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '14px', marginTop: '8px', display: 'block' }} onClick={() => setGeneratedKey(null)}>DISMISS</button>
            </div>
          )}

          {apiKeys.map(k => (
            <div key={k.id} style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)', padding: '8px 12px', marginBottom: '4px', borderRadius: '2px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '17px', color: k.revoked ? 'var(--text-muted)' : 'var(--text-primary)', textDecoration: k.revoked ? 'line-through' : 'none' }}>
                  {k.name} <span style={{ color: 'var(--text-muted)' }}>({k.key_prefix}...)</span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)' }}>
                  {k.last_used ? `Last used: ${new Date(k.last_used).toLocaleString('en-US', { hour12: false })}` : 'Never used'}
                </div>
              </div>
              {!k.revoked && (
                <button className="stamp-badge stamp-hostile" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={() => revokeApiKey(k.id)}>REVOKE</button>
              )}
            </div>
          ))}
        </div>
      </div>
    </IntelCard>
  );
}
