import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';

interface Comment {
  id: number;
  target_type: string;
  target_id: number;
  user_id: number;
  username: string;
  content: string;
  created_at: string;
  updated_at: string | null;
}

interface CommentThreadProps {
  targetType: 'incident' | 'alert' | 'anomaly_event';
  targetId: number;
}

export function CommentThread({ targetType, targetId }: CommentThreadProps) {
  const [comments, setComments] = useState<Comment[]>([]);
  const [newComment, setNewComment] = useState('');

  const load = useCallback(async () => {
    try {
      const data = await api.getComments(targetType, targetId);
      setComments(data as Comment[]);
    } catch { /* */ }
  }, [targetType, targetId]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    if (!newComment.trim()) return;
    try {
      await api.addComment(targetType, targetId, newComment);
      setNewComment('');
      load();
    } catch { /* */ }
  };

  const handleDelete = async (id: number) => {
    try { await api.deleteComment(id); load(); } catch { /* */ }
  };

  return (
    <div style={{ marginTop: '8px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '6px' }}>
        COMMS ({comments.length})
      </div>

      {comments.map(c => (
        <div key={c.id} className="cable-feed-item" style={{ padding: '6px 8px', marginBottom: '4px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', color: 'var(--cyan-primary)', fontWeight: 600 }}>[{c.username}]</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', color: 'var(--text-muted)', marginLeft: '6px' }}>
                {new Date(c.created_at).toLocaleString('en-US', { hour12: false })}
              </span>
            </div>
            <button
              onClick={() => handleDelete(c.id)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '16px', padding: '0 4px' }}
            >
              x
            </button>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '17px', color: 'var(--text-primary)', marginTop: '2px' }}>{c.content}</div>
        </div>
      ))}

      <div style={{ display: 'flex', gap: '4px', marginTop: '6px' }}>
        <input
          className="terminal-input"
          placeholder="Add comment..."
          value={newComment}
          onChange={e => setNewComment(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
          style={{ flex: 1, padding: '4px 8px', fontSize: '16px' }}
        />
        <button className="stamp-badge stamp-routine" style={{ cursor: 'pointer', fontSize: '14px' }} onClick={handleAdd}>SEND</button>
      </div>
    </div>
  );
}
