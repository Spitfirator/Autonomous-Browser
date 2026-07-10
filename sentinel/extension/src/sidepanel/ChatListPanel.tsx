import { useEffect, useState } from 'react';
import { api } from '../shared/api';
import { useStore } from '../shared/store';
import type { ConversationMeta } from '../shared/types';

function relTime(ts: number): string {
  const s = Date.now() / 1000 - ts;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** Slide-over list of past chats; clicking one makes it the active chat. */
export function ChatListPanel({ onClose }: { onClose: () => void }) {
  const [chats, setChats] = useState<ConversationMeta[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Chat awaiting a "stop current task and switch?" confirmation.
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const agentStatus = useStore((s) => s.status?.agent_status ?? 'idle');
  const currentId = useStore((s) => s.conversationId);

  useEffect(() => {
    let alive = true;
    api
      .conversations()
      .then((c) => alive && setChats(c))
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, []);

  const switchTo = async (id: string, force: boolean) => {
    setError(null);
    if (!force && agentStatus !== 'idle') {
      setConfirmId(id);
      return;
    }
    try {
      await api.activateConversation(id, force);
      const conv = await api.getConversation(id);
      useStore.getState().setConversation(id, conv.turns);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="chatlist rise">
      <div className="chatlist-head">
        <h4>Chats</h4>
        <button className="ghost chatlist-close" onClick={onClose} aria-label="Close chat list">
          ✕
        </button>
      </div>
      {error && <div className="hazard">{error}</div>}
      {!chats ? (
        <div className="chatlist-note">Loading…</div>
      ) : chats.length === 0 ? (
        <div className="chatlist-note">No chats yet — send a message to start one.</div>
      ) : (
        <div className="chatlist-items">
          {chats.map((c) => {
            const active = c.active || c.conversation_id === currentId;
            return (
              <div key={c.conversation_id}>
                <button
                  className={`chatlist-item ${active ? 'active' : ''}`}
                  onClick={() => switchTo(c.conversation_id, false)}
                  disabled={active}
                >
                  <span className="chatlist-title">{c.title}</span>
                  <span className="chatlist-meta">
                    {relTime(c.updated_at)} · {c.turn_count} turn{c.turn_count === 1 ? '' : 's'}
                    {active && <span className="chip allowed">current</span>}
                  </span>
                </button>
                {confirmId === c.conversation_id && (
                  <div className="chatlist-confirm">
                    <span>Stop the current task and switch?</span>
                    <button className="primary" onClick={() => switchTo(c.conversation_id, true)}>
                      Stop & switch
                    </button>
                    <button className="ghost" onClick={() => setConfirmId(null)}>
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
