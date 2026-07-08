import { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import type { ControlRequest } from '../types';

export function HandoverCard({ handover }: { handover: ControlRequest }) {
  const removeHandover = useStore((s) => s.removeHandover);
  const [now, setNow] = useState(Date.now() / 1000);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const total = Math.max(handover.expires_at - handover.ts, 1);
  const left = Math.max(handover.expires_at - now, 0);
  const minutes = Math.floor(left / 60);
  const seconds = Math.ceil(left % 60);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 500);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (left <= 0) removeHandover(handover.handover_id);
  }, [left, handover.handover_id, removeHandover]);

  const giveBack = async () => {
    setBusy(true);
    try {
      await api.completeHandover(handover.handover_id, note.trim());
    } catch {
      /* already resolved elsewhere (e.g. the page overlay) — WS event cleans up */
    }
    removeHandover(handover.handover_id);
  };

  return (
    <div className="card handover rise">
      <div className="approval-head">
        <span className="chip approval_required">Your turn — agent is waiting</span>
        <span className="approval-timer">
          {minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`}
        </span>
      </div>
      <div className="approval-body">
        <span className="handover-reason">{handover.reason}</span>
        {handover.url && <span className="approval-url">{handover.url}</span>}
        <span className="handover-hint">
          Do it directly in the page, then hand control back (here or via the banner on the page).
        </span>
      </div>
      <div className="countdown">
        <i style={{ width: `${(left / total) * 100}%` }} />
      </div>
      <input
        placeholder="Optional note for the agent, e.g. “logged in, postcode is SW1A 1AA”"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !busy) giveBack();
        }}
      />
      <button className="primary" disabled={busy} onClick={giveBack}>
        Give control back to agent
      </button>
    </div>
  );
}
