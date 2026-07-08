import { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import type { ApprovalRequest } from '../types';

export function ApprovalCard({ approval }: { approval: ApprovalRequest }) {
  const removeApproval = useStore((s) => s.removeApproval);
  const [now, setNow] = useState(Date.now() / 1000);
  const [busy, setBusy] = useState(false);

  const total = Math.max(approval.expires_at - approval.ts, 1);
  const left = Math.max(approval.expires_at - now, 0);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 250);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (left <= 0) removeApproval(approval.approval_id);
  }, [left, approval.approval_id, removeApproval]);

  const decide = async (approve: boolean) => {
    setBusy(true);
    try {
      await api.resolveApproval(approval.approval_id, approve);
    } catch {
      /* resolved elsewhere or expired — the WS event will clean up */
    }
    removeApproval(approval.approval_id);
  };

  return (
    <div className="card approval rise">
      <div className="approval-head">
        <span className="chip approval_required">Approval required</span>
        <span className="approval-timer">{Math.ceil(left)}s</span>
      </div>
      <div className="approval-body">
        <span className="approval-action">{approval.action}</span>
        {approval.url && <span className="approval-url">{approval.url}</span>}
        {Object.keys(approval.params).length > 0 && (
          <code className="approval-params">{JSON.stringify(approval.params).slice(0, 200)}</code>
        )}
      </div>
      <div className="countdown">
        <i style={{ width: `${(left / total) * 100}%` }} />
      </div>
      <div className="approval-actions">
        <button className="primary" disabled={busy} onClick={() => decide(true)}>
          Approve
        </button>
        <button className="danger" disabled={busy} onClick={() => decide(false)}>
          Deny
        </button>
      </div>
    </div>
  );
}
