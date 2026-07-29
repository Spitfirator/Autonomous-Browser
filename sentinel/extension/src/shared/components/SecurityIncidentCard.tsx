import { useEffect, useState } from 'react';
import { api } from '../api';
import type { ControlRequest } from '../types';

export function SecurityIncidentCard({ incident }: { incident: ControlRequest }) {
  const [now, setNow] = useState(Date.now() / 1000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const left = Math.max(incident.expires_at - now, 0);
  const minutes = Math.floor(left / 60);
  const seconds = Math.ceil(left % 60);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 500);
    return () => clearInterval(timer);
  }, []);

  const recheck = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.completeHandover(incident.handover_id, '');
      if (!result.resolved) throw new Error('Sentinel did not resolve the security pause. Try again or stop the task.');
      // Keep the incident visible until the backend emits ControlReturned.
      // That confirms the held prompt was discarded; BrowserUse then starts a
      // new step and captures the page again before another model call.
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <div className="card security-incident rise" role="alert" aria-live="assertive">
      <div className="incident-head">
        <span className="incident-mark" aria-hidden="true">
          !
        </span>
        <div>
          <span className="incident-kicker">Security pause</span>
          <h3>Sentinel needs you to check this page</h3>
        </div>
        <span className="incident-timer" aria-hidden="true">
          {left <= 0 ? 'Stopping…' : minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`}
        </span>
      </div>
      <p>
        Suspicious page instructions could not be safely removed. Sentinel hid the current page
        text and images from this model call. No action was taken from this withheld observation.
      </p>
      {incident.url && <span className="approval-url">{incident.url}</span>}
      <ol>
        <li>Review the page yourself and remove, close, or move past anything suspicious.</li>
        <li>Then ask Sentinel to inspect a fresh copy of the page.</li>
      </ol>
      <div className="incident-actions">
        <button className="primary" disabled={busy} onClick={recheck}>
          {busy ? 'Re-checking…' : 'I’ve checked it — re-check page'}
        </button>
        <button className="danger" onClick={() => api.control('stop')}>
          Stop task
        </button>
      </div>
      <span className="incident-note">
        This does not approve the hidden content. The AI will receive a new observation only.
      </span>
      {error && <div className="hazard">{error}</div>}
    </div>
  );
}
