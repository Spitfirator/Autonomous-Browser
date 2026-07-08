import { useEffect, useRef, useState } from 'react';
import { api } from '../shared/api';
import { ApprovalCard } from '../shared/components/ApprovalCard';
import { ChatThread } from '../shared/components/ChatThread';
import { HandoverCard } from '../shared/components/HandoverCard';
import {
  OverlayIcon,
  PauseIcon,
  PlayIcon,
  SendIcon,
  SettingsIcon,
  StopIcon,
} from '../shared/components/Icons';
import { OfflineBanner } from '../shared/components/OfflineBanner';
import { StatusBar } from '../shared/components/StatusBar';
import { useStore } from '../shared/store';

const hasChrome = typeof chrome !== 'undefined' && !!chrome.storage;

export function App() {
  const status = useStore((s) => s.status);
  const approvals = useStore((s) => s.approvals);
  const handovers = useStore((s) => s.handovers);
  const wsState = useStore((s) => s.wsState);

  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [visuals, setVisuals] = useState(true);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const agentStatus = status?.agent_status ?? 'idle';
  const running = agentStatus === 'running' || agentStatus === 'paused';
  const canSend = wsState === 'connected' && draft.trim().length > 0 && agentStatus !== 'stopping';

  useEffect(() => {
    if (!hasChrome) return;
    chrome.storage.local.get('inPageVisuals').then((d) => setVisuals(d.inPageVisuals !== false));
  }, []);

  const toggleVisuals = () => {
    const next = !visuals;
    setVisuals(next);
    if (hasChrome) chrome.storage.local.set({ inPageVisuals: next });
  };

  const sendMessage = async () => {
    if (!canSend || busy) return;
    setError(null);
    setBusy(true);
    try {
      await api.sendMessage(draft.trim());
      setDraft('');
      inputRef.current?.focus();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const control = async (command: 'pause' | 'resume' | 'stop') => {
    setError(null);
    try {
      await api.control(command);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const placeholder =
    agentStatus === 'running'
      ? 'Steer the agent — applied at its next thought…'
      : agentStatus === 'paused'
        ? 'Queue guidance for when it resumes…'
        : status?.task === null && wsState === 'connected'
          ? 'Give the agent a task…'
          : 'Give the agent a task or ask a follow-up…';

  return (
    <>
      <header className="panel-head">
        <div className="brand">
          <span className="mark" aria-hidden="true" />
          <span>Sentinel</span>
          <span className="sub">Agent chat</span>
        </div>
        <div className="head-actions">
          {running && (
            <>
              {agentStatus === 'paused' ? (
                <button
                  className="ghost icon-btn"
                  title="Resume the agent"
                  aria-label="Resume the agent"
                  onClick={() => control('resume')}
                >
                  <PlayIcon />
                </button>
              ) : (
                <button
                  className="ghost icon-btn"
                  title="Pause / take over"
                  aria-label="Pause / take over"
                  onClick={() => control('pause')}
                >
                  <PauseIcon />
                </button>
              )}
              <button
                className="ghost icon-btn stop-btn"
                title="Stop the task"
                aria-label="Stop the task"
                onClick={() => control('stop')}
              >
                <StopIcon />
              </button>
            </>
          )}
          <button
            className={`ghost icon-btn ${visuals ? '' : 'off'}`}
            title={visuals ? 'In-page control bar: on (turn off in your personal browser)' : 'In-page control bar: off'}
            aria-label="Toggle the in-page control bar"
            aria-pressed={visuals}
            onClick={toggleVisuals}
          >
            <OverlayIcon />
          </button>
          <button
            className="ghost icon-btn"
            title="Open dashboard (models & policies)"
            aria-label="Open dashboard"
            onClick={() => hasChrome && chrome.runtime.openOptionsPage()}
          >
            <SettingsIcon />
          </button>
        </div>
      </header>

      <main className="panel-main chat-main">
        <OfflineBanner />
        <ChatThread />
      </main>

      {(handovers.length > 0 || approvals.length > 0 || error) && (
        <section className="dock">
          {handovers.map((h) => (
            <HandoverCard key={h.handover_id} handover={h} />
          ))}
          {approvals.map((a) => (
            <ApprovalCard key={a.approval_id} approval={a} />
          ))}
          {error && <div className="hazard rise">{error}</div>}
        </section>
      )}

      <footer className="composer">
        <textarea
          ref={inputRef}
          rows={1}
          placeholder={placeholder}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              sendMessage();
            }
          }}
        />
        <button
          className="primary send-btn"
          disabled={!canSend || busy}
          onClick={sendMessage}
          title="Send (Enter)"
          aria-label={running ? 'Send' : 'Run task'}
        >
          {running ? <SendIcon /> : 'Run'}
        </button>
      </footer>

      <StatusBar />
    </>
  );
}
