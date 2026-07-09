import { useEffect, useRef, useState } from 'react';
import { useStore } from '../store';
import { verdictStyle } from '../verdicts';
import type {
  ControlRequest,
  ControlReturned,
  EnforcementDecision,
  OperatorMessage,
  SentinelEvent,
  StepEvent,
  TaskDone,
  TaskError,
} from '../types';

function Avatar() {
  return <span className="mark chat-avatar" aria-hidden="true" />;
}

function UserBubble({ event }: { event: OperatorMessage }) {
  return (
    <div className={`msg-row user rise`}>
      <div className="bubble user-bubble">
        {event.kind === 'steer' && <span className="bubble-tag">Steering</span>}
        {event.text}
      </div>
    </div>
  );
}

function StepBubble({ event }: { event: StepEvent }) {
  const [zoomed, setZoomed] = useState(false);
  const text = event.next_goal || event.evaluation_previous_goal || 'Thinking about the next move…';
  return (
    <div className="msg-row agent rise">
      <Avatar />
      <div className="bubble agent-bubble">
        <div className="bubble-meta">
          <span className="num">Step {event.step}</span>
          <span className="bubble-url" title={event.url}>
            {event.title || event.url}
          </span>
        </div>
        <p>{text}</p>
        {event.actions.length > 0 && (
          <div className="step-actions">
            {event.actions.map((a, i) => (
              <span key={i} className="chip info" title={JSON.stringify(a.params).slice(0, 300)}>
                {a.name}
              </span>
            ))}
          </div>
        )}
        {event.screenshot_b64 && (
          <img
            className={`shot ${zoomed ? 'zoomed' : ''}`}
            style={zoomed ? { maxHeight: 'none' } : { maxHeight: 96, objectFit: 'cover', objectPosition: 'top' }}
            src={`data:image/png;base64,${event.screenshot_b64}`}
            alt={`step ${event.step}`}
            onClick={() => setZoomed((z) => !z)}
          />
        )}
      </div>
    </div>
  );
}

function ResultBubble({ event }: { event: TaskDone }) {
  return (
    <div className="msg-row agent rise">
      <Avatar />
      <div className="bubble agent-bubble result-bubble">
        <div className="done-head">
          <span className={`chip ${event.success ? 'allowed' : 'info'}`}>{event.success ? 'Done' : 'Finished'}</span>
          <span className="done-meta">
            {event.steps} steps · {event.duration_s}s
          </span>
        </div>
        {event.final_result && <p>{event.final_result}</p>}
        <span className="followup-hint">Ask a follow-up below - the browser stays where it is.</span>
      </div>
    </div>
  );
}

function SystemRow({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <div className="sys-row rise" title={title}>
      {children}
    </div>
  );
}

function renderEvent(e: SentinelEvent) {
  switch (e.type) {
    case 'user_message':
      return <UserBubble key={e.seq} event={e} />;
    case 'step':
      return <StepBubble key={e.seq} event={e} />;
    case 'task_done':
      return <ResultBubble key={e.seq} event={e} />;
    case 'task_error': {
      const ev = e as TaskError;
      const label = ev.kind === 'stopped' ? 'Stopped by you' : ev.kind === 'budget_exceeded' ? 'Stopped - LLM budget reached' : ev.error;
      return (
        <SystemRow key={e.seq}>
          <span className={`chip ${ev.kind === 'stopped' ? 'approval_required' : 'blocked'}`}>{label}</span>
        </SystemRow>
      );
    }
    case 'enforcement_decision': {
      const ev = e as EnforcementDecision;
      if (ev.verdict === 'allowed') return null;
      const [label, cls] = verdictStyle(ev.verdict);
      return (
        <SystemRow key={e.seq} title={ev.reason}>
          <span className={`chip ${cls}`}>
            {label} · <span className="mono">{ev.action}</span>
          </span>
          <span className="sys-rule">{ev.reason}</span>
        </SystemRow>
      );
    }
    case 'control_request': {
      const ev = e as ControlRequest;
      return (
        <SystemRow key={e.seq} title={ev.reason}>
          <span className="chip approval_required">Your turn · {ev.reason.slice(0, 60)}</span>
        </SystemRow>
      );
    }
    case 'control_returned': {
      const ev = e as ControlReturned;
      return (
        <SystemRow key={e.seq}>
          <span className={`chip ${ev.resolved_by === 'user' ? 'allowed' : 'blocked'}`}>
            {ev.resolved_by === 'user' ? 'Control returned to agent' : 'Takeover timed out'}
          </span>
          {ev.note && <span className="sys-rule">“{ev.note}”</span>}
        </SystemRow>
      );
    }
    default:
      return null;
  }
}

export function ChatThread() {
  const events = useStore((s) => s.events);
  const status = useStore((s) => s.status);
  const handoverActive = useStore((s) => s.handovers.length > 0);
  const endRef = useRef<HTMLDivElement>(null);
  const lastSeq = events.length > 0 ? events[events.length - 1].seq : 0;

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [lastSeq, status?.agent_status]);

  const items = events.map(renderEvent).filter(Boolean);
  const thinking = status?.agent_status === 'running' && !handoverActive;

  return (
    <div className="thread">
      {items.length === 0 ? (
        <div className="thread-empty">
          <span className="mark lg" aria-hidden="true" />
          <p>
            <b>Ready when you are.</b>
          </p>
          <p>
            Tell me what to do in this browser - I’ll narrate every step here, ask before anything
            sensitive, and hand you the keys when a login or personal detail comes up.
          </p>
        </div>
      ) : (
        items
      )}
      {thinking && (
        <div className="msg-row agent">
          <Avatar />
          <div className="bubble agent-bubble typing">
            <i />
            <i />
            <i />
          </div>
        </div>
      )}
      <div ref={endRef} />
    </div>
  );
}
