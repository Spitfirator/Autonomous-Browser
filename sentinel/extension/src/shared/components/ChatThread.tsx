import { useEffect, useRef } from 'react';
import { useStore } from '../store';
import { verdictStyle } from '../verdicts';
import type {
  ControlRequest,
  ControlReturned,
  ConversationTurn,
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
  const text = event.next_goal || event.evaluation_previous_goal || 'Thinking about the next move…';
  return (
    <div className="msg-row agent rise">
      <Avatar />
      <div className="bubble agent-bubble">
        <div className="bubble-meta">
          <span className="num">Step {event.step}</span>
          <span className="bubble-url" title={event.url}>
            {event.url}
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

/** A restored turn from a past run in this chat (loaded on switch/reconnect). */
function TurnBubble({ turn }: { turn: ConversationTurn }) {
  if (turn.role === 'user') {
    return (
      <div className="msg-row user">
        <div className="bubble user-bubble">
          {turn.kind === 'steer' && <span className="bubble-tag">Steering</span>}
          {turn.text}
        </div>
      </div>
    );
  }
  return (
    <div className="msg-row agent">
      <Avatar />
      <div className="bubble agent-bubble">
        {turn.kind === 'error' && <span className="chip blocked turn-chip">Did not finish</span>}
        <p>{turn.text}</p>
      </div>
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
    case 'prompt_injection_detected':
      if (e.action_taken === 'observation_quarantined') {
        return (
          <SystemRow key={e.seq} title={e.signals.join(', ')}>
            <span className="chip blocked">Suspicious page paused · {Math.round(e.score * 100)}%</span>
            <span className="sys-rule">
              The current page text and images were hidden from the AI pending your review.
            </span>
          </SystemRow>
        );
      }
      return (
        <SystemRow key={e.seq} title={e.signals.join(', ')}>
          <span className={`chip ${e.action_taken === 'model_sanitized' ? 'allowed' : 'blocked'}`}>
            {e.action_taken === 'model_sanitized' ? 'Suspicious instructions removed' : 'Prompt injection detected'} ·{' '}
            {Math.round(e.score * 100)}%
          </span>
          <span className="sys-rule">
            {e.action_taken === 'model_sanitized'
              ? 'The unsafe text and visual observation were kept out of this model call.'
              : 'Page instructions were treated as untrusted data; protected actions remain policy-gated.'}
          </span>
        </SystemRow>
      );
    case 'control_request': {
      const ev = e as ControlRequest;
      if (ev.kind === 'security_incident') {
        return (
          <SystemRow key={e.seq} title={ev.reason}>
            <span className="chip blocked">Security pause · your review is required</span>
          </SystemRow>
        );
      }
      return (
        <SystemRow key={e.seq} title={ev.reason}>
          <span className="chip approval_required">Your turn · {ev.reason.slice(0, 60)}</span>
        </SystemRow>
      );
    }
    case 'control_returned': {
      const ev = e as ControlReturned;
      if (ev.kind === 'security_incident') {
        const label =
          ev.resolved_by === 'user'
            ? 'Page will be checked again'
            : ev.resolved_by === 'cancelled'
              ? 'Security review cancelled — task stopped'
              : 'Security review timed out — task stopped';
        return (
          <SystemRow key={e.seq}>
            <span className={`chip ${ev.resolved_by === 'user' ? 'allowed' : 'blocked'}`}>{label}</span>
          </SystemRow>
        );
      }
      return (
        <SystemRow key={e.seq}>
          <span className={`chip ${ev.resolved_by === 'user' ? 'allowed' : 'blocked'}`}>
            {ev.resolved_by === 'user'
              ? 'Control returned to agent'
              : ev.resolved_by === 'cancelled'
                ? 'Takeover cancelled'
                : 'Takeover timed out'}
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
  const turns = useStore((s) => s.turns);
  const status = useStore((s) => s.status);
  const handoverActive = useStore((s) => s.handovers.length > 0);
  const endRef = useRef<HTMLDivElement>(null);
  const lastSeq = events.length > 0 ? events[events.length - 1].seq : 0;

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [lastSeq, status?.agent_status]);

  // Runs already present in the live feed render from events; drop their
  // restored turns so a reconnect doesn't show the same exchange twice.
  const liveRuns = new Set(events.map((e) => e.run_id).filter(Boolean));
  const shownTurns = turns.filter((t) => !t.run_id || !liveRuns.has(t.run_id));
  const items = events.map(renderEvent).filter(Boolean);
  const thinking = status?.agent_status === 'running' && !handoverActive;

  return (
    <div className="thread">
      {shownTurns.map((t, i) => (
        <TurnBubble key={`t-${i}`} turn={t} />
      ))}
      {shownTurns.length > 0 && items.length > 0 && (
        <div className="sys-row">
          <span className="thread-divider">earlier in this chat ↑</span>
        </div>
      )}
      {shownTurns.length === 0 && items.length === 0 ? (
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
