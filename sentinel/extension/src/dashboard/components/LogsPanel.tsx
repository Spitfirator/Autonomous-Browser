import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { api } from '../../shared/api';
import type { SentinelEvent, TraceEventsResponse } from '../../shared/types';
import { verdictStyle } from '../../shared/verdicts';

// Where a chip/decision click should land inside the log. `nonce` re-triggers
// the scroll when the same target is clicked twice.
export type LogAnchorKind = 'allowed' | 'approvals' | 'handoffs' | 'blocked' | 'timed_out' | 'interventions';
export type LogAnchor =
  | { kind: LogAnchorKind; nonce: number }
  | { kind: 'seq'; seq: number; nonce: number };

// Mirrors how EnforcementPanel derives each chip from the enforcement summary,
// so a chip highlights exactly the events it was counted from.
function matchesAnchor(e: SentinelEvent, anchor: LogAnchor): boolean {
  switch (anchor.kind) {
    case 'seq':
      return e.seq === anchor.seq;
    case 'allowed':
      return e.type === 'enforcement_decision' && e.verdict === 'allowed';
    case 'approvals':
      return (
        (e.type === 'enforcement_decision' && e.verdict === 'approval_required') ||
        e.type === 'approval_request' ||
        e.type === 'approval_resolved'
      );
    case 'handoffs':
      return (
        (e.type === 'enforcement_decision' && e.verdict === 'handoff_required') ||
        e.type === 'control_request' ||
        e.type === 'control_returned'
      );
    case 'blocked':
      return e.type === 'enforcement_decision' && (e.verdict === 'blocked' || e.verdict === 'denied_by_human');
    case 'timed_out':
      return (
        (e.type === 'enforcement_decision' && (e.verdict === 'denied_timeout' || e.verdict === 'handoff_timeout')) ||
        (e.type === 'approval_resolved' && e.resolved_by === 'timeout') ||
        (e.type === 'control_returned' && e.resolved_by === 'timeout')
      );
    case 'interventions':
      return (
        (e.type === 'approval_resolved' && e.resolved_by === 'user') ||
        (e.type === 'control_returned' && e.resolved_by === 'user')
      );
  }
}

function cut(text: string | null | undefined, max = 120): string {
  if (!text) return '';
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function fmtOffset(s: number): string {
  if (s < 0) s = 0;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${String(Math.round(s % 60)).padStart(2, '0')}s`;
}

/** One-line body for a log row; verdict chips reuse the shared chip styles. */
function rowContent(e: SentinelEvent) {
  switch (e.type) {
    case 'user_message':
      return (
        <>
          <span className="log-type">{e.kind === 'steer' ? 'steer' : 'message'}</span>
          <span className="log-text">{cut(e.text)}</span>
        </>
      );
    case 'task_started':
      return (
        <>
          <span className="log-type">task</span>
          <span className="log-text">
            Started · {e.model} · max {e.max_steps} steps
          </span>
        </>
      );
    case 'step':
      return (
        <>
          <span className="log-type">step {e.step}</span>
          <span className="log-text">{cut(e.next_goal || e.title || e.url)}</span>
        </>
      );
    case 'llm_call':
      return (
        <>
          <span className="log-type">llm</span>
          <span className="log-text">
            {e.model} · {e.latency_ms}ms · {e.total_tokens ?? '-'} tok · call {e.calls_used}/{e.calls_budget}
            {e.is_fallback ? ' · fallback' : ''}
          </span>
        </>
      );
    case 'enforcement_decision': {
      const [label, cls] = e.verdict === 'allowed' ? ['Allowed', 'allowed'] : verdictStyle(e.verdict);
      return (
        <>
          <span className={`chip ${cls}`}>{label}</span>
          <span className="log-text">
            <span className="mono">{e.action}</span>
            {e.reason ? ` — ${cut(e.reason)}` : ''}
          </span>
        </>
      );
    }
    case 'approval_request':
      return (
        <>
          <span className="chip approval_required">Approval asked</span>
          <span className="log-text mono">{e.action}</span>
        </>
      );
    case 'approval_resolved':
      return (
        <>
          <span className={`chip ${e.approved ? 'allowed' : e.resolved_by === 'timeout' ? 'unattended' : 'blocked'}`}>
            {e.resolved_by === 'timeout' ? 'Approval timed out' : e.approved ? 'Approved by you' : 'Denied by you'}
          </span>
        </>
      );
    case 'control_request':
      return (
        <>
          <span className="chip approval_required">Handed to you</span>
          <span className="log-text">{cut(e.reason)}</span>
        </>
      );
    case 'control_returned':
      return (
        <>
          <span className={`chip ${e.resolved_by === 'timeout' ? 'unattended' : 'allowed'}`}>
            {e.resolved_by === 'timeout' ? 'Handoff timed out' : 'You handed back'}
          </span>
          {e.note && <span className="log-text">{cut(e.note)}</span>}
        </>
      );
    case 'action_executing':
      return (
        <>
          <span className="log-type">action</span>
          <span className="log-text mono">{e.action}</span>
        </>
      );
    case 'action_done':
      return (
        <>
          <span className="log-type">done</span>
          <span className="log-text mono">{e.action}</span>
        </>
      );
    case 'task_done':
      return (
        <>
          <span className={`chip ${e.success ? 'allowed' : 'info'}`}>{e.success ? 'Done' : 'Finished'}</span>
          <span className="log-text">{cut(e.final_result, 160)}</span>
        </>
      );
    case 'task_error':
      return (
        <>
          <span className="chip blocked">{e.kind === 'stopped' ? 'Stopped' : e.kind === 'budget_exceeded' ? 'Budget' : 'Error'}</span>
          <span className="log-text">{cut(e.error, 160)}</span>
        </>
      );
    default:
      return <span className="log-type">{e.type}</span>;
  }
}

/** Lazy-loaded event trace for one run; anchors scroll to + highlight rows. */
export function LogsPanel({ runId, anchor }: { runId: string; anchor: LogAnchor | null }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<TraceEventsResponse | null>(null);
  const [failed, setFailed] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (anchor) setOpen(true);
  }, [anchor]);

  useEffect(() => {
    if (!open || data || failed) return;
    let alive = true;
    api
      .runEvents(runId)
      .then((r) => alive && setData(r))
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, [open, data, failed, runId]);

  const matched = anchor && data ? new Set(data.events.filter((e) => matchesAnchor(e, anchor)).map((e) => e.seq)) : null;
  const firstMatch = anchor && data ? data.events.find((e) => matchesAnchor(e, anchor)) : undefined;
  const anchorMissed = !!anchor && !!data && data.events.length > 0 && !firstMatch;

  useLayoutEffect(() => {
    if (!open || !anchor || !data || !firstMatch) return;
    const target = scrollRef.current?.querySelector(`[data-seq="${firstMatch.seq}"]`);
    requestAnimationFrame(() => target?.scrollIntoView({ block: 'center', behavior: 'smooth' }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anchor?.nonce, data, open]);

  const t0 = data?.events[0]?.ts ?? 0;

  return (
    <div className="log-panel">
      <button className="log-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className={`log-caret ${open ? 'open' : ''}`}>›</span>
        <h4>Logs{data ? ` · ${data.total} events` : ''}</h4>
        {data?.truncated && open && (
          <span className="log-note">showing last {data.events.length} of {data.total}</span>
        )}
      </button>
      {open && (
        <>
          {anchorMissed && anchor && (
            <div className="log-note">
              {anchor.kind === 'seq' ? `Event #${anchor.seq} is not in the loaded log` : 'No matching events in the loaded log'}
            </div>
          )}
          {failed ? (
            <div className="log-note">Could not load the trace for this run</div>
          ) : !data ? (
            <div className="log-note">Loading…</div>
          ) : data.events.length === 0 ? (
            <div className="log-note">No trace for this run</div>
          ) : (
            <div className="log-scroll" ref={scrollRef}>
              {data.events.map((e) => {
                const isFirst = firstMatch?.seq === e.seq;
                return (
                  <div
                    key={isFirst && anchor ? `${e.seq}:${anchor.nonce}` : e.seq}
                    data-seq={e.seq}
                    className={`log-row ${matched?.has(e.seq) ? 'hl' : ''} ${isFirst ? 'flash' : ''}`}
                  >
                    <span className="log-seq">{e.seq}</span>
                    <span className="log-time">{fmtOffset(e.ts - t0)}</span>
                    {rowContent(e)}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}
