import { Fragment, useCallback, useEffect, useState } from 'react';
import { api } from '../../shared/api';
import { RefreshIcon } from '../../shared/components/Icons';
import { useStore } from '../../shared/store';
import type { DecisionRow, HistoryRecord } from '../../shared/types';
import { verdictStyle } from '../../shared/verdicts';
import { LogsPanel, type LogAnchor, type LogAnchorKind } from '../components/LogsPanel';

function statusChip(record: HistoryRecord): { cls: string; label: string } {
  switch (record.status) {
    case 'done':
      return { cls: 'allowed', label: 'Done' };
    case 'finished':
      return { cls: 'info', label: 'Finished' };
    case 'stopped':
      return { cls: 'approval_required', label: 'Stopped' };
    case 'budget_exceeded':
      return { cls: 'blocked', label: 'Budget' };
    case 'error':
      return { cls: 'blocked', label: 'Error' };
    default:
      return { cls: 'info', label: record.status ?? '-' };
  }
}

function fmtDur(s: number): string {
  if (s <= 0) return '0s';
  if (s < 1) return `${Math.round(s * 1000)}ms`;
  if (s < 60) return `${s < 10 ? s.toFixed(1) : Math.round(s)}s`;
  const m = Math.floor(s / 60);
  const sec = Math.round(s % 60);
  return sec ? `${m}m ${sec}s` : `${m}m`;
}

/** Baseline-vs-enforcement time split + decision breakdown for one run. */
function EnforcementPanel({
  record,
  onChipClick,
}: {
  record: HistoryRecord;
  onChipClick?: (kind: LogAnchorKind) => void;
}) {
  const enf = record.enforcement;
  if (!enf) return null;

  const total = record.duration_s ?? 0;
  const machineMs = enf.enforcement_ms_total ?? enf.decision_ms_total ?? 0;
  const approvalWait = enf.approval_wait_s ?? 0;
  const handoffWait = enf.handoff_wait_s ?? 0;
  const incidentWait = enf.incident_wait_s ?? 0;
  // Enforcement adds approval-gate waits, unresolved-observation review, and
  // policy-check time. Agent work and task-intrinsic handed-over steps
  // (logins/CAPTCHAs) remain baseline. This direct decomposition does not
  // capture block re-planning.
  const added = approvalWait + incidentWait + machineMs / 1000;
  const baseline = Math.max(0, total - added);
  const addPct = total > 0 ? Math.min(100, (added / total) * 100) : 0;
  const machineStr = machineMs < 1 ? `${machineMs.toFixed(2)}ms` : `${Math.round(machineMs)}ms`;

  const d = enf.decisions ?? {};
  const allowed = d.allowed ?? 0;
  const approvals = d.approval_required ?? 0;
  const handoffs = d.handoff_required ?? 0;
  const blocked = (d.blocked ?? 0) + (d.denied_by_human ?? 0); // deliberately stopped
  const timedOut = (d.denied_timeout ?? 0) + (d.handoff_timeout ?? 0); // nobody responded
  const interventions = enf.human_interventions ?? 0;

  // Non-zero chips deep-link into the run's log; zero chips stay inert.
  const chip = (count: number, kind: LogAnchorKind, cls: string, label: string, title?: string) =>
    count > 0 && onChipClick ? (
      <button className={`chip ${cls} chip-btn`} onClick={() => onChipClick(kind)} title={title ?? 'Show in log'}>
        {label}
      </button>
    ) : (
      <span className={`chip ${count > 0 ? cls : 'zero'}`} title={title}>
        {label}
      </span>
    );

  return (
    <div className="enf-panel">
      <div className="enf-head">
        <h4>Enforcement cost</h4>
        {record.policy_mode && <span className={`chip mode-${record.policy_mode}`}>{record.policy_mode}</span>}
      </div>

      {total > 0 ? (
        <>
          <div className="enf-bar" role="img" aria-label={`enforcement added ${Math.round(addPct)}% of the run`}>
            <span className="seg base" style={{ width: `${100 - addPct}%` }} />
            <span className="seg add" style={{ width: `${addPct}%` }} />
          </div>
          <div className="enf-legend">
            <span>
              <i className="key base" /> Without enforcement <b>{fmtDur(baseline)}</b>
            </span>
            <span>
              <i className="key add" /> Enforcement added <b>+{fmtDur(added)}</b>
            </span>
            <span className="enf-total">Total {fmtDur(total)}</span>
          </div>
        </>
      ) : (
        <div className="enf-overhead">
          <span className="enf-overhead-num">+{fmtDur(added)}</span>
          <span className="enf-overhead-pct">enforcement added</span>
        </div>
      )}

      <div className="enf-sub">
        {fmtDur(approvalWait)} on approval gates · {machineStr} policy checks
        {incidentWait > 0 && ` · ${fmtDur(incidentWait)} on security-incident review`}
        {handoffWait > 0 &&
          ` · ${fmtDur(handoffWait)} on handed-over steps (login/CAPTCHA — baseline, happens either way)`}
      </div>

      <div className="enf-decisions">
        {chip(allowed, 'allowed', 'allowed', `${allowed} allowed`)}
        {chip(approvals, 'approvals', 'approval_required', `${approvals} approval${approvals === 1 ? '' : 's'}`)}
        {chip(handoffs, 'handoffs', 'info', `${handoffs} handoff${handoffs === 1 ? '' : 's'}`)}
        {chip(blocked, 'blocked', 'blocked', `${blocked} blocked`)}
        {chip(
          timedOut,
          'timed_out',
          'unattended',
          `${timedOut} timed out`,
          'Approvals or handoffs that expired because no one responded',
        )}
        {chip(interventions, 'interventions', 'info', `${interventions} intervention${interventions === 1 ? '' : 's'}`)}
      </div>
    </div>
  );
}

/** Per-decision "could you tell why?" list with a yes/no tick (metric 6). */
function DecisionsPanel({ runId, onJump }: { runId: string; onJump?: (seq: number) => void }) {
  const [rows, setRows] = useState<DecisionRow[] | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .runDecisions(runId)
      .then((r) => alive && setRows(r))
      .catch(() => alive && setRows([]));
    return () => {
      alive = false;
    };
  }, [runId]);

  if (!rows || rows.length === 0) return null;

  const tick = (seq: number, value: boolean) => {
    const row = rows.find((r) => r.seq === seq);
    const next = row && row.understood === value ? null : value; // click the active one = clear
    setRows((cur) => (cur ? cur.map((r) => (r.seq === seq ? { ...r, understood: next } : r)) : cur));
    api.setUnderstood(runId, seq, next).catch(() => {});
  };

  return (
    <div className="dec-panel">
      <h4>Understood why each was blocked or paused?</h4>
      <div className="dec-list">
        {rows.map((r) => {
          const [label, cls] = verdictStyle(r.verdict);
          return (
            <div className="dec-row" key={r.seq}>
              <div className="dec-main">
                <span className={`chip ${cls}`}>
                  {label} · <span className="mono">{r.action}</span>
                </span>
                <span className="dec-reason">{r.reason}</span>
                {onJump && (
                  <button className="dec-jump" onClick={() => onJump(r.seq)}>
                    View in log ›
                  </button>
                )}
              </div>
              <div className="dec-tick">
                <button
                  className={`tick yes ${r.understood === true ? 'on' : ''}`}
                  onClick={() => tick(r.seq, true)}
                  aria-pressed={r.understood === true}
                >
                  Yes
                </button>
                <button
                  className={`tick no ${r.understood === false ? 'on' : ''}`}
                  onClick={() => tick(r.seq, false)}
                  aria-pressed={r.understood === false}
                >
                  No
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ActivityTab() {
  const [records, setRecords] = useState<HistoryRecord[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [logAnchor, setLogAnchor] = useState<LogAnchor | null>(null);
  const agentStatus = useStore((s) => s.status?.agent_status);

  const toggleExpanded = (runId: string, open: boolean) => {
    setExpanded(open ? null : runId);
    setLogAnchor(null); // anchors are meaningless across rows
  };

  const refresh = useCallback(() => {
    api.history(100).then(setRecords).catch(() => {});
  }, []);

  useEffect(refresh, [refresh]);
  useEffect(() => {
    if (agentStatus === 'idle') refresh(); // pick up the run that just ended
  }, [agentStatus, refresh]);

  const totals = records.reduce(
    (acc, r) => {
      acc.runs += 1;
      acc.tokens += r.total_tokens ?? 0;
      acc.calls += r.llm_calls ?? 0;
      for (const [m, t] of Object.entries(r.by_model ?? {})) acc.byModel[m] = (acc.byModel[m] ?? 0) + t;
      return acc;
    },
    { runs: 0, tokens: 0, calls: 0, byModel: {} as Record<string, number> },
  );

  return (
    <div className="tab-body">
      <header className="tab-head">
        <div>
          <h1>Activity</h1>
          <p>Every run, its outcome, and what it cost.</p>
        </div>
        <button onClick={refresh}>
          <RefreshIcon /> Refresh
        </button>
      </header>

      <div className="stat-strip rise">
        <div className="stat">
          <span className="stat-label">Runs</span>
          <strong>{totals.runs}</strong>
        </div>
        <div className="stat">
          <span className="stat-label">LLM calls</span>
          <strong>{totals.calls.toLocaleString()}</strong>
        </div>
        <div className="stat">
          <span className="stat-label">Total tokens</span>
          <strong>{totals.tokens.toLocaleString()}</strong>
        </div>
        <div className="stat">
          <span className="stat-label">Tokens by model</span>
          {Object.keys(totals.byModel).length === 0 ? (
            <strong>-</strong>
          ) : (
            <div className="by-model-list">
              {Object.entries(totals.byModel).map(([m, t]) => (
                <span key={m}>
                  {m}: <em>{t.toLocaleString()}</em>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card rise table-card">
        {records.length === 0 ? (
          <div className="feed-empty">
            <b>No runs yet</b>
            <p>Start a task from the side panel and it will show up here.</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Task</th>
                <th>Status</th>
                <th>Steps</th>
                <th>Calls</th>
                <th>Tokens</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => {
                const chip = statusChip(r);
                const open = expanded === r.run_id;
                return (
                  <Fragment key={r.run_id}>
                    <tr onClick={() => toggleExpanded(r.run_id, open)} style={{ cursor: 'pointer' }}>
                      <td className="num-cell nowrap">
                        {new Date(r.started_at * 1000).toLocaleString(undefined, {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </td>
                      <td className="task-cell">
                        {open ? r.task : r.task.length > 90 ? `${r.task.slice(0, 90)}…` : r.task}
                      </td>
                      <td>
                        <span className={`chip ${chip.cls}`}>{chip.label}</span>
                      </td>
                      <td className="num-cell">{r.steps ?? '-'}</td>
                      <td className="num-cell">{r.llm_calls ?? '-'}</td>
                      <td className="num-cell">{(r.total_tokens ?? 0).toLocaleString()}</td>
                    </tr>
                    {open && (
                      <tr className="detail-row">
                        <td colSpan={6}>
                          {(r.final_result || r.error) && <div className="row-detail">{r.final_result ?? r.error}</div>}
                          <EnforcementPanel
                            record={r}
                            onChipClick={(kind) => setLogAnchor({ kind, nonce: Date.now() })}
                          />
                          <DecisionsPanel
                            runId={r.run_id}
                            onJump={(seq) => setLogAnchor({ kind: 'seq', seq, nonce: Date.now() })}
                          />
                          <LogsPanel runId={r.run_id} anchor={logAnchor} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
