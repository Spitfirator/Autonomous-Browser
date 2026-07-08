import { useCallback, useEffect, useState } from 'react';
import { api } from '../../shared/api';
import { RefreshIcon } from '../../shared/components/Icons';
import { useStore } from '../../shared/store';
import type { HistoryRecord } from '../../shared/types';

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
      return { cls: 'info', label: record.status ?? '—' };
  }
}

export function ActivityTab() {
  const [records, setRecords] = useState<HistoryRecord[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const agentStatus = useStore((s) => s.status?.agent_status);

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
            <strong>—</strong>
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
                  <tr
                    key={r.run_id}
                    onClick={() => setExpanded(open ? null : r.run_id)}
                    style={{ cursor: 'pointer' }}
                  >
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
                      {open && (r.final_result || r.error) && (
                        <div className="row-detail">{r.final_result ?? r.error}</div>
                      )}
                    </td>
                    <td>
                      <span className={`chip ${chip.cls}`}>{chip.label}</span>
                    </td>
                    <td className="num-cell">{r.steps ?? '—'}</td>
                    <td className="num-cell">{r.llm_calls ?? '—'}</td>
                    <td className="num-cell">{(r.total_tokens ?? 0).toLocaleString()}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
