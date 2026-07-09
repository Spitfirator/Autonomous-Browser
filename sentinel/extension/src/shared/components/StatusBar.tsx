import { useStore } from '../store';

export function StatusBar() {
  const status = useStore((s) => s.status);
  const wsState = useStore((s) => s.wsState);
  const awaitingHuman = useStore((s) => s.handovers.length > 0);

  const agentStatus =
    wsState !== 'connected' ? 'offline' : awaitingHuman ? 'paused' : (status?.agent_status ?? 'idle');
  const used = status?.calls_used ?? 0;
  const budget = status?.calls_budget ?? 0;
  const pct = budget > 0 ? Math.min((used / budget) * 100, 100) : 0;
  const stateWord = awaitingHuman
    ? 'Your turn'
    : agentStatus.charAt(0).toUpperCase() + agentStatus.slice(1);

  return (
    <footer className="statusbar">
      <span className={`dot ${agentStatus}`} />
      <span className="sb-state">{stateWord}</span>
      <span className="sb-model" title={`${status?.provider ?? ''} / ${status?.model ?? ''}`}>
        {status?.model ?? '-'}
      </span>
      <div className="sb-budget" title={`LLM calls: ${used}/${budget}`}>
        <span>
          {used}
          <em>/{budget}</em>
        </span>
        <div className={`meter ${pct > 85 ? 'hot' : ''}`}>
          <i style={{ width: `${pct}%` }} />
        </div>
      </div>
      <span className="sb-tokens" title="Total tokens this run">
        {(status?.total_tokens ?? 0).toLocaleString()} tok
      </span>
    </footer>
  );
}
