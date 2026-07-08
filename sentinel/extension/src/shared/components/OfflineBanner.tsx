import { useStore } from '../store';

export function OfflineBanner() {
  const wsState = useStore((s) => s.wsState);
  if (wsState === 'connected') return null;
  return (
    <div className="hazard rise" role="status">
      <span className="dot offline" />
      {wsState === 'connecting'
        ? 'Connecting to backend…'
        : 'Backend offline — run ./start.sh in sentinel/'}
    </div>
  );
}
