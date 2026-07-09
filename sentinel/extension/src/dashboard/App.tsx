import { useState } from 'react';
import type { ReactNode } from 'react';
import { ActivityIcon, CpuIcon, ShieldIcon } from '../shared/components/Icons';
import { OfflineBanner } from '../shared/components/OfflineBanner';
import { useStore } from '../shared/store';
import { ActivityTab } from './tabs/ActivityTab';
import { ModelsTab } from './tabs/ModelsTab';
import { PoliciesTab } from './tabs/PoliciesTab';

type Tab = 'models' | 'policies' | 'activity';

const TABS: { id: Tab; label: string; icon: () => ReactNode }[] = [
  { id: 'models', label: 'Models', icon: CpuIcon },
  { id: 'policies', label: 'Policies', icon: ShieldIcon },
  { id: 'activity', label: 'Activity', icon: ActivityIcon },
];

export function App() {
  const [tab, setTab] = useState<Tab>('models');
  const status = useStore((s) => s.status);
  const wsState = useStore((s) => s.wsState);

  return (
    <div className="dash">
      <aside className="dash-nav">
        <div className="brand">
          <span className="mark" aria-hidden="true" />
          <span>Sentinel</span>
        </div>
        <div className="dash-sub">Control plane</div>
        <nav>
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`nav-item ${tab === t.id ? 'active' : ''}`}
              aria-current={tab === t.id ? 'page' : undefined}
              onClick={() => setTab(t.id)}
            >
              <t.icon />
              <span>{t.label}</span>
            </button>
          ))}
        </nav>
        <div className="dash-foot">
          <span className={`dot ${wsState !== 'connected' ? 'offline' : (status?.agent_status ?? 'idle')}`} />
          {wsState === 'connected'
            ? `Backend connected · agent ${status?.agent_status ?? '-'}`
            : 'Backend offline'}
        </div>
      </aside>

      <main className="dash-main">
        <OfflineBanner />
        {tab === 'models' && <ModelsTab />}
        {tab === 'policies' && <PoliciesTab />}
        {tab === 'activity' && <ActivityTab />}
      </main>
    </div>
  );
}
