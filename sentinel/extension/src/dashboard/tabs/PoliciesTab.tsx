import { useEffect, useState } from 'react';
import { api } from '../../shared/api';
import { TagEditor } from '../../shared/components/TagEditor';
import { Toast, useToast } from '../../shared/components/Toast';
import { useStore } from '../../shared/store';
import type { Policies } from '../../shared/types';

function ActionChecklist({
  actions,
  selected,
  onChange,
}: {
  actions: string[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="action-grid">
      {actions.map((name) => {
        const checked = selected.includes(name);
        return (
          <label key={name} className={`action-check ${checked ? 'on' : ''}`}>
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) =>
                onChange(e.target.checked ? [...selected, name] : selected.filter((a) => a !== name))
              }
            />
            <span className="mono">{name}</span>
          </label>
        );
      })}
    </div>
  );
}

export function PoliciesTab() {
  const config = useStore((s) => s.config);
  const setConfig = useStore((s) => s.setConfig);
  const [policies, setPolicies] = useState<Policies | null>(null);
  const [actions, setActions] = useState<string[]>([]);
  const [toast, showToast] = useToast();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (config && policies === null) setPolicies(config.policies);
  }, [config, policies]);

  useEffect(() => {
    api.actions().then(setActions).catch(() => {});
  }, []);

  if (!config || !policies) return <div className="help-text">Loading…</div>;

  const dirty = JSON.stringify(policies) !== JSON.stringify(config.policies);

  const save = async () => {
    setSaving(true);
    try {
      const next = await api.putConfig({ policies });
      setConfig(next);
      setPolicies(next.policies);
      showToast({ text: 'Policies saved — live immediately', kind: 'ok' });
    } catch (e) {
      showToast({ text: e instanceof Error ? e.message : 'Save failed', kind: 'err' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="tab-body">
      <header className="tab-head">
        <div>
          <h1>Policies</h1>
          <p>Enforced by the middleware on every action — even mid-run.</p>
        </div>
        <button className="primary" disabled={!dirty || saving} onClick={save}>
          {dirty ? 'Save changes' : 'Saved'}
        </button>
      </header>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Domains</h2>
        </div>
        <div className="form-grid">
          <div className="field-block">
            <div className="check-row">
              <input
                type="checkbox"
                checked={policies.domain_allowlist !== null}
                onChange={(e) =>
                  setPolicies({ ...policies, domain_allowlist: e.target.checked ? [] : null })
                }
              />
              <span className="check-label">
                Restrict to an allowlist (unchecked = any site except the blocklist)
              </span>
            </div>
            {policies.domain_allowlist !== null && (
              <TagEditor
                values={policies.domain_allowlist}
                onChange={(v) => setPolicies({ ...policies, domain_allowlist: v })}
                placeholder="allow: example.com, *.wikipedia.org…"
              />
            )}
          </div>
          <div className="field-block">
            <span className="field-label">Blocklist</span>
            <TagEditor
              values={policies.domain_blocklist}
              onChange={(v) => setPolicies({ ...policies, domain_blocklist: v })}
              placeholder="block: facebook.com, *.bank.com…"
            />
          </div>
        </div>
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Blocked actions</h2>
          <span className="help-text">Removed from the model's toolbox and refused at runtime</span>
        </div>
        <ActionChecklist
          actions={actions}
          selected={policies.blocked_actions}
          onChange={(v) => setPolicies({ ...policies, blocked_actions: v })}
        />
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Require human approval</h2>
          <span className="help-text">The agent pauses in the side panel until you approve or deny</span>
        </div>
        <ActionChecklist
          actions={actions}
          selected={policies.approval_required_actions}
          onChange={(v) => setPolicies({ ...policies, approval_required_actions: v })}
        />
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Budgets</h2>
        </div>
        <div className="budget-grid">
          <label className="field">
            <span>Max steps / task</span>
            <input
              type="number"
              min="1"
              value={policies.budgets.max_steps}
              onChange={(e) =>
                setPolicies({ ...policies, budgets: { ...policies.budgets, max_steps: Number(e.target.value) } })
              }
            />
          </label>
          <label className="field">
            <span>Max LLM calls / task</span>
            <input
              type="number"
              min="1"
              value={policies.budgets.max_llm_calls}
              onChange={(e) =>
                setPolicies({ ...policies, budgets: { ...policies.budgets, max_llm_calls: Number(e.target.value) } })
              }
            />
          </label>
          <label className="field">
            <span>Approval timeout (s)</span>
            <input
              type="number"
              min="5"
              value={policies.budgets.approval_timeout_s}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  budgets: { ...policies.budgets, approval_timeout_s: Number(e.target.value) },
                })
              }
            />
          </label>
          <label className="field">
            <span>Takeover timeout (s)</span>
            <input
              type="number"
              min="30"
              value={policies.budgets.handover_timeout_s}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  budgets: { ...policies.budgets, handover_timeout_s: Number(e.target.value) },
                })
              }
            />
          </label>
        </div>
      </div>

      <Toast toast={toast} />
    </div>
  );
}
