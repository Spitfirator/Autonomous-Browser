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
          <h2 className="card-title">Enforcement mode</h2>
          <span className="help-text">Shadow logs would-be verdicts without enforcing; Off skips evaluation (eval baselines)</span>
        </div>
        <div className="action-grid">
          {(
            [
              ['enforce', 'Enforce', 'Verdicts are applied'],
              ['shadow', 'Shadow', 'Log only — everything allowed'],
              ['off', 'Off', 'No policy evaluation'],
            ] as const
          ).map(([value, label, hint]) => (
            <label key={value} className={`action-check ${policies.mode === value ? 'on' : ''}`} title={hint}>
              <input
                type="radio"
                name="policy-mode"
                checked={policies.mode === value}
                onChange={() => setPolicies({ ...policies, mode: value })}
              />
              <span className="mono">{label}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Domains</h2>
          <span className="help-text">
            A bare word is a <b>keyword</b> — blocks any host containing it (<code>amazon</code> →
            amazon.com, www.amazon.co.uk, myamazonshop.net). A word with a dot is a{' '}
            <b>domain</b> — that site and its subdomains only (<code>amazon.com</code> won't touch
            look-alikes). Each entry shows how it's read as you type.
          </span>
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
                explain
                values={policies.domain_allowlist}
                onChange={(v) => setPolicies({ ...policies, domain_allowlist: v })}
                placeholder="allow: example.com, *.wikipedia.org…"
              />
            )}
          </div>
          <div className="field-block">
            <span className="field-label">Blocklist</span>
            <TagEditor
              explain
              values={policies.domain_blocklist}
              onChange={(v) => setPolicies({ ...policies, domain_blocklist: v })}
              placeholder="block a word (facebook) or a domain (*.bank.com)…"
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
        <div className="field-block" style={{ marginTop: 12 }}>
          <span className="field-label">Approval-required domains (every action on these pages is held)</span>
          <TagEditor
            explain
            values={policies.approval_required_domains}
            onChange={(v) => setPolicies({ ...policies, approval_required_domains: v })}
            placeholder="hold: checkout.stripe.com, *.paypal.com…"
          />
        </div>
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Sensitive domains — hand off to human</h2>
          <span className="help-text">
            First touch of these domains freezes the agent and hands you the browser; after you hand
            back, the agent may continue there for the rest of the run
          </span>
        </div>
        <TagEditor
          explain
          values={policies.sensitive_domains}
          onChange={(v) => setPolicies({ ...policies, sensitive_domains: v })}
          placeholder="hand off: accounts.google.com, *.bank.com…"
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
