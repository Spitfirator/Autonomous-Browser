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
      showToast({ text: 'Policies saved - live immediately', kind: 'ok' });
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
          <p>Enforced by the middleware on every action - even mid-run.</p>
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
              ['shadow', 'Shadow', 'Log only - everything allowed'],
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
            <b>Keyword</b> (a bare word): blocks any host containing it. <code>amazon</code> matches
            amazon.com, www.amazon.co.uk, myamazonshop.net.
            <br />
            <b>Domain</b> (has a dot): that site and its subdomains only. <code>amazon.com</code>{' '}
            skips look-alikes.
            <br />
            Each entry shows how it reads as you type.
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
          <h2 className="card-title">Sensitive domains - hand off to human</h2>
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
          <h2 className="card-title">Prompt-injection defense</h2>
          <span className="help-text">
            Treats page, file and tool-result instructions as untrusted; detected attacks taint downstream actions
          </span>
        </div>
        <label className="check-row">
          <input
            type="checkbox"
            checked={policies.prompt_injection.enabled}
            onChange={(e) =>
              setPolicies({
                ...policies,
                prompt_injection: { ...policies.prompt_injection, enabled: e.target.checked },
              })
            }
          />
          <span className="check-label">Detect and contain indirect prompt injections</span>
        </label>
        <div className="budget-grid" style={{ marginTop: 12 }}>
          <label className="field">
            <span>Detection threshold (0–1)</span>
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              value={policies.prompt_injection.detection_threshold}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  prompt_injection: {
                    ...policies.prompt_injection,
                    detection_threshold: Number(e.target.value),
                  },
                })
              }
            />
          </label>
          <label className="field">
            <span>Protected-sink block threshold</span>
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              value={policies.prompt_injection.block_threshold}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  prompt_injection: {
                    ...policies.prompt_injection,
                    block_threshold: Number(e.target.value),
                  },
                })
              }
            />
          </label>
        </div>
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Sensitive-data flow control</h2>
          <span className="help-text">
            Blocks credentials, tokens, payment data and private keys from flowing to untrusted origins; audit payloads are redacted
          </span>
        </div>
        <label className="check-row">
          <input
            type="checkbox"
            checked={policies.data_flow.enabled}
            onChange={(e) =>
              setPolicies({ ...policies, data_flow: { ...policies.data_flow, enabled: e.target.checked } })
            }
          />
          <span className="check-label">Enforce source-to-sink data-flow rules</span>
        </label>
        <div className="field-block" style={{ marginTop: 12 }}>
          <span className="field-label">Origins trusted to receive sensitive values</span>
          <TagEditor
            explain
            values={policies.data_flow.trusted_domains}
            onChange={(v) => setPolicies({ ...policies, data_flow: { ...policies.data_flow, trusted_domains: v } })}
            placeholder="trusted for secrets: accounts.example.com…"
          />
        </div>
        <label className="field" style={{ marginTop: 12 }}>
          <span>Untrusted sensitive-data flow</span>
          <select
            value={policies.data_flow.sensitive_data_verdict}
            onChange={(e) =>
              setPolicies({
                ...policies,
                data_flow: {
                  ...policies.data_flow,
                  sensitive_data_verdict: e.target.value as 'block' | 'approve',
                },
              })
            }
          >
            <option value="block">Block</option>
            <option value="approve">Hold for approval</option>
          </select>
        </label>
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Fatigue-resistant approvals</h2>
          <span className="help-text">
            Prompts only above the risk threshold; an explicit “Allow similar” grant is origin/action/taint scoped, time-limited and use-limited
          </span>
        </div>
        <label className="check-row">
          <input
            type="checkbox"
            checked={policies.adaptive_approvals.enabled}
            onChange={(e) =>
              setPolicies({
                ...policies,
                adaptive_approvals: { ...policies.adaptive_approvals, enabled: e.target.checked },
              })
            }
          />
          <span className="check-label">Use risk-adaptive prompts and bounded consent reuse</span>
        </label>
        <div className="budget-grid" style={{ marginTop: 12 }}>
          <label className="field">
            <span>Approval risk threshold / 100</span>
            <input
              type="number"
              min="0"
              max="100"
              value={policies.adaptive_approvals.approval_risk_threshold}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  adaptive_approvals: {
                    ...policies.adaptive_approvals,
                    approval_risk_threshold: Number(e.target.value),
                  },
                })
              }
            />
          </label>
          <label className="field">
            <span>Similar grant TTL (s)</span>
            <input
              type="number"
              min="1"
              max="3600"
              value={policies.adaptive_approvals.grant_ttl_s}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  adaptive_approvals: {
                    ...policies.adaptive_approvals,
                    grant_ttl_s: Number(e.target.value),
                  },
                })
              }
            />
          </label>
          <label className="field">
            <span>Similar grant max uses</span>
            <input
              type="number"
              min="1"
              max="100"
              value={policies.adaptive_approvals.grant_max_uses}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  adaptive_approvals: {
                    ...policies.adaptive_approvals,
                    grant_max_uses: Number(e.target.value),
                  },
                })
              }
            />
          </label>
          <label className="field">
            <span>Max prompts / run</span>
            <input
              type="number"
              min="1"
              max="100"
              value={policies.adaptive_approvals.max_prompts_per_run}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  adaptive_approvals: {
                    ...policies.adaptive_approvals,
                    max_prompts_per_run: Number(e.target.value),
                  },
                })
              }
            />
          </label>
        </div>
        <label className="field" style={{ marginTop: 12 }}>
          <span>After prompt budget is exhausted</span>
          <select
            value={policies.adaptive_approvals.fatigue_strategy}
            onChange={(e) =>
              setPolicies({
                ...policies,
                adaptive_approvals: {
                  ...policies.adaptive_approvals,
                  fatigue_strategy: e.target.value as 'handoff' | 'block',
                },
              })
            }
          >
            <option value="handoff">One direct browser handoff</option>
            <option value="block">Block further held actions</option>
          </select>
        </label>
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">Audit retention</h2>
          <span className="help-text">
            Action events stay redacted. Visuals and free-form reasoning can contain private page data, so storing them on disk is opt-in.
          </span>
        </div>
        <label className="check-row">
          <input
            type="checkbox"
            checked={policies.audit.store_screenshots}
            onChange={(e) =>
              setPolicies({ ...policies, audit: { ...policies.audit, store_screenshots: e.target.checked } })
            }
          />
          <span className="check-label">Persist step screenshots in trace folders</span>
        </label>
        <label className="check-row" style={{ marginTop: 10 }}>
          <input
            type="checkbox"
            checked={policies.audit.store_model_reasoning}
            onChange={(e) =>
              setPolicies({ ...policies, audit: { ...policies.audit, store_model_reasoning: e.target.checked } })
            }
          />
          <span className="check-label">Persist model thinking and memory in event traces</span>
        </label>
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
