import { useEffect, useState } from 'react';
import { api } from '../../shared/api';
import { Toast, useToast } from '../../shared/components/Toast';
import { useStore } from '../../shared/store';
import type { ModelConfig, Provider } from '../../shared/types';

const PROVIDERS: { id: Provider; label: string; keyName: string; suggestions: string[] }[] = [
  { id: 'gemini', label: 'Google Gemini', keyName: 'GEMINI_API_KEY', suggestions: ['gemini-3.1-flash-lite', 'gemini-3.1-flash'] },
  { id: 'groq', label: 'Groq', keyName: 'GROQ_API_KEY', suggestions: ['meta-llama/llama-4-scout-17b-16e-instruct', 'meta-llama/llama-4-maverick-17b-128e-instruct', 'llama-3.3-70b-versatile'] },
  { id: 'openai', label: 'OpenAI', keyName: 'OPENAI_API_KEY', suggestions: ['gpt-4o', 'gpt-4.1-mini'] },
  { id: 'anthropic', label: 'Anthropic', keyName: 'ANTHROPIC_API_KEY', suggestions: ['claude-sonnet-4-6', 'claude-haiku-4-5'] },
  { id: 'openrouter', label: 'OpenRouter', keyName: 'OPENROUTER_API_KEY', suggestions: [] },
];

function hasKey(value: ModelConfig, keys: Record<string, boolean>): boolean {
  const provider = PROVIDERS.find((p) => p.id === value.provider)!;
  return !!(keys[provider.keyName] || (value.provider === 'gemini' && keys['GOOGLE_API_KEY']));
}

function KeyChip({ value, keys }: { value: ModelConfig; keys: Record<string, boolean> }) {
  const present = hasKey(value, keys);
  return (
    <span className={`chip ${present ? 'allowed' : 'blocked'}`}>
      {present ? 'Key present' : 'Key missing'}
    </span>
  );
}

function ModelFields({
  value,
  onChange,
  idPrefix,
}: {
  value: ModelConfig;
  onChange: (next: ModelConfig) => void;
  idPrefix: string;
}) {
  const provider = PROVIDERS.find((p) => p.id === value.provider)!;
  const listId = `models-${idPrefix}`;

  return (
    <div className="form-grid">
        <label className="field">
          <span>Provider</span>
          <select
            value={value.provider}
            onChange={(e) => onChange({ ...value, provider: e.target.value as Provider })}
          >
            {PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Model</span>
          <input
            list={listId}
            value={value.model}
            onChange={(e) => onChange({ ...value, model: e.target.value })}
          />
          <datalist id={listId}>
            {provider.suggestions.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        </label>
        <label className="field">
          <span>Temperature (blank = provider default)</span>
          <input
            type="number"
            step="0.1"
            min="0"
            max="2"
            value={value.temperature ?? ''}
            onChange={(e) =>
              onChange({ ...value, temperature: e.target.value === '' ? null : Number(e.target.value) })
            }
          />
        </label>
        <label className="field checkbox">
          <span>Throttle (free-tier pacing)</span>
          <div className="check-row">
            <input
              type="checkbox"
              checked={value.throttle !== null}
              onChange={(e) =>
                onChange({
                  ...value,
                  throttle: e.target.checked ? { min_interval_s: 5, backoff_s: 30, max_retries: 2 } : null,
                })
              }
            />
            {value.throttle && (
              <div className="throttle-fields">
                <label>
                  every
                  <input
                    type="number"
                    step="0.5"
                    min="0"
                    value={value.throttle.min_interval_s}
                    onChange={(e) =>
                      onChange({ ...value, throttle: { ...value.throttle!, min_interval_s: Number(e.target.value) } })
                    }
                  />
                  s
                </label>
                <label>
                  backoff
                  <input
                    type="number"
                    min="0"
                    value={value.throttle.backoff_s}
                    onChange={(e) =>
                      onChange({ ...value, throttle: { ...value.throttle!, backoff_s: Number(e.target.value) } })
                    }
                  />
                  s
                </label>
              </div>
            )}
          </div>
        </label>
    </div>
  );
}

export function ModelsTab() {
  const config = useStore((s) => s.config);
  const setConfig = useStore((s) => s.setConfig);
  const [model, setModel] = useState<ModelConfig | null>(null);
  const [keys, setKeys] = useState<Record<string, boolean>>({});
  const [keyDrafts, setKeyDrafts] = useState<Record<string, string>>({});
  const [toast, showToast] = useToast();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (config && model === null) setModel(config.model);
  }, [config, model]);

  useEffect(() => {
    api.getKeys().then(setKeys).catch(() => {});
  }, []);

  if (!config || !model) return <div className="help-text">Loading…</div>;

  const dirty = JSON.stringify(model) !== JSON.stringify(config.model);

  const save = async () => {
    setSaving(true);
    try {
      const next = await api.putConfig({ model });
      setConfig(next);
      setModel(next.model);
      showToast({ text: 'Models saved', kind: 'ok' });
    } catch (e) {
      showToast({ text: e instanceof Error ? e.message : 'Save failed', kind: 'err' });
    } finally {
      setSaving(false);
    }
  };

  const saveKey = async (name: string) => {
    const value = keyDrafts[name]?.trim();
    if (!value) return;
    try {
      await api.putKey(name, value);
      setKeys({ ...keys, [name]: true });
      setKeyDrafts({ ...keyDrafts, [name]: '' });
      showToast({ text: `${name} saved to .env`, kind: 'ok' });
    } catch (e) {
      showToast({ text: e instanceof Error ? e.message : 'Key save failed', kind: 'err' });
    }
  };

  return (
    <div className="tab-body">
      <header className="tab-head">
        <div>
          <h1>Models</h1>
          <p>Which AI powers the agent. Changes apply to the next task.</p>
        </div>
        <button className="primary" disabled={!dirty || saving} onClick={save}>
          {dirty ? 'Save changes' : 'Saved'}
        </button>
      </header>

      <div className="card model-form rise">
        <div className="card-head">
          <h2 className="card-title">Primary model</h2>
          <KeyChip value={model} keys={keys} />
        </div>
        <ModelFields value={model} onChange={setModel} idPrefix="primary" />
      </div>

      <div className="card model-form rise">
        <div className="card-head">
          <div className="head-group">
            <h2 className="card-title">Fallback model</h2>
            {model.fallback && <KeyChip value={model.fallback} keys={keys} />}
          </div>
          <div className="check-row">
            <input
              type="checkbox"
              checked={model.fallback !== null}
              onChange={(e) =>
                setModel({
                  ...model,
                  fallback: e.target.checked
                    ? {
                        provider: 'groq',
                        model: 'meta-llama/llama-4-scout-17b-16e-instruct',
                        temperature: null,
                        throttle: { min_interval_s: 2, backoff_s: 30, max_retries: 2 },
                        fallback: null,
                      }
                    : null,
                })
              }
            />
            <span className="check-label">Switch automatically when the primary hits rate limits</span>
          </div>
        </div>
        {model.fallback && (
          <ModelFields
            value={model.fallback}
            onChange={(fb) => setModel({ ...model, fallback: fb })}
            idPrefix="fallback"
          />
        )}
      </div>

      <div className="card rise">
        <div className="card-head">
          <h2 className="card-title">API keys</h2>
          <span className="help-text">Stored in browser-use/.env - never shown back</span>
        </div>
        <div className="keys-grid">
          {PROVIDERS.map((p) => (
            <div key={p.keyName} className="key-row">
              <span className={`dot ${keys[p.keyName] ? 'running' : 'idle'}`} style={{ animation: 'none' }} />
              <span className="key-name">{p.keyName}</span>
              <input
                type="password"
                placeholder={keys[p.keyName] ? '••••••••  (set - paste to replace)' : 'Paste key…'}
                value={keyDrafts[p.keyName] ?? ''}
                onChange={(e) => setKeyDrafts({ ...keyDrafts, [p.keyName]: e.target.value })}
              />
              <button disabled={!keyDrafts[p.keyName]?.trim()} onClick={() => saveKey(p.keyName)}>
                Save
              </button>
            </div>
          ))}
        </div>
      </div>

      <Toast toast={toast} />
    </div>
  );
}
