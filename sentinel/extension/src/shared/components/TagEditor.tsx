import { useState } from 'react';

type EntryKind = 'keyword' | 'domain' | 'glob' | 'url';

// Mirrors the server matcher (server/governance/policy.py: entry_matches).
// Keep the two in sync - this is what the operator is shown, it must match
// what actually gets enforced.
export function classifyEntry(raw: string): { kind: EntryKind; scope: string } {
  const v = raw.trim().toLowerCase();
  if (v.includes('://')) return { kind: 'url', scope: `only ${v} - that exact origin` };
  if (v.includes('*')) return { kind: 'glob', scope: `hosts matching ${v}` };
  if (v.includes('.'))
    return { kind: 'domain', scope: `${v} and its subdomains (not look-alikes like not${v})` };
  return {
    kind: 'keyword',
    scope: `ANY host containing “${v}” - ${v}.com, www.${v}.com, ${v}.co.uk, my${v}shop.net…`,
  };
}

export function TagEditor({
  values,
  onChange,
  placeholder,
  explain = false,
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  explain?: boolean;
}) {
  const [draft, setDraft] = useState('');

  const add = () => {
    const value = draft.trim().toLowerCase();
    if (value && !values.includes(value)) onChange([...values, value]);
    setDraft('');
  };

  const draftClass = draft.trim() ? classifyEntry(draft) : null;

  return (
    <div className="tag-editor">
      {values.length > 0 && (
        <div className="tags">
          {values.map((v) => {
            const { kind } = classifyEntry(v);
            return (
              <span key={v} className="tag" title={classifyEntry(v).scope}>
                {explain && <span className={`tag-kind ${kind}`}>{kind}</span>}
                {v}
                <button title="Remove" onClick={() => onChange(values.filter((x) => x !== v))}>
                  ×
                </button>
              </span>
            );
          })}
        </div>
      )}
      <div className="tag-input">
        <input
          value={draft}
          placeholder={placeholder ?? 'example.com or *.example.com'}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
        />
        <button onClick={add} disabled={!draft.trim()}>
          Add
        </button>
      </div>
      {explain && draftClass && (
        <p className="tag-hint">
          <span className={`tag-kind ${draftClass.kind}`}>{draftClass.kind}</span>
          {draftClass.scope}
        </p>
      )}
    </div>
  );
}
