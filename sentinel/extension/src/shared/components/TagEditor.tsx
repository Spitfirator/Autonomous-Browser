import { useState } from 'react';

export function TagEditor({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState('');

  const add = () => {
    const value = draft.trim().toLowerCase();
    if (value && !values.includes(value)) onChange([...values, value]);
    setDraft('');
  };

  return (
    <div className="tag-editor">
      {values.length > 0 && (
        <div className="tags">
          {values.map((v) => (
            <span key={v} className="tag">
              {v}
              <button title="Remove" onClick={() => onChange(values.filter((x) => x !== v))}>
                ×
              </button>
            </span>
          ))}
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
    </div>
  );
}
