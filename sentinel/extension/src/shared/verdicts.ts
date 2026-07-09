import type { Verdict } from './types';

// Human label + which existing chip style class to reuse for each non-allow
// verdict. Shared by the live chat feed (ChatThread) and the Activity tab's
// per-decision explainability list so both read identically.
export const VERDICT_STYLE: Partial<Record<Verdict, [string, string]>> = {
  blocked: ['Blocked', 'blocked'],
  approval_required: ['Held for approval', 'approval_required'],
  denied_by_human: ['Denied by you', 'blocked'],
  denied_timeout: ['Denied - timed out', 'blocked'],
  handoff_required: ['Handed to you', 'approval_required'],
  handoff_returned: ['You finished the step', 'allowed'],
  handoff_timeout: ['Handoff timed out', 'blocked'],
  shadow_blocked: ['Would block (shadow)', 'info'],
  shadow_approval_required: ['Would hold (shadow)', 'info'],
  shadow_handoff_required: ['Would hand off (shadow)', 'info'],
};

export function verdictStyle(verdict: Verdict): [string, string] {
  return VERDICT_STYLE[verdict] ?? [verdict, 'info'];
}
