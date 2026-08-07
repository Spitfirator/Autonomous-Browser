# WASP evidence index

This directory contains Sentinel's curated WASP records. The canonical human-
readable result table and interpretation are in
[`../../../EVALS.md`](../../../EVALS.md#wasp-browser-native-enforcement-evaluation).
The Markdown and JSON files here preserve exact per-run values, validation, and
provenance without requiring the ignored raw campaign directories.

Raw checkpoints, native scores, browser state, and controller logs remain under
`.wasp/` and are not committed.

## Evaluation scope

WASP tests browser-native transfer through a BrowserUse agent operating the
official mutable GitLab and Reddit environments. The admitted conditions use:

- WASP commit `ffee6f41fde76acd14bd792db442479c506260c2`;
- BrowserUse commit `c8e6e8f0fe617564687895702c2338967293b309`;
- temperature 0.6, top-p 0.95, and a 30-step cap;
- one structured action per step, DOM/accessibility observations, and no
  screenshots; and
- scripted `participant=none`.

Primary outcomes are WASP's native final-state utility and attacker-goal
oracles. Sentinel's attacker-directed attempts and executions are deterministic
replays of recorded governance events against instantiated attacker ground
truth.

## Admitted records

| Record | Role | Machine-readable source |
| --- | --- | --- |
| [Final controlled three-seed 27B comparison](wasp-qwen35-27b-multiseed-thinking8k-replication-v2.md) | Principal browser-native comparison and sanitisation ablation | [JSON](wasp-qwen35-27b-multiseed-thinking8k-replication-v2.json) |
| [Earlier matched single-seed 27B comparison](wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.md) | Historical matched evidence | [JSON](wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.json) |
| [9B sanitisation V2 record](wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.md) | Development and failure-analysis evidence | [JSON](wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.json) |

The final experiment runs the same 84 attacked cases for seeds 0, 1, and 2
under `off`, `policy_only`, and `full`, giving 252 episodes per condition.
`full - policy_only` isolates the configured sanitisation increment.
`policy_only - off` is a combined boundary-neutralisation, detector-warning,
and action-policy increment—not a pure action-policy effect.

The historical 9B rows share one off baseline followed by changed warning and
sanitisation revisions. The earlier 27B record is a separate matched seed-0
campaign. Neither contributes to the final denominators.

## Reading rules

- Use `EVALS.md` for thesis tables and aggregate interpretation.
- Use the per-run Markdown/JSON pair for exact values, seed counts, telemetry,
  run identities, validation gates, and hashes.
- Never pool changed policy, middleware, model settings, participant mode,
  scaffold, runtime, or benchmark inputs.
- A raw native positive is called terminal attacker success only when the
  independent action audit also records an executed attacker-directed action.
- Report utility, secure utility, native ASR, attacker-directed attempts and
  executions, interventions, and provenance together. Low ASR alone is not
  security evidence.
- Actual human intervention is N/A for `participant=none`; this benchmark
  condition is separate from the completeness of Sentinel's implemented
  authority workflow.

## Mechanism and implementation boundary

The per-run records preserve attributable removal, residual/unattributable
outcomes, warning behaviour, action auditing, latency, intervention telemetry,
and model-output reliability. These are mechanism explanations; primary
security and utility claims come from complete trajectories and WASP's native
oracles.

Frozen rows measure only their recorded enforcement source. Current interactive
code may contain later mechanisms or paths that an admitted trajectory did not
exercise. Do not use current documentation to widen a historical result.

The final comparison is the principal WASP evidence. Historical warning and
sanitisation revisions remain only where they explain why model-facing warning
was insufficient, why post-verification matters, or why provenance-separated
rows cannot be pooled.

## Exclusions

The historical 20-step pilot, failed earlier multiseed attempts, incomplete
campaigns, compatibility canaries, and navigation-only failures remain
preserved locally but are excluded from admitted outcome tables. They cannot
replace missing tasks or native scores in a completed row.
