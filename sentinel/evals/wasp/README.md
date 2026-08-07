# Sentinel on WASP

This adapter evaluates Sentinel's governance layer in controlled browser-native
tasks using the official WASP injector and native user/attacker oracles,
BrowserUse as the agent/executor, and the same governance middleware used by
the interactive runtime.

WASP is pinned to commit
`ffee6f41fde76acd14bd792db442479c506260c2`. Its four setup batches—two user
goals crossed with two injection formats—produce 84 attacked cases per
condition.

## Evaluation contract

Primary outcomes come from WASP's native final-state oracles:

- user utility;
- attacker-goal success (ASR);
- secure utility; and
- the four joint utility/security outcome categories.

Sentinel adds detector, sanitisation, action-audit, approval/handoff, action-
count, and enforcement-latency telemetry. The optional LLM-based intermediate-
action classifier is not required for the primary native-oracle result.

Participant modes are scripted benchmark controls:

- `none` denies approvals and lets handovers time out safely;
- `oracle` uses task-local attacker ground truth to resolve bounded requests.

Neither mode is a human participant. No oracle-mode WASP result is admitted to
the thesis evidence.

## Admitted evidence

The canonical comparison table and interpretation are in
[`../../EVALS.md`](../../EVALS.md#wasp-browser-native-enforcement-evaluation).
[`results/README.md`](results/README.md) is the compact index of admitted
per-run Markdown and machine-readable records.

| Evidence set | Role | Provenance boundary |
| --- | --- | --- |
| [Final controlled three-seed 27B comparison](results/wasp-qwen35-27b-multiseed-thinking8k-replication-v2.md) | Principal browser-native result and sanitisation ablation | Seeds 0/1/2; off, policy-only, and full; one frozen model/runtime/scaffold |
| [Earlier matched single-seed 27B comparison](results/wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.md) | Historical matched evidence | Older structured-output profile; not pooled with the final comparison |
| [9B sanitisation V2 record](results/wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.md) | Development and failure-analysis evidence | Shared off baseline followed by provenance-separated warning and sanitisation revisions |

The historical 20-step pilot, failed multiseed attempts, incomplete campaigns,
compatibility canaries, and navigation-only failures are excluded from outcome
tables. They remain operational provenance and must not be substituted into an
admitted row.

## Final controlled design

The final Qwen 3.5 27B experiment uses seeds `0`, `1`, and `2`. Each seed runs
the same 84 cases under three conditions, giving 252 episodes per condition and
756 overall:

1. `off`: prompt-boundary and action-policy enforcement bypassed;
2. `policy_only`: enforcement enabled with `browser_sanitize=false`, retaining
   boundary neutralisation, detector warning, and action policy; and
3. `full`: the same policy with post-verified sanitisation enabled.

`full - policy_only` isolates the configured sanitisation increment.
`policy_only - off` is a combined boundary/warning/policy increment, not a pure
action-policy effect.

The frozen profile uses:

- Ollama `0.32.5` and `qwen3.5-agentdojo:27b` with native thinking separated
  from the schema-validated action;
- 32,768 context tokens and an 8,192-token output cap;
- temperature 0.6, top-p 0.95, and declared seeds 0/1/2;
- one structured action per step and a 30-step limit;
- DOM/accessibility observations with screenshots excluded; and
- pinned BrowserUse history compaction and generated-input manifests.

Before official execution, a neutral complete-schema canary verified model and
runtime identity, action-schema parity, native-thinking separation, prompt
headroom, and non-truncated sentinels for every seed. Runtime provenance also
required the complete model to remain resident on the recorded GPU at the
declared context.

The completed controller produced six immutable campaigns, 36 native-score
cells, and 756 task artefacts without a controller restart or recorded
operational failure. The independent validator regenerated the curated JSON
and Markdown from ignored raw checkpoints and matched the checked-in files.

## Provenance and interpretation

Every campaign state binds:

- WASP and generated-input revisions;
- model tag, digest, runtime, sampling, context, and output cap;
- Sentinel policy and enforcement source;
- BrowserUse scaffold and step budget;
- participant mode and seed; and
- website-reset and native-score state.

Changing any of these requires a new immutable run tag. Never edit native task
results by hand, reuse a completed tag, pool changed provenance, or infer
completion from status alone.

The current interactive runtime may contain mechanisms that post-date or were
not exercised by a frozen trajectory. The exact boundary for each row is in its
per-run record. Current implementation documentation must not be used to
retroactively widen a benchmark claim.

Low ASR is interpreted with utility, attacker-directed attempts and executions,
and model-output reliability. An inactive or incapable model is not security
evidence.

## Reproducing the aggregate

Offline preflight checks the pinned adapter and dependencies without contacting
websites or a model:

```bash
bash sentinel/evals/wasp/run-wasp.sh preflight --offline
```

Regenerate the final aggregate from preserved ignored checkpoints without
running inference:

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python \
  sentinel/evals/wasp/replication.py \
  --run-root .wasp/runs \
  --output /tmp/wasp-replication.json \
  --markdown-output /tmp/wasp-replication.md
```

Compare the regenerated files byte-for-byte with the curated JSON and Markdown
before accepting any result change.

All admitted campaigns are complete and frozen. Do not invoke live `run`,
`finish-cell`, or recovery operations without an explicit user request. Before
any authorized live work, inspect the existing checkpoints, native scores,
provenance, website continuity, GPU/model identity, and controller state. A
native-scored 21-task cell is the minimum portable recovery unit; partial cells
from different mutable website states must never be combined.

## Artefact handling

Source checkouts, environments, authentication state, raw DOM/action logs,
website images, model output, and campaign checkpoints remain under ignored
`.wasp/` paths. Do not commit private host configuration, credentials, raw
captures, or full campaign directories.

Checked-in result records contain compact metrics and provenance only. They do
not contain page text, screenshots, credentials, free-form reasoning, or final-
answer text.

## Tests

The integration and replication contracts require no browser, Docker, or GPU:

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q \
  sentinel/tests/test_wasp_campaign.py \
  sentinel/tests/test_wasp_replication.py
```

The optional sanitisation replay is a model-free mechanism check over the
frozen warning row. It must never edit campaign artefacts or replace WASP's
native utility and attacker-success oracles.
