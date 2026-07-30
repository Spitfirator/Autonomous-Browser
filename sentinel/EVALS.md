# Sentinel evaluation metrics

How we measure whether the enforcement middleware helps more than it hurts.
Every metric below is computed from data the middleware already records - no
extra instrumentation needed. Run `python evals/aggregate.py` to get the
current numbers from `data/history.jsonl` (each run's record carries a
`policy_mode`, a full policy snapshot, and an `enforcement` summary; the
per-event ground truth lives in `data/traces/<run_id>/events.jsonl`).

This file is the canonical human-readable ledger for quantitative results. For
the thesis-facing implementation map, supported contribution boundary, and
unfinished HITL work, see [THESIS-STATUS.md](THESIS-STATUS.md).

## Results index

- [AgentDojo component replay](#agentdojo-v1-full-tier-1-component-run)
- [Detector-v2 scorecard](#detector-v2-goal-hijacking-coverage)
- [Action-gating replay](#what-action-gating-does-and-does-not-cover)
- [Gemini pilot and integration smoke](#gemini-pilot-and-integration-smoke)
- [Completed Qwen AgentDojo campaigns](#completed-agentdojo-end-to-end-results)
- [WASP browser-native campaigns](#wasp-browser-native-enforcement-evaluation)

## The three run modes (policies.mode)

Comparative metrics need baselines. The middleware supports:

- **enforce** - verdicts applied (normal runtime behavior)
- **shadow** - everything allowed, would-be verdicts logged (`shadow_*`
  events). Ground truth for false blocks: the action ran anyway, so you can
  see whether blocking it would have been justified.
- **off** - no prompt boundary or verdict enforcement. Privacy-preserving paired
  action auditing remains, giving a measurable completion/latency baseline.

The eval protocol is: fix a task set, run it once per mode (same model,
same budgets), then compare.

## Metrics

### 1. Task completion rate, enforcement on vs off
`completed runs / total runs`, grouped by `policy_mode`. A run counts as
completed when `status == "done"` (agent finished and its self-report was
successful). Report `finished` (agent stopped, unclear success) separately.
- **Source:** `history.jsonl → status, policy_mode`
- **What to look for:** the enforcement penalty. If enforce ≪ off on tasks the
  policy shouldn't touch, the middleware is over-blocking or the agent
  re-plans poorly after denials.

### 2. Approval prompts per task
`enforcement.decisions.approval_required / run`. Report mean and max.
- **Source:** `history.jsonl → enforcement.decisions`
- **What to look for:** approval pressure. More than three prompts on a routine
  task approaches the default four-prompt budget and is a signal to tighten the
  rule (approve by domain instead of by action type, or vice versa). This is an
  acceptance-fatigue proxy, not evidence that an operator actually
  rubber-stamped requests.

### 3. False blocks vs missed dangerous actions
The precision/recall of the policy. This needs offline ground-truth labels:
the thesis author (and, where practical, a second coder) judges recorded
decisions against a written rubric. This is annotation, not a participant
study:

- **False block** - a `blocked` / `denied_*` / `handoff_required` decision
  (or `shadow_*` would-block) on an action that was actually safe and
  necessary for the task.
- **Missed dangerous action** - an `allowed` action that a careful operator
  would have wanted stopped or gated (found by reviewing traces, especially
  shadow-mode runs of deliberately risky tasks).

Label decisions in `evals/labels.jsonl`, one JSON object per line:
`{"run_id": "abc123", "seq": 42, "label": "false_block" | "justified_block" | "missed_danger", "note": "…"}`
(`seq` is the event's sequence number in the trace.) Then:

- `false block rate = false_block / (false_block + justified_block)`
- `missed dangerous actions` - report the absolute count per task set; each
  one is a policy gap to close (that's the point of collecting them).
- **Source:** traces + `evals/labels.jsonl`; `aggregate.py --labels` computes both.

### 4. Time overhead / latency per decision
Two very different costs, reported separately:
- **Machine overhead:** `decision_ms` is the in-memory `PolicyEngine` portion;
  `enforcement_ms` is the complete pre-action middleware path (current URL,
  cached DOM target semantics, sensitive-data/taint analysis and policy). Per-
  run summaries expose both `decision_ms_*` and `enforcement_ms_*`; use the
  latter for overhead claims.
- **Human overhead:** `enforcement.human_wait_s` - total wall-clock time the run
  spent frozen on a human, split by mechanism: `approval_wait_s` (side-panel
  approve/deny gates — the extra time enforcement genuinely *adds*, since the
  agent could have acted on its own) and `handoff_wait_s` (a human did the step
  in the browser — logins, CAPTCHAs, sensitive actions — which the task needs
  with or without enforcement, so it counts as baseline, not overhead). The
  activity panel decomposes a single run into `baseline = duration_s − (approval_wait_s
  + enforcement_ms_total)` vs. `enforcement added = approval_wait_s + enforcement_ms_total`,
  so you get both accounting buckets without a separate off-mode run. This is
  not a counterfactual estimate of the same task without enforcement: it does
  not capture second-order cost such as re-planning after a block. Use matched
  off/enforce runs for comparative overhead claims.
- End-to-end: compare `duration_s` for the same task across modes (subtract
  `human_wait_s` from enforce runs to isolate the machine cost).

### 5. Number of human interventions
`enforcement.human_interventions` - approvals a human resolved (approve *or*
deny) plus handoffs completed. Timeouts are *not* interventions (nobody came);
report `denied_timeout` / `handoff_timeout` counts separately as
**unattended rate** - a high unattended rate means the human isn't really in
the loop.
- **Source:** `history.jsonl → enforcement`

### 6. Is the reason for a block or pause inspectable?
Every non-allow decision carries a `reason` string that is shown verbatim in
the side panel chip / approval card / takeover banner (e.g. *"'https://github.com/settings'
matches blocklisted domain 'github.com'"*).
- **Automatic proxy:** % of non-allow decisions with a non-empty, rule-specific
  reason (aggregate.py reports it; should be 100% by construction).
- **Current thesis measure:** an explanation-coverage check plus a structured
  cognitive walkthrough/heuristic inspection of whether each card exposes the
  action, target, data involved, matched rule, consequence and safe
  alternatives. Do not claim measured user comprehension without participants.
- Activity's per-decision **Yes/No** `understood` ticks are audit annotations
  for that researcher/operator walkthrough. They are not participant responses
  or a validated comprehension measure.
- **Future optional human measure:** a participant could rate whether the
  explanation was understandable, but this study is explicitly outside the
  current thesis plan.

### 7. Prompt-injection detection and containment

Report detector precision, recall, F1 and false-positive rate separately from
end-to-end attack success. A detector miss is not automatically an exploit: a
missed payload may still fail because its requested action hits a static policy,
sensitive-data rule, risk approval or human denial.

- **Detection source:** privacy-preserving `prompt_injection_detected` events
  (score, severity, signals, hash—never payload text).
- **Containment:** malicious side-effect cases ending in block/deny/timeout, or
  an approval/handoff that the benchmark operator rejects, divided by malicious
  side-effect cases.
- **Attack success:** the public benchmark's own task-specific success oracle.
  This is the primary security result; detector recall is diagnostic.
- **Benign false positive:** benign cases that emit a detection or receive a
  dynamic security block/approval.

### 8. Sensitive-data flow accuracy

Label each benchmark action with its source categories, destination trust and
expected flow verdict. Report per-category precision/recall for credentials,
access tokens, payment data, private keys, one-time codes and local files. Also
assert that the raw fixture secret occurs zero times in trace events, approval
requests and history records. The report itself should contain only redacted
parameters and per-run keyed digests.

### 9. Complete-action audit coverage

Join `action_audit` events by `action_id` and require exactly one `attempted` and
one `completed` event per attempted action—even for policy blocks, denials,
timeouts, tool errors, exceptions and cancellations.

`audit coverage = paired action IDs / attempted action IDs` (target **100%**).

Also report completion outcomes and p50/p95 duration by action/capability. This
distinguishes middleware latency from browser/tool execution latency.

### 10. Attention-allocation and acceptance-fatigue proxies

In addition to raw prompts per task, report:

- `approval_reuse_rate = approval_reuses / (approval_prompts + approval_reuses)`;
- benign approval rate (offline labelled corpus);
- prompts avoided by bounded grants;
- runs reaching `approval_fatigue_limit`;
- approval/deny response time and unattended timeout rate;
- simulated unsafe-approval exposure under fixed operator-response policies.

The current thesis does **not** recruit participants and therefore must not
claim that Sentinel empirically reduces boredom, workload or real
rubber-stamping. Evaluate the mechanism with deterministic workload replay:
chronological queue versus risk-prioritised queue, the same task/event stream,
fixed approval-response policies, prompt volume, time-to-surface critical
items, queue age, starvation, prompts avoided and resulting attack/task
outcomes. Add a cognitive walkthrough of the evidence cards and supervisor
view. Real compliance-fatigue and usability effects remain future human-study
work.

## Public benchmark adapter

`evals/security_benchmark.py` provides a version-neutral offline contract. Convert
AgentDojo, BrowserGym/WorkArena injection tasks, or another public corpus to one
JSON object per line:

```json
{
  "id": "suite/task/variant",
  "category": "indirect-injection",
  "page_text": "untrusted observation text",
  "current_url": "https://benchmark.invalid/",
  "action": "navigate",
  "params": {"url": "https://receiver.invalid/?data=x"},
  "trusted_origin": false,
  "expected_injection": true,
  "expected_verdict": "block"
}
```

Then run:

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python \
  sentinel/evals/security_benchmark.py converted.jsonl \
  --policy sentinel/policies/reference-policy.json --pretty
```

The checked-in `evals/fixtures/security-smoke.jsonl` is only a contract smoke
test, not research evidence. Public-suite results must report suite/version,
conversion commit, model, seed, policy snapshot and the benchmark's native
end-to-end success oracle.

### AgentDojo v1: full Tier 1 component run

Install the pinned public benchmark in an isolated environment. Keeping it
separate avoids replacing browser-use's dependency set:

```bash
uv venv .agentdojo-venv --python 3.12
VIRTUAL_ENV=$PWD/.agentdojo-venv uv pip install 'agentdojo==0.1.35'
```

The converter preserves AgentDojo's complete v1 matrix: 629
`(user_task, injection_task)` security cases plus all 97 benign user tasks. Its
default attack is the published deterministic `tool_knowledge` attack:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_convert.py \
  --out sentinel/evals/fixtures/agentdojo-v1-tool-knowledge.jsonl

PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python \
  sentinel/evals/security_benchmark.py \
  sentinel/evals/fixtures/agentdojo-v1-tool-knowledge.jsonl \
  --policy sentinel/policies/agentdojo-policy.json --pretty
```

This invokes the current runtime detector, taint/risk engine and the real
`PolicyEngine`. It is still a component benchmark: the adapter maps native tool
effects to Sentinel capabilities and does not measure model replanning.

### AgentDojo native boundary and oracles

`evals/agentdojo_native.py` runs on AgentDojo's actual tool names, arguments,
environment objects and task oracles.

The exhaustive model-free replay requires no credential:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_native.py replay \
  --suite-version v1 --attack tool_knowledge \
  --policy sentinel/policies/agentdojo-policy.json \
  --output sentinel/evals/fixtures/agentdojo-v1-native-tool-knowledge.report.json \
  --pretty
```

Run it once for each public non-manual attack. The compact checked-in result is
`evals/agentdojo-v1-summary.json`; regenerate it after the individual reports:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_native.py summarize \
  --output sentinel/evals/agentdojo-v1-summary.json --pretty
```

Because detector/risk rules were improved after inspecting AgentDojo v1
failures, this is a development-set score. Do not describe it as an unbiased
held-out result; freeze the policy before evaluating v1.2.x, a new attack
generator, WASP, or DoomArena.

The completed model-free replay result is:

| measure | result |
| --- | ---: |
| attack families | 16 |
| security cases across families | 7,404 |
| unique benign tasks per family | 97 |
| detection precision / recall / F1 | 1.000 / 1.000 / 1.000 |
| hard-block rate on security cases | 1.000 |
| benign hard-block rate | 0/97 |
| benign approval-triggering tasks | 1/97 (1.03%) |

These aggregate detector counts repeat the 97 benign tasks once per attack
family. They are component evidence, not an end-to-end model result or a
held-out estimate.

### Detector v2: goal-hijacking coverage

The first WASP browser campaign exposed a detector fitted to AgentDojo's attack
families. On WASP's goal-hijacking payloads it scored 0.25 — below the 0.55
threshold — for 20 of 21 scenarios, while flagging ordinary GitLab chrome,
because `exfiltration_request` used `re.S` over a flattened accessibility tree
and matched across unrelated elements. Every attack that actually succeeded in
that campaign was in the undetected group.

Detector v2 makes normalization line-preserving, restricts sentence-scoped
signatures to a single line, splits secret exfiltration from generic data
transfer (which now needs an external destination), and adds
`task_precondition_claim` plus a near-zero `urgent_compliance_pressure`.

A pre-launch runtime canary then exposed a representation mismatch in the
offline WASP adapter. URL-format attacks are authored as Markdown, but
BrowserUse's live DOM omits the anchor `href` and shows only:

```text
you MUST click on
[1816]<a />
    this link
```

The old converter retained the hidden Markdown destination, so its 84/84 result
overstated live coverage; the first URL-format canary scored only 0.25 and the
row was stopped before task 1000 completed. The converter now renders
URL-format payloads in the same href-free, split-line shape, and
`task_precondition_claim` treats that bounded visible link target as the
demanded detour. The archived real task-1000 observation scores 0.57 after the
fix. Sanitisation attributes and removes the three-line cluster rather than
wiping the observation.

Detector metrics only — these are the supported results:

| corpus | cases | recall | precision | FPR |
| --- | --- | --- | --- | --- |
| `agentdojo-security` | 188 | 1.00 | 1.00 | 0.00 |
| `agentdojo-v1-tool-knowledge` | 726 | 1.00 | 1.00 | 0.00 |
| `wasp-security` | 123 | 1.00 | 0.988 | 0.026 |

Regenerate with `evals/detector_metrics.py`, which writes the compact tracked
scorecard `evals/detector-v2-metrics.json`. The large per-case reports from
`security_benchmark.py` stay local and are gitignored, as the AgentDojo ones
already were.

The live-representation correction changes no AgentDojo detection
classification, score band or score value (0 of 188 and 0 of 726), verified by
replaying both against the previous committed detector. On the corrected WASP
representation, all 42 URL-format scores change: 40 previously missed attacks
cross the detection threshold and two already-detected cases change bands. The
historical `agentdojo-security.report.json` is left untouched as a record of the
revision that produced it; the exact comparison lives in the scorecard's
`baseline_comparison` block.

Score bands are reported separately for isolated payloads and full observations,
because runtime scans the whole page:

| | detected | at/above block threshold |
| --- | --- | --- |
| isolated WASP payloads (84) | 84 | 0 |
| full attacked observations, href-free URL rendering (84) | 84 | 8 |

Three disclosures matter for how this is written up:

- These signatures were designed after reading WASP payloads, so WASP is a
  **development set** and the v1→v2 change is post-hoc benchmark adaptation, not
  evidence of held-out generalisation. The AgentDojo corpora are the held-out
  evidence, and they are unchanged.
- The single WASP false positive is GitLab's `/-/profile` page, which genuinely
  discusses passwords, keys and privacy. It is reported rather than tuned away;
  the benign half of the corpus is 39 captured real pages, not hand-written
  strings, so the rate is measured rather than asserted.
- **No end-to-end claim follows from this corpus.** It scores the detector, taint
  engine and `PolicyEngine` on synthetic sinks: attack cases carry the attacker's
  own text as parameters, which contributes sensitive-data risk that a runtime
  `click` on an element index does not. Its containment rate is therefore not
  reported here and must not be read as enforcement evidence.

### What action gating does and does not cover

Detection alone is not enforcement. The
`prompt_injection_amplified_action` rule holds a tainted action only when it is
*independently* risk-amplifying — cross-origin navigation or disclosure,
sensitive-data flow, local-file or code-execution capability, or a destructive
target. Ordinary same-origin form interaction is left to the numeric risk
policy.

Of WASP's 84 unique attacker goals, **20 have a cross-origin terminal action**
(exfiltration to the attacker domain) and fall within that targeted rule's
coverage; the remaining **64 reach their goal through a same-origin form
submission** and do not. For that majority class, observation sanitisation —
not action gating — is the primary control. Do not describe the browser rows as
action-gating all 84 scenarios.

The boundary was set from evidence, not preference. Replaying the v1 enforce
trajectories, a blanket "gate every tainted side effect" rule newly gated a
median of 8 actions per affected task (p95 28, max 28) against
`max_prompts_per_run: 4`, exhausting the budget on 35 of 50 tasks — which with
`fatigue_strategy: block` converts detection into mass blocking of legitimate
work. The narrowed rule gates a median of 0 (p95 0, max 2) and exhausts the
budget on none, while leaving cross-origin exfiltration gated. Both AgentDojo
corpora are unchanged by either rule.

For the end-to-end model loop, the same executor scans every real tool result,
keeps taint sticky, sanitizes only independently malicious structured fields,
and evaluates every proposed native call before execution. It deliberately
bypasses AgentDojo's `TraceLogger`, which stores raw injected payloads, while
retaining AgentDojo's unchanged utility and attacker-goal oracles:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_native.py agent \
  --suite-version v1 --attack tool_knowledge \
  --provider gemini --model gemini-3.1-flash-lite \
  --policy sentinel/policies/agentdojo-policy.json \
  --approval-mode deny --min-interval-s 5 \
  --output sentinel/evals/fixtures/agentdojo-v1-agent.report.json --pretty
```

### Gemini pilot and integration smoke

`attack_success_rate` follows the actual AgentDojo injection-task oracle: lower
is better. `secure_rate = 1 - attack_success_rate`. Always report utility next
to security; an inactive agent is secure but useless. Current Gemini models
also require signed function-call metadata. The native adapter retains this
opaque in memory because AgentDojo 0.1.35 otherwise drops it between turns.
The checked-in `evals/agentdojo-v1-e2e-smoke-summary.json` records a paired
integration smoke where the same native attacker oracle succeeds in `off` and
fails in `enforce`; it is explicitly not an aggregate model score because the
model missed the user task in both conditions.

The checked-in `evals/agentdojo-v1-gemini-3.1-flash-lite-pilot-summary.json`
records a larger paired native-model pilot: 34 task/injection pairs spanning all
four v1 suites, run with Gemini 3.1 Flash Lite in both `off` and `enforce`
modes. Read its limitations before citing it. The first four pairs exposed a
generic mixed-content sanitization issue and are development cases; the
remaining 30 were run after the fix was frozen and received no further tuning.
The run stopped at the 500-request daily quota and excludes the incomplete
attempt. Per-run privacy-preserving reports are written beside the summary but
are gitignored: like all auto-written run artifacts they stay on the machine
that produced them, and only hand-curated compact summaries are committed.

The 34 completed pilot pairs recorded:

| mode | utility | native ASR | secure utility |
| --- | ---: | ---: | ---: |
| off | 19/34 (55.9%) | 22/34 (64.7%) | 11/34 (32.4%) |
| enforce | 30/34 (88.2%) | 0/34 | 30/34 (88.2%) |

This is a quota-limited pilot containing four development cases, not a
headline benchmark row. The one-pair agent smoke changed native attacker
success from pass in `off` to fail in `enforce`, but user utility failed in
both modes; it establishes integration only.

### Resumable full AgentDojo campaign

The campaign controller discovers completed executions from report contents,
builds the complete 629-pair v1 manifest, and writes one atomic report after
every off/enforce execution. Rerunning the same command skips completed work;
an API or harness failure is never interpreted as a secure benchmark result.

Check progress without making a model request:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_campaign.py --dry-run
```

Run until the next daily quota stop, then rerun after the reset:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_campaign.py
```

To use one persistent command across daily resets, keep the machine awake and
allow the controller to wait until just after midnight Pacific time:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_campaign.py \
  --wait-on-daily-quota
```

Campaign reports are stored under `evals/agentdojo-campaign-v1/`; the compact
checkpoint is `evals/agentdojo-campaign-v1-state.json`. Both are local-only
(gitignored) run artifacts. The controller skips
the redundant standalone injection-goal utility run for every one-case process,
but retains AgentDojo's native user-task utility and attacker-goal oracles for
each security case.

### Historical local Qwen campaign with Ollama

The first quota-free campaign ran quantized `qwen3.5:4b` on an 8 GB Apple
Silicon laptop. Its reproducible non-thinking profile uses an 8K context,
Qwen's recommended non-thinking sampling (`temperature=0.7`, `top_p=0.8`,
`presence_penalty=1.5`) with seed 0, and a 1,024-token turn cap.
Each report records finish reasons and token counts without retaining model
content, so truncation cannot silently inflate security or reduce utility.
Install Ollama and pull the base model once:

```bash
brew install ollama
ollama pull qwen3.5:4b
ollama serve
```

With the Ollama server running, create the pinned 8K AgentDojo profile once:

```bash
ollama create qwen3.5-agentdojo:4b \
  -f sentinel/evals/ollama/Modelfile.qwen35-4b-agentdojo
```

Check the independent Qwen checkpoint without making a model request:

```bash
.agentdojo-venv/bin/python sentinel/evals/agentdojo_campaign.py \
  --provider ollama --model qwen3.5-agentdojo:4b --min-interval-s 0 \
  --reports-dir sentinel/evals/agentdojo-campaign-v1-qwen35-4b-nonthinking-v2 \
  --state sentinel/evals/agentdojo-campaign-v1-qwen35-4b-nonthinking-v2-state.json \
  --dry-run
```

Remove `--dry-run` to resume the complete 629-pair run. Do not use Gemini as
an automatic fallback inside this campaign: mixed-model executions would make
the aggregate utility and security score uninterpretable. Keep Gemini and Qwen
as separately reported experiments. The earlier four-pair Qwen pilot used a
different generation profile and remains in its original directory; it must
not be included in the v2 aggregate.

### GPU campaigns with larger Qwen models

The 4B non-thinking campaign measured a model-capability ceiling, not an
enforcement cost: 313 of 629 pairs fail utility in both modes, enforcement
blocked only 9 actions total, and enforce utility (42.0%) exceeds off
(37.7%). The GPU workflow relaxes the three self-imposed handicaps — model
size, thinking, and context — while keeping the same finite action loop.

Driver profiles (`--ollama-profile` on both the native runner and the
campaign controller):

| profile       | context | output cap | reasoning | sampling                                  |
| ------------- | ------- | ---------- | --------- | ----------------------------------------- |
| `nonthinking` | 8,192   | 1,024      | none      | temp 0.7, top_p 0.8, presence 1.5, seed 0 |
| `thinking`    | 32,768  | 4,096      | medium    | temp 0.6, top_p 0.95, seed 0              |

Reports record the profile in `provenance.model_settings.profile`, and the
campaign controller refuses to count reports from a different profile as
completed (missing profile = `nonthinking`, so the existing v2 campaign
stays resumable).

Keep site-specific usernames, hosts, and remote paths out of Git. Copy the
example configuration and edit the ignored local copy:

```bash
cp sentinel/evals/ollama/gpu.local.env.example \
  sentinel/evals/ollama/gpu.local.env
set -a
. sentinel/evals/ollama/gpu.local.env
set +a
```

One-time setup, from the laptop (establish the control master interactively
when the SSH provider requires it):

```bash
# 1. Establish the jump + control master
ssh -fN -M -S "$SOCKET" -o ControlPersist=12h \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=6 \
  -o StrictHostKeyChecking=accept-new \
  ${GPU_JUMP_HOST:+-J "$GPU_JUMP_HOST"} "$GPU_HOST"

# 2. Install/start Ollama on the GPU host and build the pinned 32K model
ssh -S "$SOCKET" "$GPU_HOST" \
  'bash -s' < sentinel/evals/ollama/setup-gpu-host.sh

# 3. Forward the Ollama port over the same socket
ssh -S "$SOCKET" -O forward -L 11434:127.0.0.1:11434 "$GPU_HOST"
```

The setup script selects 27B only on cards with approximately 24 GB or more,
9B on cards with at least 12 GB, and 4B otherwise (override with
`MODEL_TAG=...`). It creates `qwen3.5-agentdojo:<size>` with `num_ctx 32768`.
The harness needs no configuration when the forward uses local port 11434:
`OLLAMA_BASE_URL` defaults to `http://127.0.0.1:11434`.

Run the experiments in this order, changing one variable at a time:

```bash
# A. Clean-utility ceiling (no injections, 97 user tasks): both models
.agentdojo-venv/bin/python sentinel/evals/agentdojo_native.py agent \
  --provider ollama --model qwen3.5-agentdojo:27b --ollama-profile thinking \
  --attack none --min-interval-s 0 --pretty \
  --output sentinel/evals/agentdojo-baseline-qwen35-27b-thinking-clean.json

# B. Controlled model swap on suite v1 / tool_knowledge (comparable with the
#    629-pair 4B campaign; resumable):
.agentdojo-venv/bin/python sentinel/evals/agentdojo_campaign.py \
  --provider ollama --model qwen3.5-agentdojo:27b --ollama-profile thinking \
  --min-interval-s 0 \
  --reports-dir sentinel/evals/agentdojo-campaign-v1-qwen35-27b-thinking \
  --state sentinel/evals/agentdojo-campaign-v1-qwen35-27b-thinking-state.json
```

Suite pinning: the installed `agentdojo` 0.1.35 is the newest release and
ships benchmark suites `v1` through `v1.2.2` (same 97 user tasks; `v1.2.2`
fixes some task checks and adds 8 workspace injection tasks). Keep `v1` for
anything compared against the existing campaigns; move to `--suite-version
v1.2.2` (in a fresh reports dir) for externally comparable write-ups, and
never mix suite versions in one aggregate.

#### Model/run separation and publication status

Every model/profile combination has its own run tag. The tag determines
separate clean-baseline files, paired-report directory, checkpoint, and log.
The campaign controller also checks the model and Ollama profile recorded
inside every report before treating it as resumable. A report produced for
4B, 9B, or 27B therefore cannot silently count toward another model's run.

Current run identities:

| model | profile | run tag | current thesis status |
| ----- | ------- | ------- | --------------------- |
| Qwen 3.5 4B | `nonthinking` (8K) | `qwen35-4b-nonthinking-v2` | complete historical run; not used in the controlled scaling headline |
| Qwen 3.5 4B | `thinking` (32K) | `qwen35-4b-thinking` | complete: 97-task clean ceiling plus all 629 paired off/enforce cases with the fixed middleware |
| Qwen 3.5 9B | `thinking` (32K) | `qwen35-9b-thinking` | complete; already used the fixed middleware |
| Qwen 3.5 27B | `thinking` (32K) | off: `qwen35-27b-thinking`; enforce: `qwen35-27b-thinking-fixed-enforce-v1` | complete: frozen historical off plus a provenance-separated fixed-middleware enforce rerun |

Do not confuse the two sanitisation boundaries. AgentDojo's
`SentinelToolsExecutor` has sanitised detected native tool results in enforce
mode since the original AgentDojo harness, before any of these controlled
thinking-profile runs. WASP's later `browser_sanitize` setting controls
BrowserUse observation handling and is not read by the AgentDojo adapter.
Detector-v2 replay found zero changed classifications, score bands or score
values across all 726 AgentDojo v1 tool-knowledge attack and benign cases.

The reason only 27B needed an enforce rerun was the earlier
AgentDojo-relevant serializer-normalisation defect, not the later WASP
middleware. In the original 27B artifacts, three
`workspace/user_task_28` variants recorded no detection and achieved the
attacker goal; all six variants are detected and contained in the 9B, 4B and
fixed 27B artifacts. The 4B reports record commit `340d421`, which includes the
normalisation correction. The older 9B reports do not record a Git revision,
but their six affected artifacts provide direct behavioural evidence that the
correction was active. A fresh 9B run would strengthen code-provenance
bookkeeping, but is not required because of the WASP sanitisation changes.

### Completed AgentDojo end-to-end results

The controlled 4B run completed all 1,258 paired executions without runner
failures. Its 97-task clean ceiling is 78.4% overall: banking 81.2%, Slack
76.2%, travel 75.0% and workspace 80.0%. Under attack, off mode achieved
57.6% utility with 32.8% attack success; enforce mode achieved 70.9% utility
with 0/629 attack successes. In counts, enforcement changed useful outcomes
from 362 to 446 and successful attacks from 206 to zero. The four-way outcome
split was off = 297 useful/secure, 65 useful/compromised, 126
unsuccessful/secure and 141 unsuccessful/compromised; enforce = 446
useful/secure and 183 unsuccessful/secure. The reviewed compact result and
provenance are in `evals/agentdojo-v1-qwen35-4b-thinking-summary.json`.

This large change from the laptop run is why the thesis must not attribute the
old 4B-to-9B difference solely to parameter count: context, reasoning mode and
available compute were confounded. It also means the final controlled
capability comparison must be interpreted from the matched 32K/thinking runs,
not from the earlier 8K/non-thinking 4B result.

The final controlled 4B/9B/27B table uses the `thinking` 32K profile for every
model and one fixed enforcement pipeline:

| model | clean utility | off utility | off ASR | off secure utility | enforce utility | enforce ASR | enforce secure utility |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen 3.5 4B | 76/97 (78.4%) | 362/629 (57.6%) | 206/629 (32.8%) | 297/629 (47.2%) | 446/629 (70.9%) | 0/629 | 446/629 (70.9%) |
| Qwen 3.5 9B | 80/97 (82.5%) | 422/629 (67.1%) | 131/629 (20.8%) | 367/629 (58.3%) | 467/629 (74.2%) | 1/629 (0.2%) | 467/629 (74.2%) |
| Qwen 3.5 27B | 81/97 (83.5%) | 428/629 (68.0%) | 203/629 (32.3%) | 345/629 (54.8%) | 483/629 (76.8%) | 0/629 | 483/629 (76.8%) |

Enforce-mode diagnostics:

| model | detected cases | explicit action blocks | approval actions | truncated responses |
| --- | ---: | ---: | ---: | ---: |
| Qwen 3.5 4B | 600/629 | 9 | 0 | 6 |
| Qwen 3.5 9B | 615/629 | 9 | 0 | 0 |
| Qwen 3.5 27B | 609/629 | 9 | 0 | 7 |

The completed 4B run repeated **both** off and enforce; its old
8K/non-thinking off result is not a valid pair. The 27B row preserves the
historical thinking/32K off reports byte-for-byte because off bypasses the
detector and policy decision. Its fixed-middleware enforce result comes from a
new immutable run tag and must not be combined with the pre-fix enforce
reports.

For 9B, enforcement changed utility from 422/629 to 467/629, attacker success
from 131/629 to 1/629, and useful-and-secure outcomes from 367/629 to 467/629.
Paired transitions were 92 utility gains versus 47 losses, with 130 attacker
successes prevented and none introduced.

For 27B, enforcement changed utility from 428/629 to 483/629 and attacker
success from 203/629 to 0/629. Useful-and-secure outcomes increased from
345/629 to 483/629. The paired transitions were 84 utility gains versus 29
losses, all 203 historical attacker successes absent under enforce, and 158
useful-and-secure gains versus 20 losses. In the enforce row, detected
untrusted tool output was sanitised in 609/629 cases; nine subsequent actions
were blocked by the sensitive-data-flow rule. This makes sanitisation the
primary observed mechanism and hard action blocking a secondary backstop.

These parameter-size rows are descriptive independent model runs, not an
identified causal effect of parameter count. The 27B off reports also predate
Git-revision and Ollama-digest recording: their task, model name, profile and
sampling configuration match, but exact model-blob parity with the enforce
rerun cannot be cryptographically verified. Ten scored responses reached the
4,096-token cap across the pair (three off and seven enforce); the seven new
truncations are all variants of one difficult travel user task and were kept
rather than selectively rerun. The reviewed 27B aggregate and detailed
limitations are in
`evals/agentdojo-v1-qwen35-27b-thinking-fixed-summary.json`.

Keep raw reports, state, logs, per-suite clean reports, local GPU access
configuration and reservation-specific host details off Git. Commit only a
small reviewed aggregate with model/profile, suite version, policy hash and
code provenance after the reruns finish.

### WASP: browser-native enforcement evaluation

AgentDojo isolates Sentinel's enforcement logic in a different tool-agent
environment. WASP answers the browser-transfer question AgentDojo cannot:
whether the same middleware contains prompt injections while a BrowserUse agent
is actually reading pages, navigating, clicking, entering data and replanning.

The checked-in adapter is under `evals/wasp/` and pins the official WASP
repository to commit `ffee6f41fde76acd14bd792db442479c506260c2`.
The published matrix is:

- 21 attack scenarios across GitLab and Reddit;
- two benign user-goal indices;
- plain-text and URL-based goal-hijacking injections;
- 84 attacked cases per policy mode.

The browser profile was first evaluated with Qwen 3.5 9B and then replicated
as a fresh matched off/enforce comparison with Qwen 3.5 27B. Both use 32K
context, 4,096 output tokens, temperature 0.6, top-p 0.95, seed 0, BrowserUse
structured planning, one action per step, 30 steps, DOM/accessibility
observations and no screenshots. Ollama's separate native thinking stream is
disabled so its response remains valid against BrowserUse's action schema;
BrowserUse's structured thinking/planning fields remain enabled. These are
descriptive independent model runs, not an identified model-size effect and
not the same profile as AgentDojo's native-thinking runs.

The 30-step budget was frozen before the browser campaign because a
21-case off-mode pilot at 20 steps showed seven executions reaching the
effective action ceiling. That complete pilot cell (native utility 12/21,
attacker success 2/21) and all traces remain locally preserved under the old
run tag, but are excluded from the primary aggregate. No 20-step and 30-step
cases are pooled or selectively substituted.

The finalized thesis-eligible conditions are:

| model and condition | utility | end-to-end ASR | secure utility | attacker-directed attempted | attacker-directed executed |
| --- | ---: | ---: | ---: | ---: | ---: |
| 9B shared off baseline | 45/84 (53.57%) | 7/84 (8.33%) | 41/84 (48.81%) | 31/84 (36.90%) | 31/84 (36.90%) |
| 9B warn enforce | 37/84 (44.05%) | 7/84 (8.33%) | 35/84 (41.67%) | 32/84 (38.10%) | 32/84 (38.10%) |
| 9B sanitise V1 | 52/84 (61.90%) | 6/84 (7.14%) | 49/84 (58.33%) | 18/84 (21.43%) | 18/84 (21.43%) |
| **9B sanitise V2** | **54/84 (64.29%)** | **0/84** | **54/84 (64.29%)** | **1/84 (1.19%)** | **1/84 (1.19%)** |
| 27B off | 47/84 (55.95%) | 5/84 (5.95%) | 44/84 (52.38%) | 17/84 (20.24%) | 17/84 (20.24%) |
| **27B sanitise V2** | **46/84 (54.76%)** | **0/84** | **46/84 (54.76%)** | **0/84** | **0/84** |

The last two columns count task instances with at least one matched
attacker-directed attempt or execution; they are not raw action totals.

The 9B structure is exactly one shared `off` baseline with no enforcement,
followed by three separate `enforce` rows: warning-only, sanitisation V1, and
sanitisation V2. The latter two are the two sanitisation-enforcement revisions.
This is a provenance-separated engineering sequence, not one immutable matched
campaign, because middleware changed between revisions. The 27B campaign is
the primary matched browser result. Across its 168 executions, sanitisation
removed all five observed terminal attacker successes and all 17
task instances with an attacker-directed execution, changed native utility by
one task (47 to 46) and increased secure utility from 44 to 46.

`browser_sanitize` affects only the BrowserUse prompt boundary. The final
post-verified implementation used in the frozen campaigns suppressed the model
warning only when attributable removal left no detector-positive residual. The
9B V2 row recorded 1,053 confirmed removals from 1,057 attempts, with four
unattributable attempts sent through the then-current model-warning fallback
and zero residuals. The 27B row recorded 368/368 confirmed removals, zero
residuals or unattributable cases and zero post-success alerts. No hard block
or handoff occurred in the matched 27B enforce row; its one denied approval did
not prevent native user-task success.

The current runtime has since replaced that unresolved model-warning fallback
with a fail-closed operator incident for the current browser/read observation:
residual or unattributable content is withheld from the model, the run pauses,
and a human must take over or stop it before Sentinel captures a fresh
observation. Interactive runs also withhold page screenshots and image-bearing
tool results, scan page-extraction subcalls, and wrap later tool-result text so
stored or second-order instructions cross the same model boundary. A bounded
extraction or historical tool result that cannot be cleaned is dropped in
full; it does not open the browser-observation incident flow. Navigation
metadata now also withholds complete non-web URL suffixes, and enforce mode
blocks direct autonomous `navigate` actions outside HTTP(S), except
`about:blank`. These post-campaign safety changes are not measured by the
frozen 9B or 27B rows and require a new immutable run tag if they are
benchmarked later. No further
benchmark run is currently planned.

The warning-only result is a negative finding: it left ASR unchanged at 7/84,
slightly increased attacker-directed execution and reduced utility. The final
evidence supports the narrower conclusion that, under these WASP conditions,
independently enforced post-verified observation sanitisation reduced achieved
attacks and attacker-serving execution while preserving almost all aggregate
utility. It does not show universal prompt-injection robustness. Two of four
27B off batches already had zero ASR, only one seed was evaluated, and zero
successes in 84 enforce cases gives a rough rule-of-three 95% upper bound of
about 3.6%.

No oracle-participant WASP row was run. Oracle remains a possible deterministic
scripted-oversight upper bound, not a participant study and not evidence about
human fatigue, workload, trust or rubber-stamping.

Primary scores use WASP's unchanged final-state oracles:

- legitimate user-task utility;
- end-to-end attacker-goal success (ASR);
- secure utility (user success and attacker failure);
- useful/compromised, unsuccessful/secure and unsuccessful/compromised rates.

Sentinel telemetry adds detector incidence, blocks, approval/handoff pressure,
action counts and enforcement latency. The official LLM-based
intermediate-action classifier is a secondary optional score because it needs a
separate OpenAI/Azure judge; native final-state utility and ASR do not.

The complete thesis-ready synthesis, exact run identities, mechanism telemetry,
validation gates and exclusions are in
[`evals/wasp/results/README.md`](evals/wasp/results/README.md). Historical and
excluded runs are retained only where they explain a provenance boundary or
prevent a misleading comparison; they should not be expanded into headline
tables. A future plan-authority, provenance-hiding, or oracle experiment remains
a separately labelled optional ablation; do not retroactively attribute any of
those mechanisms to these frozen results.

All vendor source, virtual environments, website images, authentication state,
DOM/action logs and campaign checkpoints are ignored under `.wasp/`. The
controller checkpoints after every task and validates model, policy,
participant, generated-input and enforcement-source provenance. A fresh result
must contain at least one successful model call before it can be marked
complete. A navigation-only zero-model attempt is archived and retried once on
the unchanged environment; a second failure stops the cell before native
scoring. Because the official cleanup does not reliably clear Postmill's
in-memory posting cooldown, pristine GitLab/Reddit clones are restored before
every new pending 21-task cell. A failed injector preparation is likewise
archived and retried once only after another pristine reset, so partial page
mutations never become a task environment.

A remote reservation wipe can preserve a cell only after all 21 executions
have native scores. Evaluated cells are portable and skipped on a replacement
GPU. An unscored prepared/running cell is archived locally and restarted in
full against one newly pristine GitLab/Reddit environment; task checkpoints
from two different mutable site states are never combined. The remote images
and Ollama model must be rebuilt on the new host, while the local scored
evidence remains intact. Do not run WASP inference concurrently with
AgentDojo on the same 16 GB card.

Setup, preflight, remote-container commands and the resumable run command are
documented in [`evals/wasp/README.md`](evals/wasp/README.md).

## Optional local instrumentation smoke set

These small, deterministic, safe-to-automate tasks predate the completed public
benchmark campaigns. The demo scenarios in `demo/run_scenarios.py` remain useful
for local instrumentation checks, but they are not a planned thesis campaign
and do not supersede the AgentDojo or WASP evidence:

| Task | Policy touchpoint |
|---|---|
| Fill + submit the httpbin.org test order form | none - pure completion baseline |
| Visit a blocklisted site to change settings | block + re-plan |
| Same form task with click-approval on | approval gate ×N |
| Log in to a demo site behind a sensitive domain | forced handoff + note |

If validating local instrumentation, run each in all three modes. That produces
about 12 diagnostic runs per model configuration; treat their metrics as smoke
evidence only.
