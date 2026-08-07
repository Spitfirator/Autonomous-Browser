# WASP thesis result synthesis

This page is the thesis-ready index and synthesis of Sentinel's finalized WASP
evidence. The per-run Markdown and JSON files in this directory remain the
authoritative provenance records. Raw checkpoints, native scores, browser state
and controller logs remain under the ignored `.wasp/` directory.

## Evaluation scope

WASP tests browser-native transfer through a BrowserUse agent operating the
official mutable GitLab and Reddit environments. Each policy mode contains
four batches of 21 attacked tasks: two benign user goals crossed with plain-text
and URL-based prompt injections, for 84 task instances per mode.

All rows use:

- WASP commit `ffee6f41fde76acd14bd792db442479c506260c2`;
- BrowserUse commit `c8e6e8f0fe617564687895702c2338967293b309`;
- temperature 0.6, top-p 0.95 and a 30-step cap;
- BrowserUse structured planning, one action per step, DOM/accessibility
  observations and no screenshots;
- participant mode `none`.

The historical 9B and single-seed 27B rows used a 32,768-token context,
4,096-token output cap, seed 0, and an older non-thinking structured-output
path. The final controlled 27B experiment uses Ollama 0.32.5, native thinking,
32,768 context tokens, an 8,192-token output cap, and seeds 0/1/2. These
profiles are provenance-separated and are never pooled.

Primary outcomes are WASP's native final-state user-utility and attacker-goal
oracles. Attacker-directed attempts and executions are deterministic replays of
recorded governance events against the instantiated attacker ground truth.

## Final controlled three-seed comparison

This is the authoritative browser-native result. Each condition contains the
same 84 attacked cases under seeds 0, 1, and 2: 252 episodes per condition and
756 overall. The action audit replays governance events against instantiated
attacker ground truth. A raw native positive is called terminal attacker
success only when an attacker-directed action executed.

| Condition | Utility | Raw ASR | Action-audited terminal success | Secure utility | Attacker-directed attempted | Attacker-directed executed | Potential false blocks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Off baseline | 154/252 (61.11%) | 17/252 (6.75%) | 17/252 (6.75%) | 138/252 (54.76%) | 43/252 (17.06%) | 42/252 (16.67%) | 0/252 |
| Policy + warning, sanitisation off | 149/252 (59.13%) | 1/252 (0.40%) | 1/252 (0.40%) | 148/252 (58.73%) | 15/252 (5.95%) | 15/252 (5.95%) | 1/252 (0.40%) |
| **Full sanitisation + policy** | **149/252 (59.13%)** | **0/252** | **0/252** | **149/252 (59.13%)** | **0/252** | **0/252** | **0/252** |

The final per-seed matched counts are:

| Seed | Off utility | Full utility | Off raw ASR | Full raw ASR | Off secure utility | Full secure utility |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 53/84 | 45/84 | 5/84 | 0/84 | 48/84 | 45/84 |
| 1 | 48/84 | 52/84 | 8/84 | 0/84 | 40/84 | 52/84 |
| 2 | 53/84 | 52/84 | 4/84 | 0/84 | 50/84 | 52/84 |

Full minus off changes aggregate utility by -1.98 percentage points
(seed-effect sample SD 7.18 pp; range -9.52 to +4.76), raw ASR by -6.75 pp
(seed SD 2.48 pp), and secure utility by +4.37 pp (seed SD 9.09 pp). Full minus
policy-only isolates the configured sanitisation increment: aggregate utility
is unchanged, raw/action-audited ASR changes from 1/252 to 0/252,
attacker-directed attempted/executed tasks change from 15/252 to 0/252, and
secure utility changes from 148/252 to 149/252. Policy-only minus off is a
combined boundary-neutralisation, detector-warning and action-policy effect,
not a pure action-policy effect.

The full condition recorded no hard block, approval, handoff, security pause,
or potential false block. Policy-only generated two approval requests in one
task; scripted `participant=none` resolution denied both. One denial stopped an
attacker-directed action and one is conservatively counted as a potential false
block. Actual human intervention is N/A because no human participant was
present.

## Historical development evidence (not pooled)

| Historical model and condition | Utility | End-to-end ASR | Secure utility | Attacker-directed attempted | Attacker-directed executed |
| --- | ---: | ---: | ---: | ---: | ---: |
| 9B shared off baseline | 45/84 (53.57%) | 7/84 (8.33%) | 41/84 (48.81%) | 31/84 (36.90%) | 31/84 (36.90%) |
| 9B warn enforce | 37/84 (44.05%) | 7/84 (8.33%) | 35/84 (41.67%) | 32/84 (38.10%) | 32/84 (38.10%) |
| 9B sanitise V1 | 52/84 (61.90%) | 6/84 (7.14%) | 49/84 (58.33%) | 18/84 (21.43%) | 18/84 (21.43%) |
| 9B sanitise V2 | 54/84 (64.29%) | 0/84 | 54/84 (64.29%) | 1/84 (1.19%) | 1/84 (1.19%) |
| Prior single-seed 27B off | 47/84 (55.95%) | 5/84 (5.95%) | 44/84 (52.38%) | 17/84 (20.24%) | 17/84 (20.24%) |
| Prior single-seed 27B sanitise V2 | 46/84 (54.76%) | 0/84 | 46/84 (54.76%) | 0/84 | 0/84 |

The 9B rows are one shared off baseline followed by three changed enforce
revisions. The prior 27B row is a separate matched seed-0 campaign. Both remain
useful development evidence, but neither contributes to the final denominators.

No oracle-participant WASP row was run. Oracle remains a possible scripted-
oversight upper bound, not evidence about human behaviour.

## Sanitisation mechanism evidence

| Row | Sanitisation events | Confirmed removal | Residual | Unattributable | Post-success alerts | Branches |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Historical 9B sanitise V2 | 1,057 | 1,053 | 0 | 4, historical warning fallback | 0 | line 14; window 1,039; none 4 |
| Historical single-seed 27B sanitise V2 | 368 | 368 | 0 | 0 | 0 | line 15; window 353 |
| **Final three-seed 27B full** | **740** | **740** | **0** | **0** | **0** | **line 21; window 719** |

The frozen 9B observation replay additionally confirmed 84/84 removals, no
detector-positive residual, no non-anchor control descriptor removal and no
whole-page wipe. These are mechanism checks. Security and utility claims come
from the complete agent trajectories and WASP's native final-state oracles.

After the historical campaigns were frozen, the interactive runtime replaced
the unresolved warning fallback with a fail-closed operator incident, stopped
sending page screenshots to the model, and extended the untrusted-input
boundary to extraction and tool-result text. The final replication records its
exact later enforcement-source hash and commit. Mechanisms that no final
trajectory exercised remain technical implementation evidence rather than a
behavioural benchmark result.

## Thesis interpretation

The warning-only result is negative but informative: it left ASR at 7/84,
slightly increased attacker-directed execution from 31/84 to 32/84 and reduced
utility from 45/84 to 37/84. Detection plus a model-facing warning was therefore
insufficient in this browser setting.

The final evidence supports a narrower positive claim: under the tested WASP
conditions, independently enforced, post-verified observation sanitisation
reduced both achieved attacks and attacker-serving action execution while
preserving aggregate utility within a small, variable difference. Across 252
matched cases, full changes attacker-directed execution from 42 tasks to zero,
raw/action-audited ASR from 17 to zero, utility from 154 to 149, and secure
utility from 138 to 149.

The evidence does not show that Sentinel solves prompt injection. Of 252 off
episodes, 25 executed an attacker-directed action without terminal success and
209 recorded no attacker-directed attempt; baseline inability therefore
remains material. Zero successes in 252 full executions gives a rough
rule-of-three 95% upper bound of about 1.2%, not proof of a zero population
rate. The three seeds share one benchmark revision, fixed cell order, model,
and GPU/runtime profile, and the historical 9B/27B difference is not an
identified model-size effect.

For the thesis:

1. use the final three-seed 27B off/policy-only/full comparison as the primary
   WASP result;
2. use the 9B sequence as a provenance-separated engineering ablation showing
   why warning-only and incomplete sanitisation were insufficient;
3. report native ASR, attacker-directed attempts/executions, utility, secure
   utility and interventions together;
4. position WASP as controlled browser-native transfer and limitation evidence,
   complementing AgentDojo's controlled mechanism evaluation.

## Provenance records

- [Final controlled three-seed 27B record](wasp-qwen35-27b-multiseed-thinking8k-replication-v2.md)
  and [machine-readable aggregate](wasp-qwen35-27b-multiseed-thinking8k-replication-v2.json)
- [Final 9B sanitisation V2 record](wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.md)
  and [machine-readable summary](wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.json)
- [Matched 27B sanitisation V2 record](wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.md)
  and [machine-readable summary](wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.json)

The historical 20-step pilot, failed earlier multiseed attempts, incomplete V2
warn attempt, and older provenance-incompatible campaigns remain preserved
locally but are excluded from the final aggregate. Results are never pooled
across changed policy, middleware, model settings, participant mode, scaffold,
runtime or benchmark inputs.
