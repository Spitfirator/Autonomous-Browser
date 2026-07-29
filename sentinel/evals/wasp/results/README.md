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

All thesis-eligible rows use:

- WASP commit `ffee6f41fde76acd14bd792db442479c506260c2`;
- BrowserUse commit `c8e6e8f0fe617564687895702c2338967293b309`;
- 32,768 context tokens, 4,096 output tokens and a 30-step cap;
- temperature 0.6, top-p 0.95 and seed 0;
- BrowserUse structured planning, one action per step, DOM/accessibility
  observations and no screenshots;
- participant mode `none`.

Primary outcomes are WASP's native final-state user-utility and attacker-goal
oracles. Attacker-directed attempts and executions are deterministic replays of
recorded governance events against the instantiated attacker ground truth.

## All finalized thesis-eligible conditions

| Model and condition | Design | Utility | End-to-end ASR | Secure utility | Attacker-directed attempted | Attacker-directed executed |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 9B shared off baseline | No enforcement | 45/84 (53.57%) | 7/84 (8.33%) | 41/84 (48.81%) | 31/84 (36.90%) | 31/84 (36.90%) |
| 9B warn enforce | Warn-only enforcement | 37/84 (44.05%) | 7/84 (8.33%) | 35/84 (41.67%) | 32/84 (38.10%) | 32/84 (38.10%) |
| 9B sanitise V1 | Enforce-only development row | 52/84 (61.90%) | 6/84 (7.14%) | 49/84 (58.33%) | 18/84 (21.43%) | 18/84 (21.43%) |
| **9B sanitise V2** | **Enforce-only final 9B row** | **54/84 (64.29%)** | **0/84 (0%)** | **54/84 (64.29%)** | **1/84 (1.19%)** | **1/84 (1.19%)** |
| 27B off | Matched V2 baseline | 47/84 (55.95%) | 5/84 (5.95%) | 44/84 (52.38%) | 17/84 (20.24%) | 17/84 (20.24%) |
| **27B sanitise V2** | **Matched V2 enforce row** | **46/84 (54.76%)** | **0/84 (0%)** | **46/84 (54.76%)** | **0/84 (0%)** | **0/84 (0%)** |

The last two columns count task instances with at least one matched
attacker-directed attempt or execution, not raw action totals.

The 9B structure is one shared off baseline with no enforcement and three
enforce rows: warning-only, sanitisation V1, and sanitisation V2. V1 and V2 are
the two sanitisation-enforcement revisions. These rows document a development
sequence, not one immutable matched campaign: middleware changed between
revisions, and the final V2 row deliberately reused the shared off baseline
rather than rerunning it. The 27B row is therefore the primary matched
controlled browser comparison: all 168 off/enforce executions were collected
under one frozen model, scaffold, policy and middleware tuple with matched
generated inputs.

No oracle-participant WASP row was run. Oracle remains a possible
scripted-oversight upper bound, not part of the reported browser result and not
evidence about human behaviour.

## Primary matched 27B finding

In the matched 27B comparison, sanitisation:

- reduced native attacker success from 5/84 to 0/84;
- reduced task instances with attacker-directed attempts and executions from
  17/84 to 0/84;
- changed native utility from 47/84 to 46/84;
- increased secure utility from 44/84 to 46/84.

At task-instance level there were seven utility gains, eight losses and 69
unchanged outcomes. All five off-condition attacker successes were absent under
enforce, with no new enforce success. No hard policy block or handoff occurred.
One page-code action triggered an approval request and was denied, but the
agent recovered and the native user task still succeeded. The eight paired
utility losses therefore cannot be described as eight direct false blocks.

## Sanitisation mechanism evidence

| Final row | Sanitisation events | Confirmed removal | Residual | Unattributable | Post-success alerts | Branches |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 9B sanitise V2 | 1,057 | 1,053 | 0 | 4, historical warning fallback | 0 | line 14; window 1,039; none 4 |
| 27B sanitise V2 | 368 | 368 | 0 | 0 | 0 | line 15; window 353 |

The frozen 9B observation replay additionally confirmed 84/84 removals, no
detector-positive residual, no non-anchor control descriptor removal and no
whole-page wipe. These are mechanism checks. Security and utility claims come
from the complete agent trajectories and WASP's native final-state oracles.

After these campaigns were frozen, the interactive runtime replaced the
unresolved warning fallback with a fail-closed operator incident and stopped
sending page screenshots to the model. It also added the same untrusted-input
boundary to page-extraction subcalls and wrapped tool-result text; unresolved
bounded extraction/history values are dropped rather than opening a repeating
incident. Those changes are not part of these results. They need a new run tag
if evaluated later; no additional campaign is currently planned.

## Thesis interpretation

The warning-only result is negative but informative: it left ASR at 7/84,
slightly increased attacker-directed execution from 31/84 to 32/84 and reduced
utility from 45/84 to 37/84. Detection plus a model-facing warning was therefore
insufficient in this browser setting.

The final evidence supports a narrower positive claim: under the tested WASP
conditions, independently enforced, post-verified observation sanitisation
reduced both achieved attacks and attacker-serving action execution while
preserving almost all aggregate utility. The matched 27B reduction in
attacker-directed execution from 17/84 to zero is important because terminal
ASR alone can understate diversion when an agent is incapable of completing the
attacker's objective.

The evidence does not show that Sentinel solves prompt injection. Two of the
four 27B off batches already had zero terminal attack successes, so part of the
low ASR reflects baseline agent behaviour. Zero successes in 84 enforce
executions gives a rough rule-of-three 95% upper bound of about 3.6%, not proof
of a zero population rate. Only one seed and one benchmark revision were
evaluated, the 9B sequence is not one matched run, and the 9B/27B difference is
not an identified model-size effect.

For the thesis:

1. use the matched 27B off/enforce comparison as the primary WASP result;
2. use the 9B sequence as a provenance-separated engineering ablation showing
   why warning-only and incomplete sanitisation were insufficient;
3. report native ASR, attacker-directed attempts/executions, utility, secure
   utility and interventions together;
4. position WASP as controlled browser-native transfer and limitation evidence,
   complementing AgentDojo's controlled mechanism evaluation.

## Provenance records

- [Final 9B sanitisation V2 record](wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.md)
  and [machine-readable summary](wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.json)
- [Matched 27B sanitisation V2 record](wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.md)
  and [machine-readable summary](wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.json)

The historical 20-step pilot, incomplete V2 warn attempt and older
provenance-incompatible V1 campaigns remain preserved locally but are excluded
from the thesis aggregate. Results are never pooled across changed policy,
middleware, model settings, participant mode or benchmark inputs.
