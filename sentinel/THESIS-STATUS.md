# Sentinel thesis status and evidence map

This is the concise handoff for agents writing about Sentinel. It describes the
project argument, current implementation, evidence hierarchy, thesis-ready
scope, and unfinished work as of 2026-07-29.

Quantitative results belong in [`EVALS.md`](EVALS.md). Do not copy result tables
into this file. WASP's detailed row-level ledger remains
[`evals/wasp/results/README.md`](evals/wasp/results/README.md), linked from the
WASP results section in `EVALS.md`.

## Source-of-truth order

When a claim or number conflicts across documents, use:

1. curated result JSON or per-run result Markdown;
2. frozen campaign state, reports, task results, and provenance;
3. [`EVALS.md`](EVALS.md) and the WASP result ledger;
4. this implementation and thesis-readiness synthesis.

The current repository `HEAD` is not retrospective provenance for an older
run. Each row retains the model, policy, code, and benchmark provenance
recorded by that campaign.

## Required reading

- [`README.md`](README.md): architecture and development entry point.
- [`THREAT-MODEL.md`](THREAT-MODEL.md): trust boundary, invariants, and
  non-claims.
- [`POLICY.md`](POLICY.md) and
  [`policies/POLICY-SCHEMA.md`](policies/POLICY-SCHEMA.md): policy semantics.
- [`EVALS.md`](EVALS.md): methodology, all benchmark results, interpretation,
  and provenance limits.
- [`evals/wasp/README.md`](evals/wasp/README.md): WASP campaign design,
  infrastructure, provenance, and recovery.
- [`../DESIGN.md`](../DESIGN.md): interface direction.
- [`../AGENTS.md`](../AGENTS.md) and
  [`../thesis/AGENTS.md`](../thesis/AGENTS.md): repository and thesis-writing
  constraints.

## Project identity and supported argument

Sentinel is a research prototype and thesis artefact: an independent
runtime-enforcement and governance layer between an untrusted browser agent and
its privileged executor.

The supported claim is deliberately narrow:

> Independent runtime enforcement can reduce evaluated policy violations while
> preserving useful autonomy under the tested conditions.

Do not claim that Sentinel solves prompt injection, is universally robust, is
ready for deployment, or improves real human trust, workload, fatigue,
usability, or approval behaviour.

The contribution chain is:

1. AgentDojo supplies controlled mechanism evidence across tool domains and
   attack families.
2. WASP tests browser-native transfer through observations, navigation, and
   privileged actions.
3. The extension and governance layer provide the technical basis for
   selective human authority under uncertainty, but the HITL contribution is
   not yet complete or empirically evaluated.

The two central questions, in simple terms, are:

1. Can a separate enforcement layer reduce unsafe browser-agent actions without
   stopping useful work?
2. When automatic enforcement cannot decide safely, when and how should it
   pause and hand control to the user?

This is the intended argumentative link: AgentDojo tests enforcement in
isolation, WASP tests transfer to browser interaction, and HITL addresses the
remaining cases where safe automatic resolution is not possible.

## Confirmed decisions as of 2026-07-29

- Important enforcement lifecycle defects should be fixed now, with tests; they
  are not deferred thesis limitations.
- A failed or incomplete browser-observation sanitisation must not be followed
  by a warning to the model. Sentinel withholds the observation, pauses, shows
  a persistent operator incident in the Chrome extension, and requires human
  takeover or stop. Returning control causes a fresh browser observation; it
  does not approve or reuse the held content.
- Page-extraction subcalls and wrapped historical tool results use the same
  untrusted-input detector. If one bounded value remains unresolved, Sentinel
  removes that value in full rather than opening an incident inside a shorter
  extraction timeout or repeatedly pausing on persistent history.
- The incident path must have scripted coverage, including the four
  unattributable attempts recorded in the 9B V2 campaign, and must be visually
  checked in the extension.
- In enforce mode, recognized passwords, credentials, one-time codes,
  access/API tokens, payment details, and private keys are human-only steps.
  Consent means the user takes control and performs the step directly; an
  approval card must not authorize the guarded agent action.
- Browser screenshots are not sent to the interactive model or shown as
  side-panel thumbnails. DOM sanitisation cannot safely remove an instruction
  rendered into pixels. Explicit local trace retention may keep a frame for
  audit, but it is not sent over the extension WebSocket.
- The localhost-only, origin-checked API is the accepted deployment boundary
  for this local thesis prototype. Protection from another compromised process
  running as the same OS user is out of scope and must remain a stated limit.
- Do not launch another benchmark campaign now. Preserve the completed rows;
  mention historical/excluded runs only when they explain provenance or prevent
  a misleading comparison.
- Plan authority and multi-agent supervision are possible later HITL work, not
  current contributions. Provenance hiding is only an optional separate
  comparison, not required current work.

## Current implementation

Sentinel treats the model, DOM, screenshots, downloads, extracted text, and
tool results as untrusted. It mediates proposed actions immediately before
privileged execution, applies policy independently of model intent, and records
attempted and terminal outcomes.

| Concern | Main implementation |
| --- | --- |
| Runtime composition and browser-agent loop | `server/runner.py` |
| Model-output and observation governance | `server/governance/governed_llm.py` |
| Pre-execution tool mediation | `server/governance/governed_tools.py` |
| Central policy decision point | `server/governance/policy.py` |
| Prompt-injection detection and sanitisation | `server/governance/security.py` |
| Approval lifecycle | `server/governance/approvals.py` |
| Handover and unresolved-observation incident lifecycle | `server/governance/handover.py`, `server/governance/governed_llm.py` |
| Redacted traces, history, and audit events | `server/traces.py`, `server/history.py` |
| Local API and browser integration | `server/api.py`, `server/browser.py` |
| Operator side panel and dashboard | `extension/src/` |

Implemented mechanisms include:

- policy evaluation before privileged actions;
- hard blocks and sensitive-data-flow controls;
- narrow, expiring, run-local approvals;
- fail-closed approval and handover states;
- prompt-injection detection, targeted sanitisation, post-sanitisation
  re-detection, and branch telemetry;
- fail-closed operator quarantine after residual or unattributable current
  browser/read sanitisation, followed by a fresh observation after takeover;
- whole-value removal for unresolved bounded page-extraction or persistent
  tool-result content;
- direct takeover for recognized credentials, one-time codes, tokens, payment
  details, and private keys across guarded input, keystroke, script, and upload
  channels rather than agent approval;
- DOM-only interactive model input and no screenshot thumbnails in the
  extension;
- action revalidation after approval and explicit cancellation outcomes;
- redacted attempted/terminal audit records and local operator interfaces.

These are implementation facts. The new incident, extraction/tool-result
boundary, screenshot, guarded-secret, bounded-upload, and lifecycle hardening
post-date the frozen benchmark rows and are not benchmark results. The secret
checks are deterministic channel coverage, not universal DLP; semantically
secret values with no recognized marker can still be missed. These mechanisms
also do not mean every governance or HITL workflow is finished.

## Completed evidence map

All values, denominators, paired transitions, telemetry counts, and exclusions
are in [`EVALS.md`](EVALS.md).

### AgentDojo

- [Full component replay](EVALS.md#agentdojo-v1-full-tier-1-component-run):
  model-free detector, policy, benign-block, and approval-pressure evidence
  across all v1 attack families. It is development-set evidence.
- [Detector-v2 scorecard](EVALS.md#detector-v2-goal-hijacking-coverage):
  AgentDojo and WASP detector corpora, the live-representation correction,
  false-positive disclosure, and post-hoc adaptation limit.
- [Action-gating replay](EVALS.md#what-action-gating-does-and-does-not-cover):
  why browser observation sanitisation remains primary and why blanket
  tainted-side-effect gating was rejected.
- [Gemini pilot and integration smoke](EVALS.md#gemini-pilot-and-integration-smoke):
  secondary quota-limited and one-pair checks; neither is a headline result.
- [Completed Qwen end-to-end results](EVALS.md#completed-agentdojo-end-to-end-results):
  controlled 4B, 9B, and 27B off/enforce evidence with utility, native ASR,
  secure utility, paired changes, diagnostics, and provenance limits.

The AgentDojo results support the mechanism claim under the tested suites and
models. Cross-model differences are descriptive, not a causal parameter-count
effect. Low ASR must always be interpreted beside model capability and utility.

### WASP

- [Browser-native results](EVALS.md#wasp-browser-native-enforcement-evaluation):
  all finalized 9B development rows, the primary matched 27B comparison,
  sanitisation telemetry, warning-only negative evidence, exclusions, and
  uncertainty.
- [Curated WASP ledger](evals/wasp/results/README.md): exact run identities,
  row-level provenance, paired outcomes, validation, and machine-readable
  summary links.

Use the matched 27B row as the principal browser comparison. Use the 9B sequence
as provenance-separated engineering and failure-analysis evidence. Its exact
shape is one shared off baseline, then warning-only enforce, sanitisation V1
enforce, and sanitisation V2 enforce. The final two are the two sanitisation
revisions. Do not pool the revisions or interpret 9B-versus-27B differences as
an identified model-size effect.

### Non-headline checks

The deterministic security smoke, one-pair agent smoke, quota-limited Gemini
pilot, historical non-thinking/8K run, and excluded WASP pilot validate
contracts or document development history. Their status and any reported
values are in `EVALS.md`; do not promote them to headline evidence.

No WASP oracle campaign has been run.

## Thesis-ready contributions

The current implementation and completed evidence support discussion of:

1. an executor-side, model-independent runtime boundary;
2. fail-closed policy, approval, handover, redaction, and audit semantics;
3. post-verified sanitisation that stays silent only after attributable removal
   and clean re-detection;
4. controlled evaluation across AgentDojo mechanism evidence and WASP
   browser-native transfer evidence;
5. an evaluation approach that reports utility, secure utility, native
   attacker success, risky attempts and executions, interventions, false
   blocks, and provenance rather than treating low ASR as sufficient.

The evidence is strongest for evaluated runtime containment under the tested
models and tasks. It is not evidence of universal prevention or deployment
readiness.

## HITL and interface work: unfinished

Basic approval, handover, trace, and extension UI primitives exist. This is not
the same as a completed HITL contribution.

Do not claim the following as complete until separately implemented, frozen,
and evaluated:

- the final selective-authority and plan-authority feature set;
- a completed evaluation of the implemented unresolved-sanitisation incident
  and operator-resolution flow;
- a completed broader HITL protocol or benchmark;
- measured human approval behaviour, trust, workload, fatigue, usability, or
  rubber-stamping;
- participant-study findings;
- a WASP oracle result;
- provenance-hiding or plan-authority ablations without a frozen result.

In plain language:

- **Plan authority** means showing the user a short plan before the run—goal,
  expected sites/data, permitted and prohibited actions, likely human steps,
  and stop conditions. BrowserUse's private internal plan is not this feature.
- **Provenance hiding** means withholding a whole category of untrusted
  user-generated content based on its source, without first asking a detector
  whether its wording looks malicious. It would be a separate upper-bound
  comparison, not a replacement for the existing exposed-agent results.
- **Multi-agent supervision** means one operator overseeing a queue of several
  isolated agent runs. It is optional future work.

`participant=deny`, `participant=none`, and a deterministic
`participant=oracle` are benchmark controls, not human participants. A future
oracle study would be a scripted-oversight upper bound only.

The architecture, threat model, implementation, AgentDojo, WASP, results, and
non-HITL limitations are ready to draft. HITL and interface sections must
remain proposed, in progress, or method-only until evidence exists.

## Thesis writing route

1. Define the executor-side trust boundary and non-claims.
2. Explain policy evaluation, redaction, audit, approval, and sanitisation.
3. Use AgentDojo component replay to establish mechanism behaviour.
4. Use matched AgentDojo end-to-end rows to quantify controlled enforcement.
5. Use the matched 27B WASP row as browser-native transfer evidence.
6. Use the 9B WASP sequence as transparent development and failure analysis.
7. Discuss utility gains and losses, security by incompetence, benchmark
   coverage, residual uncertainty, and provenance asymmetries.
8. Describe the incident card and guarded detected-secret takeover as
   implemented mechanisms, while treating broader HITL claims as unfinished
   until an evaluation is frozen.

## Keeping the documents synchronized

When a benchmark is rerun:

1. preserve the previous immutable row and use a new tag when provenance
   changes;
2. add or update the compact curated result artifact;
3. update the methodology, result table, diagnostics, and interpretation in
   `EVALS.md`;
4. update the WASP ledger when applicable;
5. change this file only if the evidence map, supported interpretation, or
   thesis-readiness boundary changes.

When a HITL or interface feature is completed, update the implementation map
and remove an unfinished-work boundary only after the corresponding code,
tests, and evaluation artifact exist.
