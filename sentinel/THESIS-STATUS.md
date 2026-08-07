# Sentinel thesis evidence map

This file routes thesis work to the authoritative implementation and evidence
sources. It is not a live changelog or quantitative ledger. Verify current
behaviour in code and tests; verify experimental claims in curated artefacts
and recorded run provenance.

Quantitative results belong in [`EVALS.md`](EVALS.md). WASP's thesis-ready
synthesis and per-run records are under
[`evals/wasp/results/`](evals/wasp/results/README.md).

## Source-of-truth order

When a claim or number conflicts across documents, use:

1. curated result JSON or the corresponding per-run Markdown;
2. frozen campaign state, native scores, task artefacts, and provenance;
3. [`EVALS.md`](EVALS.md) and the WASP result ledger;
4. current implementation and tests for implementation-only claims;
5. this argument and evidence map.

The current repository `HEAD` is not retrospective provenance for an older
run. Each result remains tied to its recorded model, policy, middleware,
benchmark, and scaffold.

## Project argument

Sentinel is a research prototype and thesis artefact: an independent runtime-
enforcement and governance layer between an untrusted browser agent and its
privileged executor.

The supported claim is deliberately narrow:

> Independent runtime enforcement can reduce evaluated policy violations while
> preserving useful autonomy under the tested conditions.

Do not claim that Sentinel solves prompt injection, is universally robust, is
deployment-ready, or has demonstrated human-factors benefits.

The research question is:

> To what extent can an independent runtime-enforcement layer reduce
> prompt-injection-driven browser-agent violations while preserving task
> utility?

The evidence chain is:

1. AgentDojo supplies controlled mechanism and end-to-end evidence across tool
   domains and attack families.
2. WASP tests browser-native transfer through observations, navigation, and
   privileged actions.
3. The authority workflow supplies the completed technical mechanism for
   approval, direct human steps, and unresolved observations.

## Implementation map

| Concern | Main implementation |
| --- | --- |
| Runtime composition and browser-agent loop | `server/runner.py` |
| Model-output and observation governance | `server/governance/governed_llm.py` |
| Pre-execution tool mediation | `server/governance/governed_tools.py` |
| Central policy decision point | `server/governance/policy.py` |
| Detection, sanitisation, and redaction | `server/governance/security.py` |
| Approval lifecycle | `server/governance/approvals.py` |
| Human steps and observation incidents | `server/governance/handover.py` |
| Redacted traces, history, and audit events | `server/traces.py`, `server/history.py` |
| Local API and browser integration | `server/api.py`, `server/browser.py` |
| Side panel, in-page controls, and dashboard | `extension/src/`, `extension/public/content.js` |

Sentinel treats model output, browser observations, downloads, extracted text,
and tool results as untrusted. It mediates proposed actions immediately before
privileged execution, applies policy independently of model intent, and emits
paired attempted and terminal audit outcomes.

Implemented controls include:

- domain, action, data-flow, and risk policy before execution;
- targeted observation sanitisation with post-sanitisation verification;
- quarantine and fresh recapture for unresolved browser/read observations;
- whole-value removal for unresolved bounded extraction or tool-result text;
- DOM-only interactive model input and no extension screenshot thumbnails;
- special-URL navigation and observation boundaries;
- narrow, expiring, run-local approval with live revalidation;
- operator-initiated takeover, agent-requested control, and policy-forced human
  steps for recognized protected values or unclassifiable uploads;
- timeout, cancellation, shutdown, and reconnect handling that fail closed;
- redacted Activity, trace, and extension projections.

These mechanisms complete the bounded HITL implementation used by the thesis.
The interface walkthroughs and tests establish technical behaviour. They do
not constitute participant evaluation and do not support measured claims about
comprehension, trust, workload, fatigue, usability, or approval behaviour.

The secret checks are deterministic channel coverage, not universal DLP.
Semantically secret values without a recognized marker can still be missed.
The localhost API is an accepted prototype boundary, not same-user process
isolation.

## Evidence map

All denominators, effects, telemetry counts, exclusions, and uncertainty are in
[`EVALS.md`](EVALS.md).

### AgentDojo

- [Full component replay](EVALS.md#agentdojo-v1-full-tier-1-component-run):
  detector, policy, benign-block, and approval-pressure mechanism evidence.
- [Detector-v2 scorecard](EVALS.md#detector-v2-goal-hijacking-coverage):
  detector coverage, representation corrections, false positives, and
  adaptation limits.
- [Action-gating replay](EVALS.md#what-action-gating-does-and-does-not-cover):
  the boundary of action-only controls and the role of observation governance.
- [Completed end-to-end campaigns](EVALS.md#completed-agentdojo-end-to-end-results):
  matched utility, native ASR, secure utility, and provenance-aware model rows.

AgentDojo supports the controlled mechanism claim under the tested suites and
models. Cross-model differences are descriptive, not a causal model-size
effect.

### WASP

- [Browser-native evaluation](EVALS.md#wasp-browser-native-enforcement-evaluation):
  the admitted final comparison, sanitisation ablation, variability, action-
  audited outcomes, mechanism telemetry, and historical development evidence.
- [WASP evidence index](evals/wasp/results/README.md): exact run identities,
  row-level provenance, validation, exclusions, and per-run records.

Use the validated three-seed 27B off/policy-only/full comparison as the
principal browser result. The earlier single-seed 27B comparison and 9B
sequence are provenance-separated historical and failure-analysis evidence;
do not pool them with the final denominators or use them as a causal model-size
comparison.

The frozen benchmark rows measure only their recorded middleware versions.
Current code may contain mechanisms that a particular trajectory did not
exercise or that post-date an older row. Use the per-run provenance before
attributing a quantitative effect.

## Thesis contributions and boundaries

The implementation and admitted evidence support three contributions:

1. executor-side mediation of model-proposed privileged actions;
2. post-verified observation governance combined with selective, fail-closed
   human authority, redaction, and paired audit; and
3. controlled evaluation across AgentDojo mechanism evidence and WASP browser-
   native transfer evidence, reporting security and utility together.

The evidence supports evaluated runtime containment under tested models and
tasks. It does not establish universal prevention, deployment readiness, or
human-factors effectiveness.

Scripted `participant=deny`, `participant=none`, and deterministic
`participant=oracle` modes are benchmark controls, not people. Runtime pause
counts, timing splits, and `understood` annotations are technical telemetry or
walkthrough aids, not participant outcomes.

## Thesis writing route

1. Define the executor-side trust boundary and explicit non-claims.
2. Explain observation governance, action policy, redaction, audit, approval,
   and direct human steps.
3. Use AgentDojo component replay to establish mechanism behaviour.
4. Use matched AgentDojo rows to quantify controlled end-to-end enforcement.
5. Use the final three-seed WASP comparison and sanitisation ablation as the
   principal browser-native transfer evidence.
6. Use historical WASP rows only for provenance-aware development and failure
   analysis.
7. Discuss utility, security by incompetence, benchmark coverage, residual
   risk, and provenance limitations.
8. Present the implemented authority and interface flows as technical systems
   evidence while keeping participant claims outside the evidence supplied.

## Document ownership

- `README.md` owns architecture and development guidance.
- `THREAT-MODEL.md` owns security objectives, trust boundaries, and non-claims.
- `POLICY.md` owns policy semantics; `policies/POLICY-SCHEMA.md` is the compact
  configuration-field reference.
- `EVALS.md` owns human-readable quantitative results and interpretation.
- `evals/wasp/results/` owns curated WASP provenance and per-run records.
- This file owns only the thesis argument, evidence route, and claim boundary.

When evidence changes, preserve old immutable rows, update the curated result
record and `EVALS.md`, then change this file only if the argument, evidence
route, or supported claim boundary changes.
