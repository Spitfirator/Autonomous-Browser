# AGENTS.md

## Scope and project identity

These instructions apply to this repository.

Sentinel is a research prototype and thesis artefact: an independent
runtime-enforcement and governance layer between an untrusted browser agent and
its privileged executor. Do not frame it as a commercial product or claim that
it “solves prompt injection.” The supported claim is narrower: independent
runtime enforcement can reduce evaluated policy violations while preserving
useful autonomy under the tested conditions.

Read the relevant source of truth before editing:

- `sentinel/THESIS-STATUS.md` for the current implementation, evidence map,
  thesis-ready claims, and unfinished work.
- `sentinel/README.md` for architecture and development.
- `sentinel/THREAT-MODEL.md` for security invariants and non-claims.
- `sentinel/POLICY.md` and `sentinel/policies/POLICY-SCHEMA.md` for policy.
- `sentinel/EVALS.md` for metrics, methodology, all completed benchmark
  results, interpretation, and provenance limits.
- `sentinel/evals/wasp/README.md` for WASP campaigns and recovery.
- `DESIGN.md` for interface work.

## Current research status

The principal non-HITL benchmark evidence is ready to write up: AgentDojo has
controlled component and matched end-to-end results, and WASP has browser-native
development evidence plus a matched 27B off/enforce result. Later reruns amend
the evidence ledger; they do not silently replace or pool completed rows.

The 9B WASP structure is one shared off baseline with no enforcement, followed
by three provenance-separated enforce rows: warning-only, sanitisation V1, and
sanitisation V2. The latter two are the two sanitisation revisions. Do not call
that sequence one immutable matched campaign. The 27B off/enforce row is the
primary matched browser comparison.

The current runtime includes a fail-closed unresolved-sanitisation incident,
direct human takeover for detected secrets across guarded action channels,
approval revalidation, explicit cancellation semantics, and a DOM-only
interactive model path with no extension screenshot thumbnails. Page-extraction
subcalls and wrapped tool-result text also cross the untrusted-input boundary;
an unresolved bounded extraction/history value is removed in full rather than
opening the browser-observation incident. These changes post-date the frozen
benchmark rows; do not imply that the completed results measured them. No
further benchmark campaign is currently planned or authorized.

Broader HITL and plan-authority work is not complete. Basic approval, handover,
incident, trace, and extension UI primitives exist, but do not describe the
final HITL feature set, protocol, interface findings, or human evidence as
finished. Benchmark participant modes such as `deny`, `none`, and deterministic
`oracle` are scripted controls, not human participants. No WASP oracle result
currently exists.

When results or thesis-relevant features change, keep
`sentinel/EVALS.md`, the relevant curated result index,
`sentinel/THESIS-STATUS.md`, and `thesis/AGENTS.md` synchronized. Quantitative
results belong in `sentinel/EVALS.md`; do not duplicate result tables in the
status or agent-instruction files.

## Repository boundaries

- `sentinel/` contains the application, policies, tests, and evaluation code.
- `browser-use/` is an ignored dependency checkout with separate Git history.
  Do not modify it unless the task explicitly targets browser-use; inspect and
  isolate its repository state separately if it must change.
- `.wasp/` contains ignored local environments, checkpoints, logs, and raw
  campaign artefacts. Treat completed and active checkpoints as evidence.
- `sentinel/data/` contains local runtime state, browser profiles, and traces.
- `thesis/` is user-owned thesis work. Preserve unrelated source and output,
  and read `thesis/AGENTS.md` before any thesis writing or editing.

Never add credentials, private host details, virtual environments, model
weights, browser profiles, raw page captures, screenshots, or full campaign
directories to Git. Track reproducible code, configuration, provenance, and
compact curated result summaries only.

## Working rules

1. Run `git status --short` before editing and preserve unrelated work.
2. Read the implementation, nearby tests, and governing documentation.
3. Make the smallest change that preserves the security and experiment
   contracts.
4. Do not weaken tests, redaction, audit coverage, or security invariants to
   make a change pass.
5. Keep mirrored boundaries synchronized. Python event changes may require
   updates to `sentinel/extension/src/shared/types.ts`; policy changes may
   require schema, documentation, fixture, and evaluation updates.
6. Ask the user for clarification instead of guessing when uncertainty could
   materially change the requested outcome, security posture, experimental
   validity, research claim, or thesis structure. State any minor, safe
   assumptions used to keep reversible work moving.

## Security invariants

- Treat the model, DOM, screenshots, downloads, extracted text, and tool
  results as untrusted.
- Evaluate every proposed action immediately before privileged execution.
- Do not downgrade hard policy or sensitive-data-flow blocks into approvals.
- In enforce mode, recognized credentials, passwords, one-time codes,
  access/API tokens, payment details, and private keys are human-only: withhold
  the agent action and hand the browser to the user.
  Consent is the user's direct action during takeover, not permission for the
  agent to type or disclose the value.
- Guard indexed sensitive fields, free-text `send_keys`, sensitive
  `evaluate` semantics, secret-looking upload paths, and bounded local upload
  text. Treat remote, missing, binary, oversized, or unreadable uploads as
  unclassifiable and hand them over. These are deterministic guards, not a
  universal data-loss-prevention claim; keep residual detector misses explicit.
- Required authority must fail closed on silence, timeout, cancellation,
  malformed input, and shutdown.
- Human approval must remain explicit, narrow, expiring, run-local, and
  non-transferable.
- Every attempted action must have exactly one attempted and one terminal audit
  record, including blocks, denials, timeouts, exceptions, and cancellations.
- Never expose or persist raw secrets, credentials, payment data, injection
  payloads, or unredacted parameters. Screenshots and model rationale remain
  omitted from persistent traces by default.
- Do not present exposed model rationale as private chain-of-thought.
- Browser screenshots are not model input in the interactive runner and are not
  sent to the extension. DOM sanitisation cannot clean instructions rendered in
  pixels. Keep any explicit local trace retention separate from model/UI paths.
- Keep localhost origin, consent-scope, and API validation intact.
  Localhost-only operation is the accepted thesis boundary, not protection
  against another compromised process running as the same OS user.

`PolicyEngine.evaluate(...)` is the central policy decision point. Avoid
parallel allow/block paths that bypass it. Security-relevant changes need tests
for allowed and denied behaviour, including timeout or cancellation paths when
applicable.

## Evaluation integrity

- Never delete, overwrite, reset, or blindly rerun campaign checkpoints.
- Inspect status, artefacts, logs, and provenance before resuming interrupted
  work.
- Do not start remote, browser, GPU, or long-running benchmark runs unless the
  user explicitly requests them.
- Use a new immutable run tag whenever policy, participant mode, model or model
  settings, middleware, benchmark inputs, or scaffold changes.
- Never pool results across provenance changes, including WASP versions or
  participant modes.
- Do not edit generated task results or native scores by hand.
- Do not declare completion from `status` alone. Verify expected task
  artefacts, native scores, provenance, telemetry, and applicable test/build
  gates.
- Label intermediate checkpoints as provisional. Report attempted,
  privileged-tool-executed, and native final attacker success separately.
- Low ASR alone is not security evidence; inspect model capability, risky
  attempts and executions, legitimate utility, and false blocks.
- Treat a deterministic oracle as a scripted-oversight upper bound, not a
  participant study. Do not claim measured trust, workload, fatigue, usability,
  or rubber-stamping.
- Keep optional future mechanisms separate: plan authority is a short
  human-visible pre-run contract; provenance hiding withholds content based on
  its untrusted source; multi-agent supervision gives one operator a queue of
  isolated runs. Do not replace or retroactively redefine the frozen
  exposed/action-level baseline with any of them.

Prefer matched off/enforce comparisons. Describe AgentDojo as controlled
mechanism evidence and WASP as controlled browser-native transfer and
limitation evidence, not deployment “in the wild.”

## Validation

Run targeted tests first, then the relevant broader gate.

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q sentinel/tests
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python sentinel/evals/security_benchmark.py sentinel/evals/fixtures/security-smoke.jsonl --pretty
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q sentinel/tests/test_wasp_campaign.py
bash sentinel/evals/wasp/run-wasp.sh preflight --offline
(cd sentinel/extension && npm run build)
```

Use the full Python suite for governance, policy, security, audit, trace,
approval, or shared evaluation changes. Use both Python tests and the extension
build when a change crosses that boundary. For visual work, inspect the rendered
side panel and dashboard; a successful build is not visual QA.

If a check cannot be run, state which check was skipped and why.

## Git hygiene and handoff

- Preserve unrelated modified and untracked files.
- Stage only files belonging to the requested change.
- Do not commit, push, rewrite history, or discard user work unless requested.
- Keep machine-specific values in ignored `.env` or `*.local.env` files and
  maintain only sanitized `.example` files.
- Before handoff, inspect the scoped diff and run `git diff --check`.
- Summarize changed behaviour, checks run, and any remaining unverified risk.
