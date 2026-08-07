# AGENTS.md

## Project scope

Sentinel is a research prototype and thesis artefact: an independent runtime-
enforcement and governance layer between an untrusted browser agent and its
privileged executor. Do not frame it as a commercial product or claim that it
solves prompt injection. The supported claim is narrower: independent runtime
enforcement can reduce evaluated policy violations while preserving useful
autonomy under the tested conditions.

## Source routing

Read only the sources needed for the task:

- `sentinel/README.md`: architecture, setup, and development.
- `sentinel/THREAT-MODEL.md`: security objectives, trust boundaries, and
  non-claims.
- `sentinel/POLICY.md`: policy semantics and decision behavior.
- `sentinel/policies/POLICY-SCHEMA.md`: compact configuration-field reference.
- `sentinel/EVALS.md`: canonical human-readable methodology and quantitative
  result ledger.
- `sentinel/evals/wasp/results/README.md` and per-run records: WASP evidence
  index and immutable provenance.
- `sentinel/THESIS-STATUS.md`: thesis argument, evidence map, and claim
  boundaries; it is not a live result ledger.
- `DESIGN.md`: interface design rules.
- `thesis/AGENTS.md`: additional rules for thesis work.

Do not copy volatile result values or implementation snapshots into this file.
Resolve current claims from code, tests, curated artefacts, and recorded run
provenance.

## Repository boundaries

- `sentinel/` contains the application, policies, tests, and evaluation code.
- `browser-use/` is an ignored dependency checkout with separate Git history.
  Do not modify it unless the task explicitly targets browser-use.
- `.wasp/` contains ignored environments, checkpoints, logs, and raw campaign
  artefacts. Completed and active checkpoints are evidence.
- `sentinel/data/` contains local runtime state, browser profiles, and traces.
- `thesis/` is user-owned thesis work. Preserve unrelated source and output,
  and read `thesis/AGENTS.md` before editing it.

Never add credentials, private host details, virtual environments, model
weights, browser profiles, raw page captures, screenshots, or full campaign
directories to Git. Track reproducible code, configuration, provenance, and
compact curated result summaries only.

## Working rules

1. Run `git status --short` before editing and preserve unrelated work.
2. Read the implementation, nearby tests, and task-relevant documentation.
3. Make the smallest change that preserves security and experiment contracts.
4. Do not weaken tests, redaction, audit coverage, or security invariants to
   make a change pass.
5. Keep mirrored boundaries synchronized. Python event changes may require
   `sentinel/extension/src/shared/types.ts`; policy changes may require schema,
   documentation, fixtures, and evaluation updates.
6. Ask before guessing when uncertainty could materially change intent,
   security posture, experimental validity, a research claim, or thesis
   structure.

## Security invariants

- Treat the model, DOM, screenshots, downloads, extracted text, and tool
  results as untrusted.
- Evaluate every proposed action immediately before privileged execution.
- Keep non-web URL suffixes opaque at model, event, Activity, and trace
  boundaries. In enforce mode, direct autonomous navigation accepts HTTP(S)
  and `about:blank`; other schemes fail closed before execution.
- Do not downgrade hard policy or sensitive-data-flow blocks into approvals.
- In enforce mode, recognized credentials, passwords, one-time codes, tokens,
  payment details, and private keys are human-only. Withhold the agent action;
  consent is the operator performing the step directly during takeover.
- Guard indexed sensitive fields, free-text `send_keys`, sensitive `evaluate`
  semantics, secret-looking upload paths, and bounded local upload text.
  Remote, missing, binary, oversized, or unreadable uploads hand over as
  unclassifiable. These deterministic checks are not universal DLP.
- Required authority fails closed on silence, timeout, cancellation, malformed
  input, and shutdown.
- Approval is explicit, narrow, expiring, run-local, and non-transferable.
- Every attempted action has exactly one attempted and one terminal audit
  record, including blocks, denials, timeouts, exceptions, and cancellations.
- Never expose or persist raw secrets, payment data, injection payloads, or
  unredacted parameters. Screenshots and model rationale are omitted from
  persistent traces by default.
- Browser screenshots are not model input in the interactive runner and are
  not sent to the extension. DOM sanitisation cannot clean pixel-only content.
- Keep localhost origin, consent-scope, and API validation intact. Localhost is
  an accepted thesis boundary, not same-user process isolation.

`PolicyEngine.evaluate(...)` is the central policy decision point. Avoid
parallel allow/block paths. Security-relevant changes need allowed and denied
tests, including timeout and cancellation where applicable.

The bounded HITL scope and evidence boundary are defined in
`sentinel/THESIS-STATUS.md` and `sentinel/THREAT-MODEL.md`. Do not call the
implemented workflow unfinished or turn technical validation into participant
claims.

## Evaluation integrity

- Never delete, overwrite, reset, or blindly rerun campaign checkpoints.
- Inspect artefacts, native scores, telemetry, and provenance before reporting
  completion or resuming interrupted work.
- Do not start remote, browser, GPU, or long-running benchmark runs unless the
  user explicitly requests them.
- Use a new immutable run tag whenever policy, participant mode, model or model
  settings, middleware, benchmark inputs, or scaffold changes.
- Never pool results across provenance changes or edit generated scores by
  hand.
- Label intermediate checkpoints provisional. Separate attempted,
  privileged-tool-executed, and native final attacker success.
- Low ASR alone is not security evidence; report model capability, utility,
  risky attempts and executions, and false blocks.
- Scripted `deny`, `none`, and deterministic `oracle` modes are benchmark
  controls, not human participants.
- Prefer matched off/enforce comparisons. Describe AgentDojo as controlled
  mechanism evidence and WASP as controlled browser-native transfer evidence,
  not deployment in the wild.
- Quantitative tables belong in `sentinel/EVALS.md`. Per-run records and the
  WASP ledger preserve detailed provenance; status and instruction files should
  route to them rather than duplicate them.

## Validation

Run targeted checks first, then the relevant broader gate:

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q sentinel/tests
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python sentinel/evals/security_benchmark.py sentinel/evals/fixtures/security-smoke.jsonl --pretty
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q sentinel/tests/test_wasp_campaign.py
bash sentinel/evals/wasp/run-wasp.sh preflight --offline
(cd sentinel/extension && npm run build)
```

Use the full Python suite for governance, policy, security, audit, trace,
approval, or shared evaluation changes. Use Python tests and the extension
build when a change crosses that boundary. For visual work, inspect the
rendered panel and dashboard; a successful build is not visual QA.

## Git hygiene and handoff

- Preserve unrelated modified and untracked files.
- Stage only files belonging to the requested change.
- Do not commit, push, rewrite history, or discard user work unless requested.
- Keep machine-specific values in ignored `.env` or `*.local.env` files and
  maintain only sanitized examples.
- Before handoff, inspect the scoped diff and run `git diff --check`.
- Summarize changed behaviour, checks run, and remaining unverified risk.
