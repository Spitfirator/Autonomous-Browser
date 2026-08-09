# Interface figure provenance

This file records how the browser-integrated and control-plane figures in
Chapter 4 were produced. It is a
reproducibility handoff, not a source of benchmark evidence.

## Evidence status

The whole-browser screenshots were captured on 2 and 5 August 2026 from
Sentinel's dedicated Chrome instance launched by `sentinel/start.sh`. The production
backend listened on port 8765 and the production extension supplied both the
side panel and in-page control layer. The active-run capture used the
repository's benign `fixtures/sentinel-browser-capture.html`, served only on
`127.0.0.1:18766`. It contains no account state, credential, private URL, or
external resource.

The active-run capture belongs to local run `4df00e0f`. It was taken while the
bounded read-only task was running and before its first model response, which
is why the panel shows zero calls and zero tokens.

The handover capture was taken on 5 August 2026 from local run `8d78c714`. It
uses the visually distinct `fixtures/sentinel-login-handover.html`, a synthetic
research-archive login with a prefilled `.test` account identifier and an empty
password field. The task asked the configured `gemini-3.1-flash-lite` model to
access a named document without guessing or entering the password. After
navigation, the model invoked `request_human_control` with a password-specific
reason. The image was taken while that server-owned request was pending; no
password was entered or submitted, and the task was stopped after capture.
This exercises a natural agent-initiated handover. It is not an operator-click
takeover and not evidence that the sensitive-input detector fired.

The unresolved-observation capture uses the visually distinct
`fixtures/sentinel-unresolved-observation.html`: a synthetic workspace-settings
interface with different navigation, layout, colour, and content. Local run
`0b0f1d3c` reproduced a benign detector-positive accessibility shape whose
signals appeared only in aggregate. Sanitisation was attempted but no bounded
region could be attributed safely (`status=unattributable`, one region
targeted, zero changed). Sentinel quarantined the observation, opened one
security incident, and made zero provider calls. The capture was taken while
that request was pending and the task was then stopped. The page contains no
attack payload, live token, account, private URL, or external service. This
exercises conservative uncertainty handling; it is not detector-accuracy or
benchmark evidence.

The completed Activity panel, policy configuration view, and bounded approval
card come from the isolated deterministic walkthrough served by
`scripts/serve-interface-walkthrough.py`. That helper uses the
production `PolicyEngine`, event models and `EventHub`, `ApprovalManager`,
`HandoverManager`, `TraceStore`, `HistoryStore`, REST/WebSocket API, compiled
extension bundle, and in-page control script with benign `.test` URLs and
redacted parameters. It starts no browser agent, makes no model call, and
starts or resumes no benchmark. Its state is temporary and its served bundle
is rewritten in memory from production port 8765 to isolated port 18765.

Together these captures document implemented interface behaviour. They are
not benchmark observations, usability evidence, or participant data.

The approval and Activity panels used together in Chapter 4 are independent
illustrations, not consecutive states of one run. The approval card belongs to
the walkthrough's live run `b1c2d3e4`; the completed Activity record belongs to
the separately seeded run `c0ffee12`. Their juxtaposition explains prospective
authority and retrospective accountability without claiming that one panel is
the recorded outcome of the other.

## Figure mapping

- Figure `fig:architecture` uses
  `figures/sentinel-runtime-architecture-v2.png`, an explanatory architecture
  diagram produced from the documented runtime and trust-boundary
  specification. Its labels and directed paths were checked against the
  implementation; it is not captured runtime or benchmark evidence.
- Figure `fig:unresolved-observation` uses the whole dedicated-Chrome security
  pause on the separate workspace-settings fixture. The red page boundary,
  in-page incident controls, side-panel incident card, and zero-call budget are
  one simultaneous live view.
- Figure `fig:handover-projection` uses the whole dedicated-Chrome handover
  capture on the research-archive login fixture. Its empty password field,
  page banner, recorded `request_human_control` action, and side-panel card are
  simultaneous projections of one server-owned request.
- Figure `fig:governed-run` uses the whole dedicated-Chrome active-run capture.
  Its page, page-level ownership control, and side panel are one simultaneous
  live view.
- Figure `fig:authority-audit-evidence` uses the deterministic bounded approval
  card and completed Activity record as two independent illustrative states.
- No capture contains a credential, private URL, raw injection payload,
  personal browser state, screenshot supplied to a model, or model rationale.

The whole-browser panels are exact application-window screenshots whose JPEG
capture output was format-converted to PNG without retouching. The Activity
and approval panels are rectangular crops produced with `ffmpeg`; the policy
view is a direct viewport capture of the same deterministic dashboard. Their
pixels were not generated or semantically altered. The policy capture remains
as supporting source material but is not included in the submitted manuscript.

## Reproduction

From the repository root:

```bash
python3 -m http.server 18766 --bind 127.0.0.1 \
  --directory thesis/fixtures
(cd sentinel && ./start.sh)

PYTHONPATH=sentinel:browser-use \
  browser-use/.venv/bin/python thesis/scripts/serve-interface-walkthrough.py
```

The first two commands reproduce the live page/extension relationship. The
helper exposes `/capture/manifest`, `/walkthrough`, the compiled UI under
`/ui/` (including `/ui/dashboard.html`), and the four deterministic
authority scenarios under `/capture/scenario/`. The policy capture selects
the Policies tab without changing a value. Stop both local servers after
capture. The live Sentinel runs remain only in ignored local runtime state; the
deterministic helper retains no state.

## SHA-256 manifest

```text
a39026c6ef396d36a0c03b7dcf1c0c5a5752e31026e2d0fb4de65e443fefe4af  scripts/serve-interface-walkthrough.py
c5983784418685972e20da4056a4a2add46cc186463f0e1c39e111b8fef17b14  figures/sentinel-runtime-architecture-v2.png
05fcae9cfd144111116dc1e4b033ef0bdfafecfd4343c53024d10b1529388e6f  fixtures/sentinel-browser-capture.html
819fbeb37a0c8c3aec4855372eb71bce72ed6ca5d06846704b14951612ce2f65  fixtures/sentinel-login-handover.html
741eb8ed7d05681343b48940327d375481ac2c6e9b4729cb28ca939fbd05f722  fixtures/sentinel-unresolved-observation.html
3c7e6e79152ce5292b2f8680ef68fb652a1586b1bc0a3c2c2b1bcda339852074  figures/interface-browser-and-panel-running-live.png
973d71cb30ad7c8aab71a495931e7d0e506db0422927f1137f100c9325207df7  figures/interface-browser-and-panel-password-handover-live.png
4e1b8d9cc94ce6bfe0773798dbf85e2fb145dd4a6792df9f2d240c8724270569  figures/interface-browser-and-panel-unresolved-live.png
64b063dad08b30163cd9d7a9617384fce73293da8abeddca3fad45b344d8de22  figures/interface-activity-detail-walkthrough.png
12c4d830a60f3868e39c6e2082b9cb0262fc803d37f5f394320ca939466716d8  figures/interface-policies-walkthrough.png
689990393e490a2b2173a7c6659deb5e597dcd364e6f501219a23ddbc6beb369  figures/interface-approval-walkthrough.png
```
