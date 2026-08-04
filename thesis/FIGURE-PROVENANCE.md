# Interface figure provenance

This file records how the browser-integrated figures in Chapter 4 and the
supporting control-plane figure in Appendix A were produced. It is a
reproducibility handoff, not a source of benchmark evidence.

## Evidence status

The whole-browser screenshots were captured on 2 August 2026 from Sentinel's
dedicated Chrome instance launched by `sentinel/start.sh`. The production
backend listened on port 8765 and the production extension supplied both the
side panel and in-page control layer. The active-run and handover captures used
the repository's benign `fixtures/sentinel-browser-capture.html`, served only
on `127.0.0.1:18766`. It contains no account state, credential, private URL, or
external resource.

The active-run capture belongs to local run `4df00e0f`. It was taken while the
bounded read-only task was running and before its first model response, which
is why the panel shows zero calls and zero tokens. The handover capture belongs
to local run `f233cfc4`: the benign task explicitly asked the configured
`gemini-3.1-flash-lite` model to invoke `request_human_control`, and the image
was taken after that single call while the request was pending. The task was
stopped after capture. This exercises the implemented handover protocol; it is
not evidence that the sensitive-input detector fired.

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

The completed Activity panel and bounded approval card come from the isolated
deterministic walkthrough served by
`scripts/serve-interface-walkthrough.py`. That helper uses the
production `PolicyEngine`, event models and `EventHub`, `ApprovalManager`,
`HandoverManager`, `TraceStore`, `HistoryStore`, REST/WebSocket API, compiled
extension bundle, and in-page control script with benign `.test` URLs and
redacted parameters. It starts no browser agent, makes no model call, and
starts or resumes no benchmark. Its state is temporary and its served bundle
is rewritten in memory from production port 8765 to isolated port 18765.

Together these captures document implemented interface behaviour. They are
not benchmark observations, usability evidence, or participant data.

## Figure mapping

- Figure `fig:architecture` is a source-native TikZ diagram in
  `chapters/04-design.tex`; it is explanatory artwork rather than captured
  runtime evidence.
- Figure `fig:unresolved-observation` uses the whole dedicated-Chrome security
  pause on the separate workspace-settings fixture. The red page boundary,
  in-page incident controls, side-panel incident card, and zero-call budget are
  one simultaneous live view.
- Figure `fig:handover-projection` uses the whole dedicated-Chrome handover
  capture. Its page banner and side-panel card are simultaneous projections of
  one server-owned request.
- Figure `fig:governed-run` uses the whole dedicated-Chrome active-run capture.
  Its page, page-level ownership control, and side panel are one simultaneous
  live view.
- Figure `fig:appendix-interface-evidence` uses the deterministic completed
  Activity record and bounded approval card.
- No capture contains a credential, private URL, raw injection payload,
  personal browser state, screenshot supplied to a model, or model rationale.

The whole-browser panels are exact application-window screenshots whose JPEG
capture output was format-converted to PNG without retouching. The Activity
and approval panels are rectangular crops produced with `ffmpeg`. Pixels were
not generated or semantically altered. Additional page-only and
authority-state captures are retained beside the included images for audit;
the appendix includes one purposeful prospective/retrospective pair rather
than a screenshot gallery.

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
`/ui/`, and the four deterministic authority scenarios under
`/capture/scenario/`. Stop both local servers after capture. The live Sentinel
runs remain only in ignored local runtime state; the deterministic helper
retains no state.

## SHA-256 manifest

```text
a39026c6ef396d36a0c03b7dcf1c0c5a5752e31026e2d0fb4de65e443fefe4af  scripts/serve-interface-walkthrough.py
05fcae9cfd144111116dc1e4b033ef0bdfafecfd4343c53024d10b1529388e6f  fixtures/sentinel-browser-capture.html
741eb8ed7d05681343b48940327d375481ac2c6e9b4729cb28ca939fbd05f722  fixtures/sentinel-unresolved-observation.html
3c7e6e79152ce5292b2f8680ef68fb652a1586b1bc0a3c2c2b1bcda339852074  figures/interface-browser-and-panel-running-live.png
070ef39918f0e5e69d28d6fc612cf42b5b3ffe80fcfd8edff49feee7298bf6f5  figures/interface-browser-and-panel-handover-live.png
4e1b8d9cc94ce6bfe0773798dbf85e2fb145dd4a6792df9f2d240c8724270569  figures/interface-browser-and-panel-unresolved-live.png
64b063dad08b30163cd9d7a9617384fce73293da8abeddca3fad45b344d8de22  figures/interface-activity-detail-walkthrough.png
689990393e490a2b2173a7c6659deb5e597dcd364e6f501219a23ddbc6beb369  figures/interface-approval-walkthrough.png
```
