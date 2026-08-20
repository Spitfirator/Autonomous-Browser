# Interface figure provenance

This file records the sources of the browser-integrated and control-plane
figures in Chapter 4. The screenshots document implementation behaviour, not
benchmark results.

## Source register

- `fig:architecture` uses `figures/sentinel-runtime-architecture-v2.png`, an
  explanatory diagram checked against the runtime and trust-boundary
  specification.
- `fig:governed-run` uses run `a0905831` and the benign local fixture
  `fixtures/sentinel-browser-capture.html`. It was captured from the production
  extension before the first model response.
- `fig:handover-projection` uses run `13845d5e` and
  `fixtures/sentinel-login-handover.html`. The model requested human control at
  an empty password field; no password was entered or submitted.
- `fig:unresolved-observation` uses run `d2390d03` and
  `fixtures/sentinel-unresolved-observation.html`. The detector-positive
  observation was unattributable, was quarantined, and produced zero provider
  calls.
- `fig:authority-audit-evidence` uses two stages of walkthrough run
  `b1c2d3e4` from `scripts/serve-interface-walkthrough.py`. The approval panel
  shows the `upload_file` request while it is held; the Activity panel records
  the same task and decision after the run. The helper exercises the production
  policy, authority, event, trace, history, REST/WebSocket, and compiled
  extension components with benign `.test` data and redacted parameters. The
  Activity capture shows the per-decision understanding control with both
  responses unset; it documents the instrument, not a participant response.

No capture contains a credential, private URL, raw injection payload, personal
browser state, screenshot supplied to a model, or model rationale. Figures
4.2--4.4 are the user's whole-window PNG captures. The approval and Activity
images are rectangular crops exported to PNG without retouching.

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
helper exposes its manifest, walkthrough, compiled UI, and deterministic
authority scenarios on port 18765. Stop both local servers after capture.

## SHA-256 manifest

```text
7e528883e8c63bc61fcffda7ed731b94d875caab1886f238b71b76ad3718f966  scripts/serve-interface-walkthrough.py
c5983784418685972e20da4056a4a2add46cc186463f0e1c39e111b8fef17b14  figures/sentinel-runtime-architecture-v2.png
ed62ba14bbeff51260feff3cdab046ad270678f345e379b2ec04efaa908945db  fixtures/sentinel-browser-capture.html
6bf553c3a99a179345c46e71140d4897d2913fd17594d8cb98c364f74514a724  fixtures/sentinel-login-handover.html
741eb8ed7d05681343b48940327d375481ac2c6e9b4729cb28ca939fbd05f722  fixtures/sentinel-unresolved-observation.html
d507b36a90cd36dfc71d0880e7621e6556dd41a684db7fb023c27002ece686c3  figures/interface-browser-and-panel-running-live.png
65e20010340957682d0e4962e21e0e5e3c1d69cc6d96d4dce8694de2f7ee1e77  figures/interface-browser-and-panel-password-handover-live.png
359b8278293ae0fdfd19836f065cabe7e0caf4e5384bbc125e91c1c76612d926  figures/interface-browser-and-panel-unresolved-live.png
843638eb826ebc47fc011bb6944c979d902f5255d8726a61e6aa935167479189  figures/interface-activity-detail-walkthrough.png
095b08ced4a4b57e7b5f6d11ad8f5f321021a7bd46fef7c0f8c01a764c1169f1  figures/interface-approval-walkthrough.png
```
