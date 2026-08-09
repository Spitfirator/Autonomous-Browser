# Interface figure provenance

This file records the sources of the browser-integrated and control-plane
figures in Chapter 4. The screenshots document implementation behaviour, not
benchmark results.

## Source register

- `fig:architecture` uses `figures/sentinel-runtime-architecture-v2.png`, an
  explanatory diagram checked against the runtime and trust-boundary
  specification.
- `fig:governed-run` uses run `4df00e0f` and the benign local fixture
  `fixtures/sentinel-browser-capture.html`. It was captured from the production
  extension before the first model response.
- `fig:handover-projection` uses run `8d78c714` and
  `fixtures/sentinel-login-handover.html`. The model requested human control at
  an empty password field; no password was entered or submitted.
- `fig:unresolved-observation` uses run `0b0f1d3c` and
  `fixtures/sentinel-unresolved-observation.html`. The detector-positive
  observation was unattributable, was quarantined, and produced zero provider
  calls.
- `fig:authority-audit-evidence` uses the approval and Activity captures from
  `scripts/serve-interface-walkthrough.py`. The helper exercises the production
  policy, authority, event, trace, history, REST/WebSocket, and compiled
  extension components with benign `.test` data and redacted parameters.

No capture contains a credential, private URL, raw injection payload, personal
browser state, screenshot supplied to a model, or model rationale. Whole-window
captures were converted from JPEG to PNG without retouching; the approval and
Activity images are rectangular crops.

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
a39026c6ef396d36a0c03b7dcf1c0c5a5752e31026e2d0fb4de65e443fefe4af  scripts/serve-interface-walkthrough.py
c5983784418685972e20da4056a4a2add46cc186463f0e1c39e111b8fef17b14  figures/sentinel-runtime-architecture-v2.png
05fcae9cfd144111116dc1e4b033ef0bdfafecfd4343c53024d10b1529388e6f  fixtures/sentinel-browser-capture.html
819fbeb37a0c8c3aec4855372eb71bce72ed6ca5d06846704b14951612ce2f65  fixtures/sentinel-login-handover.html
741eb8ed7d05681343b48940327d375481ac2c6e9b4729cb28ca939fbd05f722  fixtures/sentinel-unresolved-observation.html
3c7e6e79152ce5292b2f8680ef68fb652a1586b1bc0a3c2c2b1bcda339852074  figures/interface-browser-and-panel-running-live.png
973d71cb30ad7c8aab71a495931e7d0e506db0422927f1137f100c9325207df7  figures/interface-browser-and-panel-password-handover-live.png
4e1b8d9cc94ce6bfe0773798dbf85e2fb145dd4a6792df9f2d240c8724270569  figures/interface-browser-and-panel-unresolved-live.png
64b063dad08b30163cd9d7a9617384fce73293da8abeddca3fad45b344d8de22  figures/interface-activity-detail-walkthrough.png
689990393e490a2b2173a7c6659deb5e597dcd364e6f501219a23ddbc6beb369  figures/interface-approval-walkthrough.png
```
