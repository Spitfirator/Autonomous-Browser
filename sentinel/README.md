# Sentinel

Sentinel is a research prototype that places independent governance between an
untrusted browser agent and its privileged executor. It mediates model input
and proposed actions, supplies bounded human authority, and records redacted
audit evidence. It does not claim to solve prompt injection or provide a
deployment-ready browser sandbox.

```text
Dedicated Chrome
├─ Sentinel extension: side panel, dashboard, and in-page controls
│  ⇅ REST + WebSocket on http://127.0.0.1:8765
└─ BrowserUse agent over CDP
   ├─ GovernedLLM: untrusted-observation boundary
   └─ GovernedTools: pre-execution policy and authority boundary
```

## Start

```bash
cd sentinel
./start.sh
```

The script starts the loopback backend, builds the extension when needed, and
opens or reconnects to a dedicated Chrome profile. Open the side panel from the
Sentinel toolbar icon. `Ctrl-C` stops the backend; Chrome remains available for
the next restart.

Requirements:

- `uv` and the adjacent `browser-use` checkout with its virtual environment;
- Node.js/npm for the extension build;
- Google Chrome; and
- Ollama with the configured local model, or a supported provider key stored in
  the ignored browser-use environment file or dashboard.

The default local profile is defined in `server/config.py`. Do not place API
keys or machine-specific provider settings in tracked files.

## Runtime ownership

| Path | Responsibility |
|---|---|
| `server/runner.py` | Browser-agent lifecycle, steering, pause, and stop |
| `server/governance/governed_llm.py` | Observation boundary and model-call governance |
| `server/governance/governed_tools.py` | Action mediation immediately before execution |
| `server/governance/policy.py` | Central policy decision point |
| `server/governance/approvals.py` | Narrow approval lifecycle |
| `server/governance/handover.py` | Human steps and unresolved-observation incidents |
| `server/traces.py`, `server/history.py` | Redacted audit and run summaries |
| `server/api.py`, `server/events.py` | Loopback API and mirrored event contract |
| `extension/` | Side panel, dashboard, and in-page control projections |
| `data/` | Ignored configuration, profiles, history, and traces |

`PolicyEngine.evaluate(...)` is the single policy decision point. The policy
behavior and precedence are documented in [`POLICY.md`](POLICY.md); the compact
field reference is [`policies/POLICY-SCHEMA.md`](policies/POLICY-SCHEMA.md).
Security objectives, residual risks, and non-claims belong in
[`THREAT-MODEL.md`](THREAT-MODEL.md).

## Governed workflow

- Browser/read observations, extraction values, downloads, and wrapped tool
  results are untrusted. Detected regions are sanitised and checked again.
- An unresolved current browser/read observation is withheld and opened as an
  operator incident. Unresolved bounded extraction/history values are removed
  in full.
- Every proposed privileged action is re-evaluated against the live policy and
  browser context immediately before execution.
- Hard policy violations remain blocks. Recognized human-only values and
  unclassifiable uploads withhold the agent action and hand the browser to the
  operator.
- Approval is explicit, narrow, expiring, run-local, and revalidated against
  current context before execution.
- Every attempted action receives one attempted and one terminal redacted audit
  record, including denial, timeout, cancellation, exception, and shutdown.

The interactive model is DOM/text-only, and the extension receives no page
screenshots or raw page titles. Optional screenshot and model-reasoning flags
control local trace retention only. These deterministic controls are not
universal DLP and do not cover instructions rendered only in pixels.

## Operator interface

The side-panel composer starts a task while idle, steers the next agent step
while running, and starts a contextual follow-up after completion. The in-page
control identifies when the agent owns the browser and lets the operator take
over or stop.

Approval cards resolve a single held action. Takeover cards transfer the live
browser to the operator for a direct human step. A sanitisation incident is a
different fail-closed state: the held observation is never approved, and
returning control triggers a fresh observation before the model continues.
Silence, timeout, cancellation, and shutdown do not authorize pending work.

## Configuration and API

Dashboard policy edits apply to the next action, including mid-run. The API is
loopback-only and origin-checked:

```text
GET /api/status
POST /api/task
POST /api/agent/{pause|resume|stop}
GET|PUT /api/config
GET|PUT /api/keys
POST /api/approvals/{id}
GET /api/history
GET /api/actions
GET /ws
```

Loopback is the accepted local thesis boundary, not same-user process
isolation. A compromised process under the same OS account may still call the
API or alter local files.

## Development and validation

```bash
# Backend without launching Chrome
SENTINEL_NO_BROWSER=1 ./start.sh

# Python security and governance suite
PYTHONPATH=sentinel:browser-use \
  browser-use/.venv/bin/pytest -q sentinel/tests

# Offline benchmark contract smoke
PYTHONPATH=sentinel:browser-use \
  browser-use/.venv/bin/python sentinel/evals/security_benchmark.py \
  sentinel/evals/fixtures/security-smoke.jsonl --pretty

# Extension build
(cd sentinel/extension && npm run build)
```

For extension watch mode, run `npm run dev` under `extension/` and reload the
unpacked extension. The default port is `8765`; override it with
`SENTINEL_PORT`. Use `SENTINEL_DEV_ALLOW_ANY_ORIGIN=1` only for deliberate
local preview work.

## Research evidence

- [`EVALS.md`](EVALS.md) is the canonical human-readable methodology and
  quantitative result ledger.
- [`evals/wasp/README.md`](evals/wasp/README.md) defines the browser-native
  evaluation and reproducibility contract.
- [`evals/wasp/results/README.md`](evals/wasp/results/README.md) indexes admitted
  WASP records and their immutable provenance.
- [`THESIS-STATUS.md`](THESIS-STATUS.md) contains the thesis argument, evidence
  route, and supported claim boundary without duplicating result tables.

Completed rows remain tied to their recorded code, policy, model, benchmark,
and scaffold. Do not use current implementation documentation to widen an
older result or pool changed provenance.
