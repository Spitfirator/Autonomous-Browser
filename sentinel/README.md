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

## Reproducible setup

Run the commands in this README from the repository root: the directory that
contains `sentinel/` and the adjacent `browser-use/` checkout.

Requirements:

- Python 3.11 or later and [`uv`](https://docs.astral.sh/uv/);
- Node.js/npm;
- Google Chrome; and
- either Ollama with a compatible local model or an API key for a supported
  provider.

Sentinel was developed against BrowserUse 0.13.2 at commit
`c8e6e8f0fe617564687895702c2338967293b309`. If the adjacent checkout and its
virtual environment are not already present, create them before installing the
extension dependencies:

```bash
git clone https://github.com/browser-use/browser-use.git browser-use
git -C browser-use checkout c8e6e8f0fe617564687895702c2338967293b309
cp sentinel/dependencies/browser-use-0.13.2.uv.lock browser-use/uv.lock
(cd browser-use && uv sync --locked --extra core)
(cd sentinel/extension && npm ci && npm run build)
```

The pinned BrowserUse commit ignores its generated `uv.lock`, so Sentinel
includes the validated lock snapshot used by this submission under
`sentinel/dependencies/`. Together with the extension's `package-lock.json`, it
fixes the Python and Node dependency versions. The BrowserUse checkout has
separate Git history and is intentionally not committed inside this repository.

### Model provider and API keys

The default provider is local Ollama, which requires no API key. Ensure the
model selected in Sentinel's dashboard is installed locally before starting a
task. Alternatively, select Gemini, Groq, OpenAI, Anthropic, or OpenRouter and
supply your own provider key.

The preferred route is to enter the key once in the dashboard's Models page.
The dashboard sends it over the loopback API to the backend, which stores it in
the ignored `browser-use/.env` file. The API subsequently exposes only whether
each supported key is present; it does not return the saved value. A key can
instead be added manually, using the appropriate variable name:

```dotenv
OPENAI_API_KEY=replace-with-your-own-key
# GEMINI_API_KEY=replace-with-your-own-key
# GOOGLE_API_KEY=replace-with-your-own-key
# GROQ_API_KEY=replace-with-your-own-key
# ANTHROPIC_API_KEY=replace-with-your-own-key
# OPENROUTER_API_KEY=replace-with-your-own-key
```

Never commit `browser-use/.env`, a real key, or machine-specific provider
settings. Do not place a key in the extension source, its manifest, or its
build configuration. The extension does not persist provider credentials;
model calls are made by the local Sentinel backend.

### Start Sentinel and Chrome

```bash
./sentinel/start.sh
```

The launcher starts the loopback backend, builds the extension if its bundle is
missing, and opens or reconnects to a dedicated Chrome profile. On Chromium
builds that accept `--load-extension`, the unpacked extension loads
automatically. Branded Chrome 137 and later may require this one-time step in
the dedicated window:

1. Open `chrome://extensions` and enable **Developer mode**.
2. Select **Load unpacked** and choose `sentinel/extension/dist` from this
   checkout.
3. Return to the Sentinel setup page; it confirms when the extension has
   connected.
4. Open the side panel from the Sentinel toolbar icon.

The extension remains installed in Sentinel's ignored, dedicated Chrome
profile. `Ctrl-C` stops the backend; Chrome remains available for the next
restart.

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
| `extension/` | Operator-facing task, control, policy, approval, handover, and redacted projection UI |
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

Dashboard policy edits apply to the next action, including mid-run. The main
operator-facing routes are below; health and extension-setup probes are omitted:

```text
GET /api/status
POST /api/task
POST /api/message
POST /api/agent/{pause|resume|stop}
POST /api/agent/reset
GET|POST /api/conversations
GET /api/conversations/{id}
POST /api/conversations/{id}/activate
GET|PUT /api/config
GET|PUT /api/keys
POST /api/approvals/{approval_id}
POST /api/handover/{handover_id}/complete
GET /api/history
GET /api/traces/{run_id}/{decisions|events}
POST /api/traces/{run_id}/decisions/{seq}
GET /api/actions
GET /ws
```

The service binds to loopback. Most browser-origin requests are origin-checked;
originless local clients remain accepted, and handover completion accepts any
page origin when it presents the current opaque handover identifier so the
in-page control can return the browser. These are accepted local-prototype
boundary choices, not same-user process isolation. A compromised process under
the same OS account may still call the API or alter local files.

## Reproducing the validation

The following gate is deterministic and does not require a provider key, a
running model, Chrome, Docker, or a GPU. Run every command from the repository
root:

```bash
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

Accept the gate only if all three commands exit successfully: pytest reports
no failures, the security smoke completes, and the extension build produces
`sentinel/extension/dist/manifest.json`. The Python suite includes the WASP
campaign and aggregate-replication contract tests without requiring the
external WASP environment. Exact test totals are deliberately not stated here
because they change as the suite grows.

The additional WASP source and evaluator preflight requires a one-time network
bootstrap. It downloads the pinned official source, a separate evaluator
environment, and Playwright Chromium into the ignored `.wasp/` directory:

```bash
bash sentinel/evals/wasp/bootstrap.sh
bash sentinel/evals/wasp/run-wasp.sh preflight --offline
```

After that bootstrap, the preflight itself runs without contacting benchmark
websites or a model. It checks the pinned adapter, attack matrix, reset
contract, and evaluator imports; it does not execute a campaign.

These checks reproduce the enforcement, audit, privacy, campaign-contract, and
extension-build evidence without making model-quality claims. They do not
re-run the thesis experiments. Full AgentDojo or WASP execution additionally
requires the recorded benchmark revisions, model/runtime configuration,
website state, and compute described in [`EVALS.md`](EVALS.md) and
[`evals/wasp/README.md`](evals/wasp/README.md). Raw WASP checkpoints and page
captures are ignored because they may contain private environment state; the
checked-in records preserve compact metrics and run metadata. A newly executed
campaign must use a new run tag and must not be pooled with a frozen result
whose configuration differs.

## Development

Run the backend without launching Chrome when working only on the API:

```bash
SENTINEL_NO_BROWSER=1 ./sentinel/start.sh
```

For extension watch mode, run `npm run dev` under `sentinel/extension/` and
reload the unpacked extension. The default port is `8765`; override it with
`SENTINEL_PORT`. Use `SENTINEL_DEV_ALLOW_ANY_ORIGIN=1` only for deliberate
local preview work.

## Research evidence

- [`EVALS.md`](EVALS.md) is the canonical human-readable methodology and
  quantitative result ledger.
- [`evals/wasp/README.md`](evals/wasp/README.md) defines the browser-native
  evaluation and reproducibility contract.
- [`evals/wasp/results/README.md`](evals/wasp/results/README.md) indexes admitted
  WASP records and their fixed run metadata.

Completed rows remain tied to their recorded code, policy, model, benchmark,
and scaffold. Do not use current implementation documentation to widen an
older result or pool changed configurations.
