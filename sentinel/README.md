# Sentinel

Control plane and **enforcement middleware** for [browser-use](../browser-use). One command
launches a dedicated Chrome window with the Sentinel side panel; every LLM call and every
browser action the agent takes flows through the governance layer, streams live to the
panel, and can be blocked or held for human approval.

```
Chrome (dedicated profile, launched by the backend)
 ├─ Sentinel extension: side panel (run/watch/approve) + dashboard (models/policies/activity)
 │    ⇅ REST + WebSocket  http://127.0.0.1:8765
 └─ driven over CDP by
Python backend (aiohttp)
 └─ AgentRunner → Agent(llm=GovernedLLM(ThrottledLLM(Chat*)), tools=GovernedTools)
                   └─ prompt boundary + taint/risk engine + PolicyEngine
                      + bounded ApprovalManager        ← the enforcement middleware
```

## Run it

```bash
cd sentinel
./start.sh
```

That builds the extension bundle if missing (first run: `npm install && npm run build`),
starts the backend on `127.0.0.1:8765`, and opens the dedicated Chrome window. The
Sentinel extension is auto-installed into that window via CDP; if Chrome ever refuses
(the flag/API landscape shifts by version), the window opens a one-time setup page with
copy-paste "Load unpacked" instructions - after that it persists in the profile forever.

Open the panel with the **Sentinel icon** in the Chrome toolbar (pin it via the puzzle
icon). Stop the server with `Ctrl-C` - the Chrome window intentionally stays open
(`keep_alive`); the next `./start.sh` reconnects to it instead of launching a new one.

Requirements: `uv` (uses `../browser-use`'s venv - zero extra Python deps), `node`/`npm`
for the extension build, Google Chrome, and a running Ollama server with the default
`qwen3.5-agentdojo:4b` profile (see `EVALS.md`). Gemini remains an optional governed
fallback. API keys live in `../browser-use/.env` (`GEMINI_API_KEY`, `GROQ_API_KEY`, …)
and can also be set from the dashboard.

## What's where

| Path | What |
|---|---|
| `server/main.py` | entrypoint: wiring + aiohttp on 127.0.0.1:8765 |
| `server/runner.py` | one Agent at a time; pause/resume/stop; step callbacks → events |
| `server/browser.py` | dedicated Chrome launch, reconnect, extension install ladder |
| `server/governance/` | **the middleware**: `governed_llm` (every model call), `governed_tools` (every action), `policy` (decision point), `approvals` (human gate), `handover` (human takeover), `throttle` (free-tier pacing) |
| `server/traces.py` | per-run audit traces: redacted events + meta; screenshot/reasoning retention is opt-in |
| `server/config.py` | pydantic config + `data/config.json` store; paths |
| `server/events.py` | WS event models + fan-out hub (mirrored in `extension/src/shared/types.ts`) |
| `extension/` | MV3 extension, React + Vite + TS; `dist/` is the unpacked bundle |
| `data/` | runtime state: config, history, traces, the persistent Chrome profile |
| `POLICY.md` / `policies/` | the policy schema + a shareable reference policy |
| `THREAT-MODEL.md` | trust boundaries, invariants, control mapping and residual risks |
| `THESIS-STATUS.md` | concise thesis handoff: implementation state, evidence map, supported claims and unfinished work |
| `EVALS.md` / `evals/` | canonical result ledger, evaluation protocol, AgentDojo campaigns and WASP browser-native adapter |
| `demo/` | `run_scenarios.py`: scripted allowed/blocked/approval/handoff demo runs |
| `share/` | generated share pack: traces, decision logs, screenshots |

## The middleware

`PolicyEngine.evaluate(action, params, url)` is the single decision point - extend here.
Schema + decision order: **[POLICY.md](POLICY.md)**. Metrics: **[EVALS.md](EVALS.md)**.

- **Domain allow/blocklist** - glob patterns (`*.bank.com`); checked per action against
  the navigation target or current page, and mirrored into browser-use's SecurityWatchdog
  as a second net. Live: dashboard edits apply to the *next action*, even mid-run.
- **Special-URL boundary** - enforce mode blocks direct autonomous navigation
  outside HTTP(S), except the browser recovery target `about:blank`. In every
  mode, non-web URL suffixes are replaced before model input, events, Activity
  or traces, so a `data:` address cannot smuggle an inline HTML document through
  navigation metadata.
- **Blocked actions** - removed from the LLM's toolbox at run start *and* refused at
  runtime; the agent gets an explanatory error and re-plans.
- **Approval gate** - by action type or by domain: the agent pauses inside the step; the
  side panel shows an approval card with countdown; deny/timeout returns an error the
  agent adapts to.
- **Sensitive domains → forced handoff** - first touch of a listed domain freezes the run
  and hands the browser to the human (same flow as `request_human_control`, but initiated
  by policy). After the human hands back, the agent may act there for the rest of the run.
- **Prompt-injection containment** - browser/read state, page-extraction input, and
  wrapped tool-result text are explicit untrusted-data boundaries. Multi-signal findings
  are origin-scoped, payload-free, reinforced at the system boundary and propagated
  into downstream action risk. High-confidence injection into
  navigation/input/upload/code/file sinks blocks. Detected current browser/read
  observations are sanitised and checked again; residual or unattributable content is
  quarantined from the model while the extension asks the operator to take over or
  stop. An unresolved bounded extraction or historical tool result is removed in full
  instead, avoiding nested timeout and replay loops.
- **Sensitive-data flow control** - in enforce mode, recognized credentials,
  one-time codes, tokens, private keys and payment data become direct
  human-takeover steps, even on a trusted destination. Detection covers
  recursive parameter patterns, live password/OTP/payment fields, free-text
  `send_keys`, sensitive `evaluate` code, secret-looking upload paths, and a
  bounded scan of authorized local text uploads. Uploads Sentinel cannot inspect
  safely are handed over too. Other sensitive flows outside
  `data_flow.trusted_domains` fail closed by policy; UI and traces receive only
  redacted values and per-run keyed digests. This is deterministic channel
  coverage, not universal DLP.
- **Fatigue-resistant approval** - ordinary clicks do not prompt. Consequential target
  semantics and other risk factors can hold an action. The operator chooses Allow once,
  a narrow/time-and-use-bounded Allow similar scope, or Deny. A per-run prompt budget
  collapses repeated cards into one direct handoff (or a hard block).
- **Modes** - `enforce` (default), `shadow` (log would-be verdicts, allow everything -
  and do not modify model input, for false-block/attack-success evals), `off`
  (no prompt boundary or verdict enforcement; redacted auditing remains).
- **Budgets** - max steps, max LLM calls per task (graceful stop at the limit, hard
  backstop two calls later), approval + takeover timeouts.
- **Agent-internal planning** - BrowserUse's structured planning/replanning loop
  is enabled. This is distinct from the proposed plan-authority feature, where a
  human would review a short pre-run contract covering the goal, expected sites/data,
  allowed and prohibited actions, likely human steps and stop conditions. That remains
  optional future HITL work.
- **DOM-only interactive perception** - browser screenshots are not sent to the model.
  An instruction rendered into pixels cannot be cleaned by DOM sanitisation. Screenshots
  are also omitted from the extension; optional local trace retention is a separate,
  explicit audit setting.
- **Full audit stream** - every decision is a WS `enforcement_decision` event (with
  policy-only `decision_ms` and full pre-action `enforcement_ms`); every model call a `llm_call` event with latency +
  tokens; every run is persisted to `data/traces/<run_id>/` (redacted events + meta
  with per-run enforcement metrics; special-URL payloads, screenshots and
  reasoning are omitted at rest by default).
- **Paired action audit** - every attempted action, including a policy refusal, timeout,
  exception or cancellation, emits start and completion records under one action ID with
  capabilities, taint, risk, verdict, outcome and duration—never raw secrets.

## The chat

The side panel is a conversation. One box does everything, depending on when you type:

- **Idle** → your message starts a task.
- **While the agent runs** → your message is *steering*: it's injected into the agent's
  very next thought as top-priority operator guidance ("use the cheapest option",
  "skip the wine"). Shown as an amber `steering` bubble.
- **After a task finishes** → your message is a *follow-up*: the agent gets a recap of
  what it just did plus your new request, and continues in the same browser session.

Agent steps stream in as chat bubbles (goal and redacted action chips); a typing
indicator shows while it thinks; the final answer arrives as a highlighted bubble.

## The in-page control layer

While the agent works, the controlled window shows a pulsing amber frame and a floating
pill - **Working on task · [Take over] [Open chat] [Stop]** - rendered by the extension's
content script on whatever page the agent is on. Real mouse/keyboard input is shielded
(swallowed) while the agent thinks, and released during the agent's own action windows;
**Take over** pauses the agent (pill flips to *You're in control · Give control back*),
after which the page is fully yours until you hand it back. The small ◉ toggle in the
panel header turns the in-page layer off - do that in your personal Chrome if you load
the extension there, since the agent only ever drives the dedicated window.

The interactive model is DOM-only, so neither this control layer nor page content
rendered only into screenshot pixels is sent to it.

## Human takeover (your turn)

The agent has a `request_human_control` tool and standing instructions to use it instead
of guessing whenever a step needs *you*: logins/credentials, one-time codes, CAPTCHAs,
payment, or personal details (postcodes, addresses). When it fires:

1. The run freezes inside the step and the in-page pill switches to an amber **"Your
   turn"** state with the agent's reason; the side panel shows the same takeover card
   with a countdown.
2. You do the step by hand in the browser - click, type, log in, whatever's needed.
3. Optionally type a note for the agent ("logged in, postcode is SW1A 1AA"), then hit
   **Done - continue** on the page pill (or **Give control back** in the panel).
4. The agent resumes from the *current* page state with your note in its context.

If nobody responds within the takeover timeout (default 15 min, Policies tab), or the
run is cancelled, the original action is not executed and the wait fails closed.

## Unresolved sanitisation incident

If Sentinel detects an injection in the current browser/read observation but cannot
safely remove all of it—or cannot map the finding to a narrow part of that observation—it
does not ask the model to resist a warning. It withholds that observation and pauses on
a persistent security incident in the extension:

1. The side panel and in-page control explain that untrusted content could not be
   cleaned safely. No attacker text is copied into the card.
2. The user takes control, checks or leaves the page, and either stops the task or marks
   the page ready to be checked again.
3. Giving control back is not approval of the held content. Sentinel discards the stale
   model call and captures a fresh browser observation before continuing.
4. Silence, timeout, cancellation, or shutdown stops the unsafe path without a model
   call.

After the run ends, Activity keeps a per-task **security pause** count and review time.
The count links to the incident lifecycle in that run's redacted log.

Page-extraction subcalls and persistent tool-result values cross the same detector and
sanitiser, but they are bounded inputs with different lifecycle constraints. If one
cannot be cleaned, Sentinel removes that whole value rather than starting an incident
inside BrowserUse's extraction timeout or repeatedly pausing on the same history item.

## Using the panel from your everyday Chrome

The extension also works in your personal Chrome as a remote control/monitor (the agent
still acts in its dedicated window): open `chrome://extensions`, enable **Developer mode**,
**Load unpacked** → select `sentinel/extension/dist`. Any `chrome-extension://` origin is
accepted by the localhost backend. Turn the in-page layer off there (◉ toggle in the panel
header) so your own browsing doesn't show the control pill. After rebuilding the extension
(`npm run build`), hit reload on `chrome://extensions` in both browsers.

## API (localhost only, Origin-checked)

`GET /api/status` · `POST /api/task {task, max_steps?}` · `POST /api/agent/{pause|resume|stop}`
· `GET|PUT /api/config` · `GET|PUT /api/keys` · `POST /api/approvals/{id} {approve, scope}`
· `GET /api/history` · `GET /api/actions` · `GET /ws` (events; first frame is a snapshot)

This local, origin-checked API is the intended boundary for the thesis prototype; there
is no remote deployment. A malicious process already running as the same OS user is
outside that boundary and could still call the API or alter local files.

## Development

- Backend only (no Chrome): `SENTINEL_NO_BROWSER=1 ./start.sh`
- Extension watch build: `cd extension && npm run dev`, then reload in `chrome://extensions`
- Allow non-extension origins (e.g. previewing `dist/` over http): `SENTINEL_DEV_ALLOW_ANY_ORIGIN=1`
- Port: `SENTINEL_PORT=…` (default 8765)
- Security/unit suite: `PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q sentinel/tests`
- Offline benchmark smoke run: `PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python sentinel/evals/security_benchmark.py sentinel/evals/fixtures/security-smoke.jsonl --pretty`
- Full AgentDojo v1 component/native replay: see [EVALS.md](EVALS.md#agentdojo-v1-full-tier-1-component-run); the compact reproducible result is `evals/agentdojo-v1-summary.json`.
- Browser-native WASP setup and resumable paired campaign: see
  [evals/wasp/README.md](evals/wasp/README.md); the complete thesis-ready result
  synthesis is [evals/wasp/results/README.md](evals/wasp/results/README.md).
  Its contract tests need no browser, Docker or GPU:
  `PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q sentinel/tests/test_wasp_campaign.py`.

Known quirks: `pause` takes effect after the in-flight step completes (upstream behavior,
it also prints a cosmetic "Press Enter" line in the server log). Profile persistence
relies on the `browser-use-user-data-dir-` marker in the profile path - re-check
`BrowserProfile._copy_profile()` if you upgrade browser-use past v0.13.x.
