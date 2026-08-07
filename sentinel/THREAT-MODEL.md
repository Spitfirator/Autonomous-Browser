# Sentinel enforcement threat model

## Security objectives

Sentinel must keep a browser agent inside the operator's intent even when a
website is malicious, compromised, or contains third-party content. The core
invariants are:

1. Every proposed tool action is evaluated immediately before execution.
2. Every attempted action has a privacy-preserving start and terminal audit
   record, including blocks, approval timeouts, exceptions and cancellations.
3. Website/file/tool content is data, never an authority source.
4. Sensitive data cannot move into an untrusted sink merely because page text
   or the model requested it.
5. In enforce mode, recognized passwords/credentials, one-time codes, access
   tokens, payment values, private keys and secret placeholders are human-only.
   The agent action is withheld and control is handed over unless a
   higher-priority hard block refuses it outright; it is never downgraded to an
   approval card.
6. Human consent is explicit, narrow, expiring and non-transferable; silence,
   timeout, shutdown and malformed API input fail closed.
7. Monitoring must not become a second data leak: secrets and attacker payloads
   are not copied into events, traces or approval cards.
8. Sanitisation is successful only after attributable content changed and
   re-detection on the resulting observation is clean. A residual or
   unattributable current browser/read observation is quarantined before the
   model call, escalated to the operator and replaced with a fresh observation
   after resolution. An unresolved bounded extraction/history value is removed
   in full.

## Trust boundaries and actors

| Component / actor | Trust | Notes |
|---|---|---|
| Operator request and live steering | trusted authority | May authorize goals, but does not bypass configured hard blocks |
| Sentinel system policy and local config | trusted authority | Localhost policy edits apply at the next call/action |
| Browser-use agent model | untrusted decision maker | May hallucinate, be injected, retry denials or produce malformed actions |
| Page DOM/text, title and URL | untrusted data | Includes ads, iframes, extensions and compromised first-party content |
| Page screenshot pixels | excluded from the normal model/UI path | Interactive agents use `use_vision=false`; optional local trace retention does not make pixels trusted |
| Downloads, extracted text and tool results | untrusted data | Can carry stored/second-order injections |
| Action parameters | tainted model output | Evaluated/redacted before they reach the real tool |
| Browser/tool implementation | privileged executor | Only called after an allow/approval verdict |
| Extension side panel | operator UI, not policy authority | API validates scope; a UI cannot mint consent by itself; screenshots and raw page titles are not sent to it |
| Local trace/event consumers | honest-but-curious | Receive redacted values and per-run digests, not secrets |
| Other processes running as the same OS user | outside the trusted local-control boundary | Loopback binding is accepted for the non-deployed thesis setup, but is not same-user process isolation |

## Threats and controls

| Threat | Primary controls |
|---|---|
| Indirect prompt injection in DOM/read/extraction/tool results | system trust boundary, deterministic multi-signal detector, origin-scoped taint, policy-controlled targeted sanitisation, post-sanitisation re-detection, protected-sink enforcement |
| Partial, failed or over-broad sanitisation | current browser/read observation: pre-model quarantine, persistent operator incident and fresh observation; bounded extraction/history value: whole-value removal; both fail closed before a model sees unresolved content |
| Injection hidden in an image/canvas | screenshots are excluded from the normal model path; visual/canvas attacks remain outside evaluated coverage |
| Secret/API key/password exfiltration | recursive value/key classification, DOM password/OTP/payment-field semantics, guarded free-text keystrokes and page-evaluation semantics, direct human takeover for recognized values regardless of trusted destination/configured approval, redacted audit |
| Local-file upload/exfiltration | `local_file_read` capability, secret-looking path checks, bounded scan of authorized local UTF-8 text, content-bound approval scope; remote/missing/binary/oversized/unreadable files hand over as unclassifiable |
| Consequential click (purchase, publish, delete, transfer) | target-element semantics raise risk to approval threshold without prompting on ordinary clicks |
| Cross-origin exfiltration in a URL | origin transition + tainted query factors; high-confidence injected navigation is blocked |
| Inline content or code hidden in a special URL | direct autonomous navigation is limited to HTTP(S) plus `about:blank`; non-web URL suffixes such as `data:`, `javascript:`, `blob:` and `file:` are withheld from model metadata, events, Activity and traces |
| JavaScript/code execution | high base risk, adaptive approval; injected code sink is blocked at high confidence |
| Redirect/pop-up bypass of URL rules | browser-use navigation watchdog mirrors block/allow lists |
| Approval fatigue / rubber-stamping | risk threshold, Allow once, explicit bounded Allow similar, prompt budget, handoff/block escalation |
| Replaying or widening consent | HMAC-scoped run-local key, target origin/path and DOM semantics, action/capability/taint/category binding, exact digest for code/files/uploads, TTL/use cap, server-side scope validation |
| Page/policy changes while approval is pending | post-approval URL/DOM/policy/risk refresh; execute only when now allowed or the same narrow scope remains valid |
| Stop races with an approval or handoff completion | run-local cancellation signal checked before accepting authority and immediately before privileged execution; one terminal cancelled audit and no scope grant |
| Domain rules skipped because current URL is unavailable | protected page actions fail closed while enforce-mode domain-sensitive policy is active |
| Secret leakage through monitoring | recursive redaction, HTTP(S) query/fragment redaction, complete non-web URL suffix redaction, no injection payload events, keyed per-run digests, error type rather than raw exception, screenshots/reasoning omitted from disk by default |
| Action disappears from audit during preflight/cancellation | attempted audit precedes fallible URL/DOM/risk/policy work; every path receives exactly one terminal record, including explicit cancellation |
| Model retries a denied action | fail-closed result explicitly says not to retry; bounded prompt budget prevents an infinite approval loop |

## Decision and data-flow model

The trusted user request is the root authority. Browser observations are marked
`untrusted_web`; a detection adds `prompt_injection_suspected`; values add
`sensitive:<category>`; uploads add `local_file`. Actions expose capabilities
such as `page_write`, `data_disclosure`, `navigation`, `code_execution`, and
local-file read/write.

When `browser_sanitize` is enabled, detected browser/read observations,
page-extraction inputs, and wrapped tool-result values are rewritten only
inside their untrusted regions before the model call. Removing some text is
not sufficient: Sentinel extracts what the model will actually receive and
runs detection again. A sanitisation outcome is `removed` only when at least
one region changed and re-detection is clear. Partial removal is `residual`; a
finding that cannot be safely mapped to a region is `unattributable`.

Every attempt emits privacy-preserving branch and outcome telemetry. After
confirmed clean removal, `alert_after_sanitize=false` continues without a
model-facing warning; explicit `true` preserves the historical post-removal
warning as a provenance ablation. A `residual` or `unattributable` current
browser/read observation is never passed onward with a warning: Sentinel
withholds it before the LLM call, pauses on a `security_incident` handover and
exposes only redacted origin, severity and status to the operator. Returning
control means “obtain a fresh observation,” not “approve the quarantined
content.” Operator text is not injected into the model for this incident path.
Timeout, cancellation and shutdown fail closed. A bounded
`webpage_content` extraction or persistent wrapped tool result cannot safely
use that lifecycle: BrowserUse gives extraction subcalls a shorter timeout and
keeps history results after a page refresh. Sentinel therefore replaces the
complete unresolved bounded value with a fixed marker, preventing nested
timeouts and incident loops. Detection also leaves origin-scoped taint
available to the action policy.

Static policy blocks and allowlist boundaries run first. Dynamic hard
data-flow blocks and recognized human-only takeover decisions run before a
generic sensitive-domain handoff or any approval rule, so detected
password/one-time-code/token/payment/private-key flows cannot be converted into
agent permission by `sensitive_data_verdict="approve"` or a trusted
destination. The operator may consent by taking control and performing the
step directly.
Medium/ambiguous risk is eligible for approval only when the action has a side
effect. Read-only inspection stays available so the agent can recover or gather
evidence without training the operator to approve reads.

This classification is deliberately conservative but not complete data-loss
prevention. It recognizes known value/key patterns and guarded action
semantics; a semantically secret value with no recognizable marker can still
be missed. Local upload inspection is limited to 256 KiB of authorized UTF-8
text. Files outside that boundary are handed to the operator, not declared
clean.

Approval authority is checked again at the execution boundary. After explicit
approval or a matching bounded grant, Sentinel re-fetches the current URL and
DOM target, reloads policy, recalculates risk and re-evaluates the action. It
executes only if the refreshed policy allows it or the same narrow scope remains
valid; any changed, unavailable or newly forbidden context is recorded and
fails closed.

The ordinary interactive agent receives the text/DOM observation path with
`use_vision=false`. BrowserUse screenshot persistence is discarded, page
screenshots and raw titles are stripped from WebSocket/replay data, and the
extension displays neither. If the operator explicitly enables
`store_screenshots`, a frame may be written to the local trace only; that does
not expose it to the model or extension.

## Residual risks and explicit non-claims

- Signature detection cannot prove a page is benign and will not recognize all
  novel/obfuscated attacks. Security comes from combining detection with
  source/sink controls, static domain policy and operator consent.
- Targeted sanitisation is best-effort. It can fail to attribute a finding,
  leave detector-positive content, or remove legitimate nearby content.
  Quarantine or bounded whole-value removal prevents a known unresolved input
  reaching the model, but cannot prove that a later fresh observation is
  benign or that a missed detector signal was absent.
- Screenshot-only or canvas-rendered attacks are not analyzed by the
  deterministic detector and are outside current evaluated coverage. Disabling
  vision removes that injection channel from the normal model input but may
  also remove visual-only task information. Any visual model-input path would
  require its own filtering and evaluation.
- Generic text fields do not reveal business semantics perfectly. Sentinel
  recognizes password/OTP/payment metadata and common consequential button
  language; applications should still configure sensitive domains and trusted
  data destinations.
- The control API is intentionally loopback-only for this local, non-deployed
  thesis artefact. That is an accepted scope assumption, not proof that all
  activity or model-provider traffic remains on-device. A compromised process
  running as the same OS user can call the localhost API or alter files;
  Sentinel does not provide same-user process isolation or an OS sandbox.
- Once an action is allowed, the browser/tool implementation and remote site may
  behave differently from their visible description (for example, a benign
  click handler can be replaced server-side). Navigation watchdogs and audit
  reduce impact/detectability but do not provide transactional isolation.
- Direct agent `navigate` calls reject non-web schemes, but a page can still
  initiate navigation through its own script or click handler. If that happens,
  the URL-carried suffix remains withheld and the resulting DOM stays inside
  the ordinary untrusted-observation boundary; this is not a general browser
  content sandbox.
- The bounded HITL workflow is implemented, including approval, operator and
  agent-requested takeover, policy-forced human steps, unresolved-observation
  incidents, cancellation, audit, and extension projections. It has not been
  evaluated as a participant study, so Sentinel makes no measured claim about
  human comprehension, trust, workload, fatigue, usability, or
  rubber-stamping.

## Evidence boundary

[`EVALS.md`](EVALS.md) is the canonical human-readable result ledger; curated
per-run files preserve exact model, policy, middleware, benchmark, participant
mode, and scaffold provenance. AgentDojo supplies controlled mechanism and
end-to-end evidence. WASP supplies controlled browser-native transfer and
limitation evidence. Neither is deployment in the wild.

Frozen rows measure only their recorded implementation. Do not infer that a
current mechanism was exercised by an older trajectory, rewrite a completed
row, or pool changed provenance. A new quantitative claim requires the
corresponding validation artefact or a new immutable run tag.

Report legitimate utility, secure utility, native attack success, risky
attempts and executions, interventions, false blocks and provenance together.
Low ASR alone is not security evidence because an incapable or inactive agent
may also fail the attack.

`participant=deny`, `participant=none`, and deterministic
`participant=oracle` are benchmark controls, not people. Implementation tests
and walkthroughs can validate the authority protocol but cannot establish
human outcomes without participant evidence.
