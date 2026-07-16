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
5. Human consent is explicit, narrow, expiring and non-transferable; silence,
   timeout, shutdown and malformed API input fail closed.
6. Monitoring must not become a second data leak: secrets and attacker payloads
   are not copied into events, traces or approval cards.

## Trust boundaries and actors

| Component / actor | Trust | Notes |
|---|---|---|
| Operator request and live steering | trusted authority | May authorize goals, but does not bypass configured hard blocks |
| Sentinel system policy and local config | trusted authority | Localhost policy edits apply at the next call/action |
| Browser-use agent model | untrusted decision maker | May hallucinate, be injected, retry denials or produce malformed actions |
| Page DOM, title, URL and screenshot | untrusted data | Includes ads, iframes, extensions and compromised first-party content |
| Downloads, extracted text and tool results | untrusted data | Can carry stored/second-order injections |
| Action parameters | tainted model output | Evaluated/redacted before they reach the real tool |
| Browser/tool implementation | privileged executor | Only called after an allow/approval verdict |
| Extension side panel | operator UI, not policy authority | API validates scope; a UI cannot mint consent by itself |
| Local trace/event consumers | honest-but-curious | Receive redacted values and per-run digests, not secrets |

## Threats and controls

| Threat | Primary controls |
|---|---|
| Indirect prompt injection in DOM/read results | system trust boundary, deterministic multi-signal detector, origin-scoped taint, fresh model warning, protected-sink enforcement |
| Injection hidden in an image/canvas | system boundary covers screenshots; high-impact actions remain risk-gated; see residual risks |
| Secret/API key/password exfiltration | recursive value/key classification, DOM password/OTP/payment-field semantics, destination trust list, default hard block, redacted audit |
| Local-file upload/exfiltration | `local_file_read` capability, elevated risk approval, existing static upload approval/block policies |
| Consequential click (purchase, publish, delete, transfer) | target-element semantics raise risk to approval threshold without prompting on ordinary clicks |
| Cross-origin exfiltration in a URL | origin transition + tainted query factors; high-confidence injected navigation is blocked |
| JavaScript/code execution | high base risk, adaptive approval; injected code sink is blocked at high confidence |
| Redirect/pop-up bypass of URL rules | browser-use navigation watchdog mirrors block/allow lists |
| Approval fatigue / rubber-stamping | risk threshold, Allow once, explicit bounded Allow similar, prompt budget, handoff/block escalation |
| Replaying or widening consent | HMAC-scoped run-local key, target origin/path and DOM semantics, action/capability/taint/category binding, exact digest for code/files/uploads, TTL/use cap, server-side scope validation |
| Secret leakage through monitoring | recursive redaction, URL query/fragment redaction, no injection payload events, keyed per-run digests, error type rather than raw exception, screenshots/reasoning omitted from disk by default |
| Action disappears from audit due to cancellation | `BaseException`/cancellation completion path; tests require paired attempt/completion records |
| Model retries a denied action | fail-closed result explicitly says not to retry; bounded prompt budget prevents an infinite approval loop |

## Decision and data-flow model

The trusted user request is the root authority. Browser observations are marked
`untrusted_web`; a detection adds `prompt_injection_suspected`; values add
`sensitive:<category>`; uploads add `local_file`. Actions expose capabilities
such as `page_write`, `data_disclosure`, `navigation`, `code_execution`, and
local-file read/write.

Static policy blocks and domain boundaries run first. Dynamic hard data-flow
blocks run before any approval rule, so an action cannot downgrade a hard block
to a user prompt. Medium/ambiguous risk is eligible for approval only when the
action has a side effect. Read-only inspection stays available so the agent can
recover or gather evidence without training the operator to approve reads.

## Residual risks and explicit non-claims

- Signature detection cannot prove a page is benign and will not recognize all
  novel/obfuscated attacks. Security comes from combining detection with
  source/sink controls, static domain policy and operator consent.
- Screenshot-only or canvas-rendered attacks are covered by the model's trust
  boundary but are not OCR-classified by the deterministic detector. A future
  benchmark may justify a separate local visual classifier; it should not send
  screenshots to an extra external service by default.
- Generic text fields do not reveal business semantics perfectly. Sentinel
  recognizes password/OTP/payment metadata and common consequential button
  language; applications should still configure sensitive domains and trusted
  data destinations.
- A compromised local process running as the same user can call the localhost
  API or alter files. Sentinel is an agent-governance layer, not an OS sandbox.
- Once an action is allowed, the browser/tool implementation and remote site may
  behave differently from their visible description (for example, a benign
  click handler can be replaced server-side). Navigation watchdogs and audit
  reduce impact/detectability but do not provide transactional isolation.

## Benchmark evidence

`evals/security_benchmark.py` accepts a stable JSONL adapter format and reports
detection precision/recall/FPR, side-effect containment, expected-verdict
accuracy and benign approval rate. Online agent benchmarks should additionally
measure task completion, attack success, paired-action audit coverage, prompts
per task, grant reuse, denial/timeout rate and human wait time from real traces.

`evals/agentdojo_native.py` additionally evaluates AgentDojo's native tool
names, arguments, environment objects and attacker/user oracles. Its exhaustive
ground-truth replay is component evidence, while `agent` mode is the end-to-end
model result. Reports label AgentDojo's injection oracle as
`attack_success_rate` because the upstream boolean is true when the attacker
goal succeeds; lower is better.
