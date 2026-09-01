# Sentinel policy behavior

Every proposed action passes through one policy object before privileged
execution. The object lives under `policies` in `sentinel/data/config.json` and
can be edited from the dashboard or applied programmatically. From the
repository root:

```bash
curl -X PUT http://127.0.0.1:8765/api/config \
     -H 'Content-Type: application/json' \
     -d @sentinel/policies/reference-policy.json
```

Edits apply to the next governed action, including mid-run. The complete field
shape, validation constraints, and example policy are in
[`policies/POLICY-SCHEMA.md`](policies/POLICY-SCHEMA.md). This file owns
decision precedence and runtime semantics.

Every domain-list entry (blocklist, allowlist, approval, sensitive) is matched
against a URL's **host** with these four shapes, from broadest to most specific:

| Entry | Means | Blocks / matches |
|---|---|---|
| `facebook` | **keyword** - host *contains* the word | `facebook.com`, `www.facebook.com`, `m.facebook.com`, `business.facebook.net`, even `notfacebook.com` |
| `facebook.com` | **domain** - that domain + its subdomains | `facebook.com`, `www.facebook.com`; **not** `notfacebook.com` |
| `*.facebook.com` | **glob** on the host | subdomains + apex |
| `https://facebook.com` | **scheme + host** | that scheme and host; ports are ignored |

A bare word (no dot) is the broadest form - use it when you want to block a
service however the agent spells the URL. It matches the **host only**, so
`duckduckgo.com/?q=facebook` (the word in a search query) is still allowed - the
agent can search, it just can't *reach* the site.

### Domain rules are enforced at the navigation layer

Domain rules aren't just checked when the agent calls `navigate`. The blocklist
is mirrored into browser-use's SecurityWatchdog as `prohibited_domains` (and an
allowlist, when set, as `allowed_domains`), which enforce at the browser's real
navigation events:

- **direct navigation** - blocked before it starts;
- **redirects** - a redirect that lands on a disallowed host is bounced to
  `about:blank`;
- **new tabs / pop-ups** - a disallowed tab is closed;
- **link clicks, JS navigation, switching search engines** - all caught the same
  way, because the net is on the navigation, not on the agent's chosen action.

The watchdog therefore applies the configured host boundary to search-result
clicks, redirects, and other navigation paths. The action-level check (rules
below) and this navigation net use the **same** matching, so the panel's
"Blocked" reason always matches what the browser enforces. (One precedence note:
if a domain is on both lists, the allowlist wins at the browser layer, while the
`PolicyEngine` decision below always applies the blocklist first - so keep a
domain on one list, not both.)

Host rules cannot safely classify URLs that have no host. In enforce mode,
Sentinel therefore blocks direct autonomous `navigate` actions using non-web
schemes such as `data:`, `javascript:`, `blob:`, `file:` or `mailto:`.
`http:`, `https:` and the recovery target `about:blank` remain available.
Regardless of mode, model navigation metadata, Activity and traces replace the
complete suffix of a non-web URL with `[REDACTED]`; an inline `data:` document
is never displayed as though it were an ordinary URL path.

## Decision order (first match wins)

Every browser action passes through `PolicyEngine.evaluate()` -
[server/governance/policy.py](server/governance/policy.py) - the single
decision point:

| # | Rule | Verdict | What happens |
|---|------|---------|--------------|
| 1 | `blocked_actions` | **block** | action refused; agent told to re-plan |
| 2 | non-web direct `navigate` scheme | **block** | embedded content, local-resource or external-handler URLs never reach the privileged navigation tool |
| 3 | `domain_blocklist` | **block** | same (checked against the navigation target or current page) |
| 4 | `domain_allowlist` | **block** | anything not on the list is refused |
| 5 | high-confidence injection into a protected sink, unsafe sensitive flow, or unavailable URL needed by active domain policy | **block** | action is refused; values remain redacted in events |
| 6 | detected password/one-time-code/token/payment/private-key data in an agent action | **handoff** | original action is withheld; the human performs the step directly |
| 7 | `sensitive_domains` | **handoff** | run freezes; human takes over in the browser |
| 8 | `approval_required_actions` / `_domains` | **approve** | side-panel allow-once / allow-similar / deny gate |
| 9 | adaptive or configured approvable risk | **approve** | only side-effecting actions are held; read-only inspection stays available |
| 10 | *(default)* | **allow** | action executes |

The agent can also hand over voluntarily: it has a `request_human_control`
action and standing instructions to use it for logins, one-time codes,
CAPTCHAs, payment, or personal details - the same handoff flow, initiated by
the model instead of a rule.

## Prompt-injection containment

Sentinel does not equate “the detector found nothing” with “the page is
trusted.” The complete model is layered:

1. In enforce mode, the system message declares browser DOM/text, files, URLs
   and tool results to be untrusted data that cannot issue instructions. The
   ordinary interactive model does not receive page screenshots.
2. `GovernedLLM` extracts `<browser_state>`, `<read_state>`,
   `<webpage_content>`, and Sentinel-wrapped tool-result regions and looks for
   independent attack signals (authority impersonation, instruction override,
   role reassignment, secrecy/evasion, secret exfiltration, forged role/tool
   markup, encoded instructions). It never emits the payload text.
3. A detected payload is stored internally as an origin-scoped taint with a
   score, signal names and a short hash; public events receive a separate
   per-run keyed digest. When `browser_sanitize` is enabled in enforce mode,
   `GovernedLLM` removes only attributed untrusted regions and re-runs
   detection on what the model will receive. `removed` requires both a changed
   region and a clear re-detection; partial or unsafe mapping is recorded as
   `residual` or `unattributable`.
4. Forged protocol boundary tags inside page/read state are escaped. After
   confirmed clean removal, `alert_after_sanitize=false` continues silently;
   explicit `true` retains the old post-removal warning as a historical
   provenance ablation. That switch never applies to `residual` or
   `unattributable`. For a current browser/read observation, Sentinel withholds
   it before the model call, pauses the run and opens a persistent
   security-incident card for the operator. The unresolved page content is not
   converted into a model warning.
5. Resolving the incident never approves the quarantined content. The operator
   takes control or makes the page safe, returns control, and Sentinel obtains
   a fresh browser observation before the model can continue. Timeout,
   cancellation and shutdown fail closed. A bounded extraction or persistent
   tool-result value uses whole-value removal instead: this avoids BrowserUse's
   shorter nested extraction timeout and a loop over unchanged agent history.
6. `GovernedTools` propagates confirmed origin taint into every proposed action.
   Read-only inspection is allowed; medium-confidence side effects are held; high-
   confidence protected sinks (search/navigation, input/keys, upload, code/file
   writes, premature completion, injected handoff requests, and consequential
   clicks) are blocked.

This deterministic detector is intentionally benchmarkable and explainable;
it is defense in depth, not a claim that signatures can recognize every novel
attack. The taint-and-sink layer limits what a missed or ambiguous instruction
can do. A quarantine is a response to a detected sanitisation failure; it does
not prove that undetected or purely visual attacks are absent.

## Sensitive-data flow control and redaction

The action analyzer labels both sources and sinks:

- source labels: `untrusted_web`, `prompt_injection_suspected`,
  `sensitive:<category>`, `local_file`;
- capabilities/sinks: navigation, page write, data disclosure, local-file
  read/write, code execution, network read and task completion.

In enforce mode, recognized credentials/passwords, one-time codes, secret
placeholders, access tokens/API keys, JWTs, private keys and payment data are
human-only. Recognition covers recursive action parameters, indexed
password/OTP/payment fields, free-text `send_keys`, sensitive `evaluate`
semantics, secret-looking upload paths, and bounded inspection of authorized
local text uploads. Remote, missing, binary, oversized, and unreadable uploads
are treated as unclassifiable and handed over. The proposed agent action is not
approved or executed—even for a trusted destination and even when
`sensitive_data_verdict` is `approve`. Operator consent is expressed by taking
control and entering, submitting, or uploading the value directly in the
browser. A higher-priority hard policy or prompt-injection block still wins and
is never weakened into a handoff. Other sensitive categories follow
`trusted_domains` and `sensitive_data_verdict`. In every case, the side panel,
traces and approval manager receive only a redacted copy. A per-run keyed
digest correlates an attempt and completion without creating a stable cross-run
fingerprint of the secret.

These checks are deterministic channel guards, not universal DLP. A secret
without a recognized value, field, action, filename, or bounded-text marker may
still be missed. The upload scan covers at most 256 KiB of local UTF-8 text and
binds a clean file's keyed content digest into the approval scope.

## Bounded human approval

Approval is a risk response, not a blanket prompt on every click. The operator
can choose:

- **Allow once** — applies only to the pending action;
- **Allow similar** — creates a run-local grant scoped to action type, target
  origin/path, DOM target semantics, capabilities, taint class and sensitive
  category; uploads/code/file writes additionally bind the exact parameter
  digest. It expires after
  `grant_ttl_s` or `grant_max_uses`, whichever comes first;
- **Deny** — fails closed and tells the agent not to retry.

The browser/API cannot manufacture reusable consent when the original request
did not offer it. Approval is not a promise to execute later: after an explicit
approval or reuse of an existing grant, Sentinel re-reads the current URL and
DOM target, reloads policy, recalculates risk and re-evaluates immediately
before the privileged call. It executes only if the refreshed policy allows it
or the same narrow scope is still valid; changed or unavailable context fails
closed with a decision and paired audit. After `max_prompts_per_run`, Sentinel
stops producing approval cards and follows `fatigue_strategy`: one direct
browser handoff (default), or a hard block. Denial, timeout, cancellation and
shutdown are distinct non-executing outcomes.

## Where decisions are visible

- **Side panel**: every non-allow verdict is a chip in the chat with the
  human-readable reason; approval, handoff and unresolved-sanitisation incident
  cards dock at the bottom. Page screenshots and raw page titles are never sent
  to the extension.
- **WebSocket** (`/ws`): each decision is an `enforcement_decision` event with
  `verdict`, `rule`, `reason`, `mode`, policy-only `decision_ms`, complete
  pre-action `enforcement_ms`, action ID, risk/factors,
  capabilities, taint labels, target origin and a keyed parameter digest.
- **Action audit**: every attempt—including blocks and timeouts—has an
  `action_audit:attempted` event and exactly one `action_audit:completed` event
  with outcome and duration. The attempted record is emitted before fallible
  URL/DOM/risk/policy preflight, so preflight exceptions and cancellations are
  paired too. Payloads are redacted and raw exceptions are not recorded.
- **Injection alerts**: `prompt_injection_detected` contains score, severity,
  signal names and content hash, never the attacker payload.
- **Sanitisation outcomes**: `prompt_injection_sanitized` records status,
  branch, changed/unattributable region counts, residual score and whether an
  alert was emitted, never the removed payload.
- **Server log**: one `[decision]` line per verdict at the decision point.
- **Trace files**: every run writes `sentinel/data/traces/<run_id>/events.jsonl` +
  `meta.json` (policy snapshot at run start, outcome, enforcement metrics).
  `steps/*.png` and free-form model thinking/memory are retained only when the
  respective `audit` flags are explicitly enabled; both are off by default.
  Screenshot retention does not enable vision for the agent or expose frames
  to the extension.

## Local deployment boundary

The control API listens on loopback for this local, non-deployed thesis
artefact, and its existing origin, consent-scope and input validation remain
part of the boundary. Loopback is an accepted deployment assumption, not
same-user process isolation: another compromised process running as the same
OS user may still call the API or modify local files. Sentinel does not claim
to be an OS sandbox.

## Verdict vocabulary (events + traces)

`allowed` · `blocked` · `approval_required` → (`allowed` | `denied_by_human` |
`denied_timeout` | `denied_cancelled`) · `handoff_required` →
(`handoff_returned` | `handoff_timeout` | `handoff_cancelled`) ·
`shadow_blocked` · `shadow_approval_required` ·
`shadow_handoff_required` · `approval_reused`

## Evidence boundary

This file describes the current policy implementation. Completed AgentDojo and
WASP rows in [`EVALS.md`](EVALS.md) remain tied to their recorded code, policy,
model, and run provenance. Older results should not be treated as evidence that
a current policy mechanism was tested. New quantitative claims require a
matching validation artefact or immutable run tag; completed rows must not be
rewritten or pooled.
