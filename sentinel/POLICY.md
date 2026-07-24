# Sentinel policy schema

One JSON object governs everything the agent is allowed to do. It lives at
`data/config.json` under the `policies` key, is edited live from the dashboard
(Policies tab), or applied programmatically:

```bash
curl -X PUT http://127.0.0.1:8765/api/config \
     -H 'Content-Type: application/json' \
     -d @policies/reference-policy.json
```

Edits apply to the agent's **very next action**, even mid-run.

## The schema

```jsonc
{
  "policies": {
    // enforce  - verdicts are applied (default)
    // shadow   - everything is allowed, but would-be verdicts are still
    //            evaluated and logged (measure false blocks / missed dangers)
    // off      - no prompt boundary or verdict enforcement; redacted action
    //            auditing remains so baseline runs are still measurable
    "mode": "enforce",

    // null = any site allowed. A list = ONLY these sites (entries matched the
    // same way as every other domain list - see the table below).
    "domain_allowlist": null,

    // Never allowed, even if the allowlist would permit them.
    "domain_blocklist": ["*.bank.com", "github.com"],

    // Action types the agent may never use. Also removed from the LLM's
    // tool schema at run start, so the model can't even plan with them.
    "blocked_actions": ["upload_file"],

    // ASK APPROVAL: the run pauses inside the step; the side panel shows an
    // approve/deny card with a countdown. Deny (or timeout) returns an error
    // the agent adapts to. By action type, by domain, or both.
    "approval_required_actions": ["upload_file"],
    "approval_required_domains": ["checkout.stripe.com", "*.paypal.com"],

    // HANDOFF TO HUMAN: first touch of these domains freezes the agent and
    // hands the browser to the human (in-page "Your turn" banner + panel
    // card). The intercepted action is NOT executed. After the human hands
    // control back (optionally with a note the agent reads), the agent may
    // act on that domain for the rest of the run - the human vouched for it.
    "sensitive_domains": ["accounts.google.com", "practicetestautomation.com"],

    // Indirect prompt injection: page/read-state regions are always untrusted.
    // Scores >= detection_threshold taint downstream actions and reinforce the
    // model's system boundary. Protected sinks at/above block_threshold block.
    "prompt_injection": {
      "enabled": true,
      "detection_threshold": 0.55,
      "block_threshold": 0.85,
      // Optional browser-path intervention. When true in enforce mode,
      // detected page/read-state regions are removed before the model sees
      // them. The default false preserves warn-only and historical runs.
      "browser_sanitize": false
    },

    // Credentials, access tokens, payment details, private keys and secret
    // placeholders may only flow to an explicitly trusted destination.
    "data_flow": {
      "enabled": true,
      "trusted_domains": [],
      "sensitive_data_verdict": "block" // or "approve"
    },

    // Risk-based prompts plus explicit, bounded consent reuse. Once the prompt
    // budget is spent, hand over once (or block) instead of inducing approval
    // fatigue with more cards.
    "adaptive_approvals": {
      "enabled": true,
      "approval_risk_threshold": 55,
      "grant_ttl_s": 300,
      "grant_max_uses": 3,
      "max_prompts_per_run": 4,
      "fatigue_strategy": "handoff" // or "block"
    },

    // Live screenshots/reasoning still reach the side panel. At-rest trace
    // retention is opt-in because those channels cannot be reliably redacted.
    "audit": {
      "store_screenshots": false,
      "store_model_reasoning": false
    },

    "budgets": {
      "max_steps": 30,            // agent steps per task
      "max_llm_calls": 60,        // graceful stop at limit, hard stop +2 later
      "approval_timeout_s": 120,  // unanswered approval => denied
      "handover_timeout_s": 900   // unanswered handoff => agent must re-plan
    }
  }
}
```

Every domain-list entry (blocklist, allowlist, approval, sensitive) is matched
against a URL's **host** with these four shapes, most rigid to most precise:

| Entry | Means | Blocks / matches |
|---|---|---|
| `facebook` | **keyword** - host *contains* the word | `facebook.com`, `www.facebook.com`, `m.facebook.com`, `business.facebook.net`, even `notfacebook.com` |
| `facebook.com` | **domain** - that domain + its subdomains | `facebook.com`, `www.facebook.com`; **not** `notfacebook.com` |
| `*.facebook.com` | **glob** on the host | subdomains + apex |
| `https://facebook.com` | **full URL** - scheme-aware | that origin only |

A bare word (no dot) is the rigid one - use it when you want to block a service
however the agent spells the URL. It matches the **host only**, so
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

So the agent cannot reach a blocked site by clicking a search result, following
a redirect, or trying a different search engine. The LLM-level check (rules
below) and this navigation net use the **same** matching, so the panel's
"Blocked" reason always matches what the browser enforces. (One precedence note:
if a domain is on both lists, the allowlist wins at the browser layer, while the
`PolicyEngine` decision below always applies the blocklist first - so keep a
domain on one list, not both.)

## Decision order (first match wins)

Every browser action passes through `PolicyEngine.evaluate()` -
[server/governance/policy.py](server/governance/policy.py) - the single
decision point:

| # | Rule | Verdict | What happens |
|---|------|---------|--------------|
| 1 | `blocked_actions` | **block** | action refused; agent told to re-plan |
| 2 | `domain_blocklist` | **block** | same (checked against the navigation target or current page) |
| 3 | `domain_allowlist` | **block** | anything not on the list is refused |
| 4 | `sensitive_domains` | **handoff** | run freezes; human takes over in the browser |
| 5 | sensitive-data flow or high-confidence injection into a protected sink | **block** | source-to-sink flow is refused; values remain redacted in events |
| 6 | `approval_required_actions` / `_domains` | **approve** | side-panel allow-once / allow-similar / deny gate |
| 7 | adaptive risk score ≥ threshold | **approve** | only side-effecting actions are held; read-only inspection stays available |
| 8 | *(default)* | **allow** | action executes |

The agent can also hand over voluntarily: it has a `request_human_control`
action and standing instructions to use it for logins, one-time codes,
CAPTCHAs, payment, or personal details - the same handoff flow, initiated by
the model instead of a rule.

## Prompt-injection containment

Sentinel does not equate “the detector found nothing” with “the page is
trusted.” The complete model is layered:

1. In enforce mode, the system message declares browser DOM, screenshots,
   files, URLs and tool results to be untrusted data that cannot issue
   instructions.
2. `GovernedLLM` extracts only `<browser_state>` / `<read_state>` regions and
   looks for independent attack signals (authority impersonation, instruction
   override, role reassignment, secrecy/evasion, secret exfiltration, forged
   role/tool markup, encoded instructions). It never emits the payload text.
3. A detected payload is stored as an origin-scoped taint with a score, signal
   names and a short content hash. In enforce mode, the model receives a fresh
   system-level warning that contains no attacker-controlled snippet and forged
   protocol boundary tags inside page/read state are escaped. Shadow mode only
   records the finding and would-be verdict; it does not alter model input.
4. `GovernedTools` propagates that taint into every proposed action. Read-only
   inspection is allowed; medium-confidence side effects are held; high-
   confidence protected sinks (search/navigation, input/keys, upload, code/file
   writes, premature completion, injected handoff requests, and consequential
   clicks) are blocked.

This deterministic detector is intentionally benchmarkable and explainable;
it is defense in depth, not a claim that signatures can recognize every novel
attack. The taint-and-sink layer limits what a missed or ambiguous instruction
can do.

## Sensitive-data flow control and redaction

The action analyzer labels both sources and sinks:

- source labels: `untrusted_web`, `prompt_injection_suspected`,
  `sensitive:<category>`, `local_file`;
- capabilities/sinks: navigation, page write, data disclosure, local-file
  read/write, code execution, network read and task completion.

Credentials, secret placeholders, access tokens/API keys, JWTs, private keys,
payment data and common sensitive parameter names are detected recursively.
Unless the target URL matches `data_flow.trusted_domains`, disclosure is
blocked (or held if configured). Original parameters still reach the real tool
after an allow, but the side panel, traces and approval manager receive only a
redacted copy. A per-run keyed digest correlates an attempt and completion
without creating a stable cross-run fingerprint of the secret.

## Fatigue-resistant human approval

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
did not offer it. After `max_prompts_per_run`, Sentinel stops producing approval
cards and follows `fatigue_strategy`: one direct browser handoff (default), or a
hard block. Timeouts and shutdown also fail closed.

## Where decisions are visible

- **Side panel**: every non-allow verdict is a chip in the chat with the
  human-readable reason; approval/handoff cards dock at the bottom.
- **WebSocket** (`/ws`): each decision is an `enforcement_decision` event with
  `verdict`, `rule`, `reason`, `mode`, policy-only `decision_ms`, complete
  pre-action `enforcement_ms`, action ID, risk/factors,
  capabilities, taint labels, target origin and a keyed parameter digest.
- **Action audit**: every attempt—including blocks and timeouts—has an
  `action_audit:attempted` event and exactly one `action_audit:completed` event
  with outcome and duration. Payloads are redacted and raw exceptions are not
  recorded.
- **Injection alerts**: `prompt_injection_detected` contains score, severity,
  signal names and content hash, never the attacker payload.
- **Server log**: one `[decision]` line per verdict at the decision point.
- **Trace files**: every run writes `data/traces/<run_id>/events.jsonl` +
  `meta.json` (policy snapshot at run start, outcome, enforcement metrics).
  `steps/*.png` and free-form model thinking/memory are retained only when the
  respective `audit` flags are explicitly enabled; both are off by default.

## Verdict vocabulary (events + traces)

`allowed` · `blocked` · `approval_required` → (`allowed` | `denied_by_human` |
`denied_timeout`) · `handoff_required` → (`handoff_returned` |
`handoff_timeout`) · `shadow_blocked` · `shadow_approval_required` ·
`shadow_handoff_required` · `approval_reused`
