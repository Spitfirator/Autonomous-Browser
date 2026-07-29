# Sentinel Policy Schema

One policy document governs every action an autonomous browser agent tries to
take. The **PolicyEngine** is the single decision point: before any tool call or
navigation runs, the engine evaluates it against the policy and returns one of
four **verdicts**.

| Verdict     | Meaning                                                                 |
|-------------|-------------------------------------------------------------------------|
| `allow`     | The action runs. (Default when nothing matches.)                        |
| `block`     | The action is refused outright. The agent is told and moves on.         |
| `approve`   | **Ask a human.** The action pauses at an approve/deny gate in the side panel. |
| `handoff`   | **Hand control to a human.** The run freezes and a person drives the browser for this step, then hands control back and the agent resumes. |

`approve` is a lightweight yes/no gate on one action. In enforce mode, it can
never authorize the agent to use a recognized password, one-time code, token,
payment value or private key through a guarded action channel.
`handoff` is full human takeover of the live browser: the proposed agent action
is withheld and the person performs the protected step directly.

---

## Handoff: three triggers

A handoff can start three ways:

1. **Agent-initiated (the primary path).** The agent is given a
   `request_human_control` tool. Whenever it hits a step only a person should do
   — logins/credentials, verification or one-time codes, CAPTCHAs, payment, or
   personal details it doesn't know (addresses, postcodes, names) — it calls that
   tool instead of guessing. This needs **no policy configuration**; it's a
   standing capability of the agent.

2. **Policy-forced (the backstop).** `sensitive_domains` forces a handoff on the
   first touch of a matching domain even if the agent didn't ask — so a human is
   guaranteed to be in the loop on those pages regardless of the agent's judgment.

3. **Data-flow-forced.** If a proposed action contains a recognized
   password/credential, one-time code, access token, payment value, private key
   or secret placeholder—or an upload cannot be safely classified—dynamic risk
   analysis returns `handoff` before a generic sensitive-domain or approval
   rule. This applies even on a trusted domain and even if
   `sensitive_data_verdict` is `approve`; a higher-priority hard block still
   wins and is never weakened into a handoff.

All three paths converge on the same thing: the run freezes, the original
action does not execute, a person drives the browser, then hands control back
and the agent resumes from the updated page. User consent for a human-only
value therefore means entering/submitting it during takeover, not approving
the agent to type it.

---

## Rule order (first match wins)

The engine checks rules top-to-bottom and returns the first one that fires:

| # | Rule                                    | Verdict   |
|---|-----------------------------------------|-----------|
| 1 | `blocked_actions`                       | `block`   |
| 2 | `domain_blocklist`                      | `block`   |
| 3 | `domain_allowlist` (URL on nothing)     | `block`   |
| 4 | high-confidence injection, configured hard sensitive flow, or missing URL required by active domain rules | `block` |
| 5 | detected human-only password/one-time-code/token/payment/private-key flow | `handoff` |
| 6 | `sensitive_domains` (first touch/run)   | `handoff` |
| 7 | `approval_required_actions` / `_domains`| `approve` |
| 8 | detected injection + independently amplified action | `approve` |
| 9 | dynamic side-effect risk ≥ threshold    | `approve` |
| 10 | default                                | `allow`   |

Rule 8 is **targeted defense in depth, not a blanket gate**. On a page with an
active finding it holds only actions that are independently risk-amplifying:

- the action crosses an origin boundary, or discloses data off the current one;
- it carries sensitive data;
- it reads a local file into web content, or executes code in the page;
- its target appears destructive or consequential.

Ordinary same-origin interaction — typing into a form, clicking an unremarkable
control — is left to the numeric risk policy in rule 9, and read-only actions
are never gated.

This boundary is deliberate. An injected page is normally the same page the
user's own task lives on, so gating every same-origin side effect spends the
approval budget on legitimate work: replaying the WASP v1 trajectories, a
blanket rule gated a median of 8 actions per affected task (max 28) against a
4-prompt budget, exhausting it on 35 of 50 tasks and blocking the task rather
than the attack. The narrowed rule gates a median of 0 (p95 0, max 2) and
exhausts the budget on none.

The consequence must be stated when reporting results: **action gating does not
cover low-impact same-origin goal hijacking.** Observation sanitisation is the
primary control for that class; rule 8 covers cross-origin exfiltration and
independently high-impact actions.

BrowserUse does not expose anchor `href` values in its live DOM text. The
detector therefore recognizes a bounded precondition claim split across a
visible anchor line — for example, `you MUST click on`, `[n]<a />`, `this link`
— even though the destination itself is unavailable. This produces a
medium-confidence finding; it does not infer the hidden target or turn an
ordinary `click Save` instruction into an injection.

---

## Fields

```jsonc
{
  "policies": {
    // enforce = apply | shadow = observe without changing model/actions
    // off = no prompt boundary/verdict enforcement (redacted action audit remains)
    "mode": "enforce",

    // null = allow any domain. A list = strict allowlist: anything NOT matching is BLOCKED.
    "domain_allowlist": null,

    // Navigating/acting on a matching URL -> BLOCK.
    "domain_blocklist": ["*.bank.com", "internal-admin.corp", "facebook"],

    // Action types the agent may never perform -> BLOCK.
    "blocked_actions": ["upload_file"],

    // Action types that require a human yes/no before running -> APPROVE.
    "approval_required_actions": ["execute_javascript"],

    // URLs that require a human yes/no before acting -> APPROVE.
    "approval_required_domains": ["checkout.stripe.com", "*.paypal.com"],

    // First time the agent touches one of these domains in a run -> HANDOFF.
    "sensitive_domains": ["accounts.google.com", "*.okta.com"],

    "prompt_injection": {
      "enabled": true,
      "detection_threshold": 0.55,
      "block_threshold": 0.85,
      // Interactive default: in enforce mode, remove detected untrusted
      // page/read-state regions before the model sees them. Frozen benchmark
      // policies set this explicitly when they need warn-only behavior.
      "browser_sanitize": true,
      // Safe default: stay quiet after a confirmed clean removal. Explicit true
      // adds the old model warning for a historical ablation. Both values quarantine
      // an unresolved current browser/read observation before the model call,
      // escalate it to the operator, and require a fresh observation. Unresolved
      // bounded extraction/history values are removed in full instead.
      "alert_after_sanitize": false,
      // Actions hard-blocked at/above block_threshold. Defaults to the full set
      // including "done" and "request_human_control". A browser agent scored
      // from final site state should drop those two so it can still finish and
      // still escalate; an agent whose answer text is itself the exfiltration
      // channel must keep them. Removing an action does not leave it unguarded:
      // it still falls through to the sensitive-data and tainted-side-effect
      // rules below.
      "hard_block_sinks": [
        "search", "navigate", "input", "send_keys",
        "upload_file", "evaluate", "write_file", "replace_file",
        "done", "request_human_control"
      ]
    },

    "data_flow": {
      "enabled": true,
      // Applies to non-human-only sensitive categories. In enforce mode,
      // recognized passwords/credentials, one-time codes, tokens, payment values,
      // private keys and secret placeholders force takeover, regardless of
      // destination or verdict configuration.
      "trusted_domains": [],
      "sensitive_data_verdict": "block" // block | approve
    },

    "adaptive_approvals": {
      "enabled": true,
      "approval_risk_threshold": 55,
      "grant_ttl_s": 300,
      "grant_max_uses": 3,
      "max_prompts_per_run": 4,
      "fatigue_strategy": "handoff" // handoff | block
    },

    "audit": {
      // The normal model remains DOM/text-only and the extension receives no
      // screenshots. This controls opt-in local trace files only.
      "store_screenshots": false,
      "store_model_reasoning": false   // thinking/memory in at-rest traces
    },

    "budgets": {
      "max_steps": 30,           // hard stop on agent steps per run
      "max_llm_calls": 60,       // hard stop on model calls per run
      "approval_timeout_s": 120, // how long an APPROVE gate waits before auto-deny
      "handover_timeout_s": 900  // how long a HANDOFF waits for the human before timing out
    }
  }
}
```

### Domain entry syntax

Every domain list accepts four entry shapes, from most rigid to most precise:

| Shape     | Example                    | Matches                                                        |
|-----------|----------------------------|---------------------------------------------------------------|
| keyword   | `facebook`                 | host **contains** the word: `facebook.com`, `m.facebook.com`, `business.facebook.net` |
| domain    | `bank.com`                 | that domain **and all subdomains**, any scheme (not lookalikes like `notbank.com`) |
| glob      | `*.paypal.com`             | `fnmatch` on the host (apex included for `*.x`)                |
| full URL  | `https://checkout.stripe.com` | scheme-aware exact match                                    |

---

## Behaviour notes

- **Vouched-for domains.** After a human completes a handoff on a
  `sensitive_domains` match, that domain is marked as vouched-for **for the rest
  of that run** — the agent may act on it without re-triggering the handoff. The
  reasoning: the human was just there and vouched for the context. This trust is
  per-run only and resets on the next run. Timeout, cancellation or shutdown
  never vouches for a domain. A recognized human-only value in a later guarded
  agent action still triggers takeover even on a previously vouched-for domain.
- **Human-only detection boundary.** Recognition covers recursive parameter
  patterns, indexed password/OTP/payment fields, free-text `send_keys`,
  sensitive `evaluate` semantics, secret-looking upload paths, and up to
  256 KiB of authorized local UTF-8 upload text. Remote, missing, binary,
  oversized, or unreadable uploads hand over as unclassifiable. This is not
  universal DLP; unmarked secrets outside those deterministic checks can be
  missed.
- **Shadow mode.** In `mode: "shadow"` the engine evaluates every rule and logs
  the verdict it *would* have returned, but executes the action as `allow`
  anyway. Use it to measure false blocks / missed dangerous actions before
  turning on `enforce`. `off` skips prompt-boundary and verdict enforcement;
  paired redacted action auditing remains for a measurable baseline.
- **After a denial, timeout or cancellation.** None silently passes and none
  executes the pending action. Shutdown cancellation is recorded separately
  from a human denial or return, does not count as human intervention and
  cannot mint approval or vouched-for state.
- **Allow similar is bounded consent, not an allowlist edit.** It is scoped to
  action, origin, capabilities, taint and sensitive category for this run only,
  and expires by both time and use count. The server only accepts this scope if
  the pending request explicitly offered it.
- **Approval is revalidated.** After Allow once or Allow similar—and before
  reuse of the same grant can execute—Sentinel re-fetches the URL and DOM
  target, reloads the policy and recalculates risk. Execution occurs only if
  the refreshed policy allows it or the same narrow scope is still valid.
  Changed, missing or newly blocked context fails closed with paired decision
  and audit records.
- **Failed sanitisation is quarantined.** In enforce mode, `residual` and
  `unattributable` observations are withheld before the model call. The
  extension shows a persistent operator incident; returning control requests a
  fresh observation and never approves the quarantined content. Timeout,
  cancellation and shutdown fail closed.
- **Screenshots are not an interactive channel.** The normal agent uses
  `use_vision=false`; page screenshots and raw page titles are stripped from
  WebSocket/replay events and never displayed in the extension. An explicit
  `store_screenshots` opt-in writes local trace files only. Screenshot-only and
  canvas attacks are outside current evaluated coverage.
- **Monitoring is redacted.** Approval cards, decisions and paired action-audit
  events never receive raw detected secrets. See `../POLICY.md` for the complete
  prompt-boundary, taint, action-capability and audit model.
- **Localhost is a deployment assumption, not a sandbox.** The control API
  remains loopback-only with origin, consent-scope and input validation for the
  local thesis setup. It does not protect against a compromised process running
  as the same OS user.

---

## Evidence boundary

This schema describes the current runtime. Completed AgentDojo and WASP rows
remain tied to their recorded immutable provenance. Human-only data handoff,
unresolved-sanitisation quarantine, approval revalidation, preflight audit and
screenshot-channel hardening were added later and are not measured by those
completed rows. The WASP profile already used DOM/accessibility observations
without screenshots; the later screenshot change hardens the ordinary
interactive extension and trace path. New quantitative claims require targeted
validation or a new run tag; do not rewrite or pool the frozen results.
