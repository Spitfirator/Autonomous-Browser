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

`approve` is a lightweight yes/no gate on one action. `handoff` is a full
human-takeover of the live browser — used when only a person should act
(credentials, one-time codes, CAPTCHAs, payment details).

---

## Handoff: two triggers

A handoff can start two ways, and only one of them lives in this policy file:

1. **Agent-initiated (the primary path).** The agent is given a
   `request_human_control` tool. Whenever it hits a step only a person should do
   — logins/credentials, verification or one-time codes, CAPTCHAs, payment, or
   personal details it doesn't know (addresses, postcodes, names) — it calls that
   tool instead of guessing. This needs **no policy configuration**; it's a
   standing capability of the agent.

2. **Policy-forced (the backstop).** `sensitive_domains` forces a handoff on the
   first touch of a matching domain even if the agent didn't ask — so a human is
   guaranteed to be in the loop on those pages regardless of the agent's judgment.

Both paths converge on the same thing: the run freezes, a person drives the
browser, then hands control back and the agent resumes from the updated page.
So `sensitive_domains` is not the whole of "handoff" — it's the enforced subset.

---

## Rule order (first match wins)

The engine checks rules top-to-bottom and returns the first one that fires:

| # | Rule                                    | Verdict   |
|---|-----------------------------------------|-----------|
| 1 | `blocked_actions`                       | `block`   |
| 2 | `domain_blocklist`                      | `block`   |
| 3 | `domain_allowlist` (URL on nothing)     | `block`   |
| 4 | `sensitive_domains` (first touch/run)   | `handoff` |
| 5 | dynamic sensitive-data / high-confidence injection flow | `block` |
| 6 | `approval_required_actions` / `_domains`| `approve` |
| 7 | detected injection + independently amplified action | `approve` |
| 8 | dynamic side-effect risk ≥ threshold    | `approve` |
| 9 | default                                 | `allow`   |

Rule 7 is **targeted defense in depth, not a blanket gate**. On a page with an
active finding it holds only actions that are independently risk-amplifying:

- the action crosses an origin boundary, or discloses data off the current one;
- it carries sensitive data;
- it reads a local file into web content, or executes code in the page;
- its target appears destructive or consequential.

Ordinary same-origin interaction — typing into a form, clicking an unremarkable
control — is left to the numeric risk policy in rule 8, and read-only actions
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
primary control for that class; rule 7 covers cross-origin exfiltration and
independently high-impact actions.

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
      // Browser path only. In enforce mode, remove detected untrusted
      // page/read-state regions before the model sees them. Default: false.
      "browser_sanitize": false,
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
      // Sensitive values may flow only to these destinations.
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
      "store_screenshots": false,      // live panel is unaffected
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
  per-run only and resets on the next run.
- **Shadow mode.** In `mode: "shadow"` the engine evaluates every rule and logs
  the verdict it *would* have returned, but executes the action as `allow`
  anyway. Use it to measure false blocks / missed dangerous actions before
  turning on `enforce`. `off` skips prompt-boundary and verdict enforcement;
  paired redacted action auditing remains for a measurable baseline.
- **After a denial or timeout.** A denied approval, or a handoff no human answers
  before `handover_timeout_s`, does not silently pass — the agent is told the
  step was refused and instructed not to retry it, so it finds another way or
  finishes with what it has.
- **Allow similar is bounded consent, not an allowlist edit.** It is scoped to
  action, origin, capabilities, taint and sensitive category for this run only,
  and expires by both time and use count. The server only accepts this scope if
  the pending request explicitly offered it.
- **Monitoring is redacted.** Approval cards, decisions and paired action-audit
  events never receive raw detected secrets. See `../POLICY.md` for the complete
  prompt-boundary, taint, action-capability and audit model.

---
