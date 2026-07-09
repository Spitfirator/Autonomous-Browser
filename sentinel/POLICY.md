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
    // off      - policy evaluation is skipped (baseline for eval runs)
    "mode": "enforce",

    // null = any site allowed. A list = ONLY these sites (glob syntax).
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
| `facebook` | **keyword** — host *contains* the word | `facebook.com`, `www.facebook.com`, `m.facebook.com`, `business.facebook.net`, even `notfacebook.com` |
| `facebook.com` | **domain** — that domain + its subdomains | `facebook.com`, `www.facebook.com`; **not** `notfacebook.com` |
| `*.facebook.com` | **glob** on the host | subdomains + apex |
| `https://facebook.com` | **full URL** — scheme-aware | that origin only |

A bare word (no dot) is the rigid one — use it when you want to block a service
however the agent spells the URL. It matches the **host only**, so
`duckduckgo.com/?q=facebook` (the word in a search query) is still allowed — the
agent can search, it just can't *reach* the site.

### Blocklist enforcement is at the navigation layer

Blocklist entries aren't just checked when the agent calls `navigate`. They are
mirrored into browser-use's SecurityWatchdog as `prohibited_domains`, which
enforces at the browser's real navigation events:

- **direct navigation** — blocked before it starts;
- **redirects** — a redirect that lands on a blocked host is bounced to
  `about:blank`;
- **new tabs / pop-ups** — a blocked tab is closed;
- **link clicks, JS navigation, switching search engines** — all caught the same
  way, because the net is on the navigation, not on the agent's chosen action.

So the agent cannot reach a blocked site by clicking a search result, following
a redirect, or trying a different search engine. The LLM-level check (rules
below) and this navigation net use the **same** matching, so the panel's
"Blocked" reason always matches what the browser enforces.

## Decision order (first match wins)

Every browser action passes through `PolicyEngine.evaluate()` —
[server/governance/policy.py](server/governance/policy.py) — the single
decision point:

| # | Rule | Verdict | What happens |
|---|------|---------|--------------|
| 1 | `blocked_actions` | **block** | action refused; agent told to re-plan |
| 2 | `domain_blocklist` | **block** | same (checked against the navigation target or current page) |
| 3 | `domain_allowlist` | **block** | anything not on the list is refused |
| 4 | `sensitive_domains` | **handoff** | run freezes; human takes over in the browser |
| 5 | `approval_required_actions` / `_domains` | **approve** | side-panel approve/deny gate |
| 6 | *(default)* | **allow** | action executes |

The agent can also hand over voluntarily: it has a `request_human_control`
action and standing instructions to use it for logins, one-time codes,
CAPTCHAs, payment, or personal details — the same handoff flow, initiated by
the model instead of a rule.

## Where decisions are visible

- **Side panel**: every non-allow verdict is a chip in the chat with the
  human-readable reason; approval/handoff cards dock at the bottom.
- **WebSocket** (`/ws`): each decision is an `enforcement_decision` event with
  `verdict`, `rule`, `reason`, `mode`, and `decision_ms` (policy latency).
- **Server log**: one `[decision]` line per verdict at the decision point.
- **Trace files**: every run writes `data/traces/<run_id>/events.jsonl` +
  `steps/*.png` screenshots + `meta.json` (policy snapshot at run start,
  outcome, enforcement metrics). This is the shareable audit log.

## Verdict vocabulary (events + traces)

`allowed` · `blocked` · `approval_required` → (`allowed` | `denied_by_human` |
`denied_timeout`) · `handoff_required` → (`handoff_returned` |
`handoff_timeout`) · `shadow_blocked` · `shadow_approval_required` ·
`shadow_handoff_required`
