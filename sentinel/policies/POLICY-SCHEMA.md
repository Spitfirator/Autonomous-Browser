# Sentinel policy field reference

This file is the compact reference for the `policies` object stored in
`sentinel/data/config.json`. See [`../POLICY.md`](../POLICY.md) for rule
precedence, runtime behavior, security boundaries, and audit semantics. The
Pydantic models and interactive migration in
[`../server/config.py`](../server/config.py) are the executable source of truth
for validation and defaults.

Unknown fields are rejected. Policy updates apply to the next governed action,
including during a run.

## Configuration shape

```jsonc
{
  "policies": {
    // enforce = apply verdicts; shadow = evaluate and log without enforcement;
    // off = no prompt-boundary or verdict enforcement. Redacted audit remains.
    "mode": "enforce",

    // null permits any host. A list blocks hosts that do not match an entry.
    "domain_allowlist": null,

    // Matching hosts are blocked.
    "domain_blocklist": ["*.bank.com", "internal-admin.corp"],

    // These agent action types are always blocked.
    "blocked_actions": ["upload_file"],

    // These action types or hosts require explicit human approval.
    "approval_required_actions": ["execute_javascript"],
    "approval_required_domains": ["checkout.stripe.com", "*.paypal.com"],

    // First contact with a matching host hands the browser to the operator.
    "sensitive_domains": ["accounts.google.com", "*.okta.com"],

    "prompt_injection": {
      "enabled": true,
      "detection_threshold": 0.55,
      "block_threshold": 0.85,

      // In enforce mode, remove detected untrusted regions before model input.
      "browser_sanitize": true,

      // false continues silently after confirmed clean removal. It does not
      // weaken quarantine of unresolved current observations or full removal
      // of unresolved bounded extraction/history values.
      "alert_after_sanitize": false,

      // High-confidence tainted use of these actions is blocked. Removing an
      // action here does not bypass sensitive-data or tainted-side-effect rules.
      "hard_block_sinks": [
        "search",
        "navigate",
        "input",
        "send_keys",
        "upload_file",
        "evaluate",
        "write_file",
        "replace_file",
        "done",
        "request_human_control"
      ]
    },

    "data_flow": {
      "enabled": true,
      "trusted_domains": [],

      // Applies to non-human-only sensitive categories. Recognized passwords,
      // one-time codes, tokens, payment values, private keys, secret
      // placeholders, and unclassifiable uploads require takeover in enforce.
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

    // These flags control opt-in local trace retention only. The interactive
    // model remains DOM/text-only and the extension receives no screenshots.
    "audit": {
      "store_screenshots": false,
      "store_model_reasoning": false
    },

    "budgets": {
      "max_steps": 30,
      "max_llm_calls": 60,
      "approval_timeout_s": 120,
      "handover_timeout_s": 900
    }
  }
}
```

## Domain entry syntax

All domain lists use the same host matcher.

| Entry | Match |
|---|---|
| `facebook` | Host contains the keyword, including `notfacebook.com` |
| `facebook.com` | The domain and its subdomains, excluding lookalikes |
| `*.facebook.com` | Host glob; the apex is included for `*.x` |
| `https://facebook.com` | Scheme-aware host match; ports are ignored |

Matching is against the host, not query text. Browser navigation enforcement
also covers redirects, link clicks, new tabs, and script-initiated navigation.
Direct autonomous navigation to non-web schemes fails closed in enforce mode;
HTTP(S) and the recovery target `about:blank` remain available.

## Validation constraints

- `mode`: `enforce`, `shadow`, or `off`.
- Injection thresholds: between `0` and `1`, with `block_threshold` greater
  than or equal to `detection_threshold`.
- `sensitive_data_verdict`: `block` or `approve`.
- `approval_risk_threshold`: integer from `0` to `100`.
- `grant_ttl_s`: `1` to `3600` seconds.
- `grant_max_uses` and `max_prompts_per_run`: integer from `1` to `100`.
- `fatigue_strategy`: `handoff` or `block`.

Use [`reference-policy.json`](reference-policy.json) as a starting document.
For the interactive application, `ConfigStore` migrates a new omitted
`browser_sanitize` field to `true` and `alert_after_sanitize` to `false`; API
patches preserve fields already present in the active configuration. Standalone
or frozen evaluation documents retain the Pydantic legacy omitted-field
semantics (`false` and `true`, respectively). Frozen policies must therefore be
interpreted with the code and run provenance recorded for that campaign.

## Evidence boundary

This reference describes the current runtime. Completed results in
[`../EVALS.md`](../EVALS.md) remain tied to their recorded code, policy, model,
and run provenance. A current field or default must not be attributed to an
older result without a matching artefact.
