# Product

## Register

product

## Users

**A single operator supervising an autonomous browser agent.** The primary (currently only) user is the project owner running browser-use agents through Sentinel — giving the agent tasks, watching it work, approving sensitive actions, taking over for logins/payments, and tuning models and policies. Context: a desk, a dedicated agent-driven Chrome window plus the Sentinel side panel and dashboard, often glancing over mid-task. The job on any screen: *know what the agent is doing and what it costs, and intervene (approve, steer, take over, stop) without friction or doubt.*

## Product Purpose

Sentinel is the control plane and enforcement middleware for autonomous browser agents (browser-use). Every LLM call and browser action flows through its governance layer — domain rules, blocked actions, human-approval gates, budgets — and streams live to the extension UI. Success looks like: the operator trusts the agent to run unattended because the UI makes state legible at a glance and puts a reliable human gate in front of anything sensitive.

## Brand Personality

**Precise. Trustworthy. Calm under automation.**

Deliberately the same design language as the FUZER organiser dashboard ("The Control Room"): instrument-grade legibility, restraint over decoration, one clear action per screen. Where FUZER supervises money in motion, Sentinel supervises an agent in motion — the same calm, light, confident surface applies. Voice is plain and direct; the interface should feel like it has the agent firmly on a leash, never breathless or theatrical.

## Anti-references

- **The previous Sentinel theme:** dark "mission control" cockpit — blue-black scanline backgrounds, phosphor-amber on dark, mono-first uppercase micro-labels everywhere. Explicitly rejected by the owner ("dark, rather strange").
- **Generic AI-SaaS slop:** card-grid-everything, gradient hero metrics, tracked uppercase eyebrows, purple gradients.
- **Hacker/terminal aesthetics:** green-on-black, CRT effects, all-caps telemetry cosplay.
- **Legacy enterprise density:** gray-on-gray, cluttered toolbars, unstyled tables.

## Design Principles

1. **Same house as FUZER.** Reuse FUZER's token system, type scale, and component language wholesale (see DESIGN.md). Sentinel is a different product in the same design family — do not fork the aesthetic.
2. **The agent's state is the headline.** Running / paused / your-turn / offline must be readable in half a second from any surface (panel, dashboard, in-page pill), always as color + text, never color alone.
3. **Amber is the signal, not the wash.** The brand amber marks the primary action, the active state, and the "agent is driving" frame — ≤10% of any screen.
4. **Interruptions are first-class.** Approval and takeover cards are the most important UI in the product: obvious, calm, one primary action, with a visible countdown.
5. **Numbers you can bill by.** Steps, calls, tokens, and budgets render in tabular figures, consistently formatted — the operator should trust them the way a FUZER organiser trusts revenue.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Body and placeholder text ≥4.5:1; muted-foreground is the floor for de-emphasised text. Full keyboard operability with visible 3px focus rings. Every animation has a `prefers-reduced-motion` alternative. State is never conveyed by hue alone (dot + word, chip + label). English-only for now.
