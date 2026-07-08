---
name: Sentinel
description: FUZER's "Control Room" design system applied to the Sentinel agent control plane — light, precise, amber-as-signal.
colors:
  primary: "oklch(0.852 0.199 91.936)"
  primary-foreground: "oklch(0.421 0.095 57.708)"
  foreground: "oklch(0.145 0 0)"
  background: "oklch(1 0 0)"
  card: "oklch(1 0 0)"
  muted: "oklch(0.97 0 0)"
  muted-foreground: "oklch(0.556 0 0)"
  secondary: "oklch(0.967 0.001 286.375)"
  secondary-foreground: "oklch(0.21 0.006 285.885)"
  border: "oklch(0.922 0 0)"
  input: "oklch(0.922 0 0)"
  ring: "oklch(0.708 0 0)"
  success: "oklch(0.792 0.209 151.711)"
  destructive: "oklch(0.577 0.245 27.325)"
  accent-deep: "oklch(0.681 0.162 75.834)"
typography:
  headline:
    fontFamily: "Sora Variable, Sora, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Sora Variable, Sora, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 600
    lineHeight: 1.3
  body:
    fontFamily: "Sora Variable, Sora, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Sora Variable, Sora, system-ui, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 500
    lineHeight: 1.2
  numeric:
    fontFamily: "Sora Variable, Sora, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
    fontVariation: "tabular-nums"
  mono:
    fontFamily: "Geist Mono Variable, Geist Mono, ui-monospace, monospace"
    fontSize: "0.8125rem"
    fontWeight: 500
rounded:
  sm: "6px"
  md: "8px"
  lg: "10px"
  xl: "14px"
  2xl: "18px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-foreground}"
    rounded: "{rounded.lg}"
    height: "32px"
  button-outline:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    rounded: "{rounded.lg}"
    height: "32px"
  button-destructive:
    backgroundColor: "oklch(0.577 0.245 27.325 / 0.1)"
    textColor: "{colors.destructive}"
    rounded: "{rounded.lg}"
    height: "32px"
  input:
    backgroundColor: "transparent"
    textColor: "{colors.foreground}"
    rounded: "{rounded.lg}"
    height: "32px"
---

# Design System: Sentinel

**This is FUZER's organiser-dashboard system** (`fuzer/apps/frontend/DESIGN.md`, "The Control Room") applied to Sentinel. Read that file for the full rationale; this file records the port and the Sentinel-specific deltas. If a question isn't answered here, the FUZER document is the source of truth.

## The port, in one paragraph

Light-first white surfaces, near-black ink, hairline `border` dividers, flat-by-default (shadows only on true overlays: toasts, the floating in-page pill). One family — Sora — carries all hierarchy through weight and size; Geist Mono appears only for IDs, action names, params, domains, and model IDs. The brand amber `primary` is a rationed signal (≤10% of any screen): the primary button, the active nav item, the approval accent, the "agent is driving" page frame. Compact tactile controls: 32px height, 10px radius, `active:translateY(1px)`, 3px focus ring at 50% alpha. Sentence case everywhere — **no uppercase tracked eyebrows, no mono labels for prose, no border-left accent stripes, no glow shadows on in-flow cards** (all four were present in the old dark theme and are banned).

## Sentinel-specific decisions

- **Fonts are bundled locally** (`@fontsource-variable/sora`, `@fontsource-variable/geist-mono`) because MV3 extension pages must not load remote assets. Family names: `'Sora Variable'`, `'Geist Mono Variable'`. The server-rendered setup page may use the Google Fonts CDN with a system fallback; the content-script overlay uses `system-ui` (no font loading inside third-party pages).
- **Brand mark:** a small amber rounded square with a `primary-foreground` inner bar (the "signal block"), drawn inline (SVG/CSS) — replaces the old `▮` text glyph. Wordmark "Sentinel" in Sora 600–700, sentence case.
- **Status colors:** running = `success`, paused / needs-you = `primary` (amber), stopped/offline/error = `destructive`, idle = neutral. Always dot + word or chip + label — never hue alone.
- **Chips (verdicts, run status):** tinted-background badges, sentence case, 500 weight. Allowed/done = success tint with darkened-success text; blocked/error = destructive tint with destructive text; held/approval = primary tint with `primary-foreground` text; neutral/info = `secondary` with `secondary-foreground` text. The old blue "info" color is retired — off-palette.
- **`accent-deep`** (`oklch(0.681 0.162 75.834)`, FUZER's `chart-3`/`sidebar-primary`): the darker amber used where the signal must be *text or icon on white* (active nav icon, step numbers, timers) — raw `primary` fails contrast as foreground on white.
- **Approval / takeover cards** are the product's hero moment: white card, amber-mixed border, countdown meter in `primary`, one amber primary action ("Approve" / "Give control back"), destructive-tinted secondary ("Deny"). No box-shadow — they are in-flow, not overlays.
- **The in-page frame + pill** (content script): the amber breathing frame stays — it *is* the "agent is driving" signal — over a white floating pill (real overlay → soft shadow allowed). Buttons inside: dark `foreground` button for "Take over", amber primary for "give back / done", destructive tint for "Stop".
- **Numbers:** steps, calls, tokens, budgets, timers — Sora with `font-variant-numeric: tabular-nums`, never mono.
- **Motion:** small 4–6px ease-out rises on new chat items and cards; breathing pulse on live status dots and the page frame; everything gated behind `prefers-reduced-motion: reduce`.

## Surfaces

1. **Side panel** (`extension/src/sidepanel`, ~320–420px): chat-first. White canvas, hairline header/footer, secondary-tinted user bubbles, bordered agent bubbles, amber only on the send action, approval/takeover cards, and steering tags.
2. **Dashboard** (`extension/src/dashboard`): FUZER-style app shell — white sidebar with icon + sentence-case nav (active = `secondary` fill + `accent-deep` icon), headline + one primary Save action per tab, bordered section panels, quiet tables with sentence-case headers.
3. **Setup page** (`server/static/setup.html`): muted canvas, single white card, real numbered install steps, mono paths, amber "waiting" → success "connected" status row.
4. **In-page overlay** (`extension/public/content.js`): amber frame + white floating pill, as above.
