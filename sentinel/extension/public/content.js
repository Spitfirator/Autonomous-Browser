// Sentinel content script: renders the in-page control layer while the agent
// drives this browser - pulsing frame, control pill (Take over / Open chat /
// Stop), input shield, and the "YOUR TURN" takeover card. State arrives via
// chrome.storage.session (written by the service worker from the backend WS).
//
// The shield swallows real user input while the agent thinks, but drops during
// the agent's own action windows (state.acting) because CDP-dispatched events
// land in the DOM exactly like user input and must reach the page.

(() => {
  if (window.top !== window) return;

  let state = null; // sentinelState from the service worker
  let enabled = true; // chrome.storage.local.inPageVisuals !== false
  let host = null;
  let refs = null;
  let countdownTimer = null;
  let shieldActive = false;

  // ── Shadow DOM ─────────────────────────────────────────────────────────────
  function ensureHost() {
    if (host && host.isConnected) return refs;
    host = document.createElement('sentinel-control');
    host.id = '__sentinel_root';
    host.style.cssText = 'all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    root.innerHTML = `
      <style>
        :host { all: initial; }
        /* The pill is a true floating overlay, so it carries a soft shadow;
           the amber frame is the "agent is driving" signal. System font - no
           loading in pages. */
        * { box-sizing: border-box; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; }
        .glow {
          position: fixed; inset: 0; pointer-events: none;
          border: 3px solid oklch(0.852 0.199 91.936 / 0.9); border-radius: 2px;
          box-shadow: inset 0 0 20px oklch(0.852 0.199 91.936 / 0.25);
          animation: breathe 1.6s ease-in-out infinite;
        }
        .glow.static { animation: none; opacity: .6; }
        .glow.incident {
          border-color: oklch(0.577 0.245 27.325 / 0.92);
          box-shadow: inset 0 0 24px oklch(0.577 0.245 27.325 / 0.22);
          opacity: 1;
        }
        @keyframes breathe { 50% { opacity: .4; } }
        .shield { position: fixed; inset: 0; pointer-events: none; background: transparent; }
        .shield.active { pointer-events: auto; cursor: not-allowed; }
        .pill {
          position: fixed; top: 10px; left: 50%; transform: translateX(-50%);
          pointer-events: auto; display: flex; align-items: center; gap: 10px;
          background: oklch(1 0 0); color: oklch(0.145 0 0);
          border: 1px solid oklch(0.922 0 0); border-radius: 14px;
          padding: 8px 10px 8px 12px; box-shadow: 0 8px 30px oklch(0 0 0 / 0.16);
          font-size: 13px; white-space: nowrap; max-width: min(92vw, 760px);
        }
        .pill.attention { animation: nudge .3s ease; }
        .pill.incident {
          width: min(92vw, 720px); white-space: normal; align-items: flex-start;
          border-color: oklch(0.577 0.245 27.325 / 0.42);
          background: oklch(0.99 0.008 27.325);
        }
        @keyframes nudge { 30% { transform: translateX(-50%) scale(1.04); } }
        .bot {
          width: 22px; height: 22px; border-radius: 7px; flex: none;
          background: oklch(0.852 0.199 91.936); display: grid; place-items: center;
        }
        .bot::after {
          content: ''; width: 5px; height: 11px; border-radius: 2px;
          background: oklch(0.421 0.095 57.708);
        }
        .bot.pulse { animation: breathe 1.4s ease-in-out infinite; }
        .bot.incident { background: oklch(0.577 0.245 27.325 / 0.14); color: oklch(0.577 0.245 27.325); }
        .bot.incident::after {
          content: '!'; width: auto; height: auto; background: none;
          font-weight: 800; font-size: 14px;
        }
        .label { color: oklch(0.556 0 0); font-weight: 500; overflow: hidden; text-overflow: ellipsis; }
        .label b { color: oklch(0.145 0 0); font-weight: 600; }
        .pill.incident .label { flex: 1; line-height: 1.45; overflow: visible; }
        .pill.incident .label b { display: block; color: oklch(0.577 0.245 27.325); margin-bottom: 2px; }
        button {
          all: initial; cursor: pointer; font: 500 12.5px system-ui, -apple-system, 'Segoe UI', sans-serif;
          border-radius: 9px; padding: 7px 12px; white-space: nowrap;
          background: oklch(1 0 0); color: oklch(0.145 0 0); border: 1px solid oklch(0.922 0 0);
          transition: background 0.15s, opacity 0.15s;
        }
        button:hover { background: oklch(0.97 0 0); }
        button:active { transform: translateY(1px); }
        button:focus-visible { border-color: oklch(0.708 0 0); box-shadow: 0 0 0 3px oklch(0.708 0 0 / 0.5); }
        button.dark { background: oklch(0.205 0 0); color: oklch(0.985 0 0); border-color: transparent; }
        button.dark:hover { background: oklch(0.3 0 0); }
        button.red { background: oklch(0.577 0.245 27.325 / 0.08); color: oklch(0.577 0.245 27.325); border-color: transparent; }
        button.red:hover { background: oklch(0.577 0.245 27.325 / 0.15); }
        button.amber { background: oklch(0.852 0.199 91.936); color: oklch(0.421 0.095 57.708); border-color: transparent; font-weight: 600; }
        button.amber:hover { background: oklch(0.852 0.199 91.936); opacity: 0.8; }
        input {
          all: initial; font: 12.5px system-ui, -apple-system, 'Segoe UI', sans-serif; color: oklch(0.145 0 0);
          background: oklch(1 0 0); border: 1px solid oklch(0.922 0 0);
          border-radius: 8px; padding: 7px 10px; width: 230px;
        }
        input::placeholder { color: oklch(0.556 0 0); }
        input:focus { border-color: oklch(0.708 0 0); box-shadow: 0 0 0 3px oklch(0.708 0 0 / 0.5); }
        .timer { color: oklch(0.421 0.095 57.708); font-weight: 600; font-size: 12.5px; font-variant-numeric: tabular-nums; }
        .hidden { display: none !important; }
        @media (max-width: 640px) {
          .pill.incident {
            left: 10px; right: 10px; transform: none; width: auto; max-width: none;
            display: grid; grid-template-columns: 22px minmax(0, 1fr); align-items: start;
          }
          .pill.incident .label { min-width: 0; }
          .pill.incident .timer, .pill.incident button { grid-column: 1 / -1; }
          .pill.incident .timer { justify-self: start; }
          .pill.incident button { box-sizing: border-box; display: block; width: 100%; text-align: center; }
        }
        @media (prefers-reduced-motion: reduce) {
          .glow, .bot.pulse, .pill.attention { animation: none; }
        }
      </style>
      <div class="glow hidden" part="glow"></div>
      <div class="shield" part="shield"></div>
      <div class="pill hidden" part="pill"></div>
    `;
    (document.documentElement || document).appendChild(host);
    refs = {
      glow: root.querySelector('.glow'),
      shield: root.querySelector('.shield'),
      pill: root.querySelector('.pill'),
    };
    refs.shield.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      refs.pill.classList.remove('attention');
      void refs.pill.offsetWidth;
      refs.pill.classList.add('attention');
    });
    return refs;
  }

  function send(cmd, extra) {
    try {
      chrome.runtime.sendMessage({ cmd, ...(extra || {}) });
    } catch {
      /* extension reloaded; next state update rebuilds everything */
    }
  }

  function button(text, cls, onClick) {
    const b = document.createElement('button');
    b.textContent = text;
    if (cls) b.className = cls;
    b.addEventListener('click', (e) => {
      e.stopPropagation();
      onClick();
    });
    return b;
  }

  // Block real keyboard input while shielded (agent typing happens during
  // state.acting, when the shield is down - so it is never affected).
  ['keydown', 'keypress', 'keyup'].forEach((type) =>
    window.addEventListener(
      type,
      (e) => {
        if (shieldActive && !(host && e.composedPath().includes(host))) {
          e.stopImmediatePropagation();
          e.preventDefault();
        }
      },
      true,
    ),
  );

  // ── Render ─────────────────────────────────────────────────────────────────
  function render() {
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
    const incident = state && state.handover && state.handover.kind === 'security_incident';
    // A security incident is fail-safe UI: it remains visible through service
    // reconnects and even when the optional everyday in-page controls are off.
    const active =
      state &&
      state.agent_status &&
      state.agent_status !== 'idle' &&
      (incident || (enabled && state.online));
    if (!active) {
      shieldActive = false;
      if (host) {
        host.remove();
        host = null;
        refs = null;
      }
      return;
    }

    const { glow, shield, pill } = ensureHost();
    const s = state;
    const working = s.agent_status === 'running' && !s.handover;
    const paused = s.agent_status === 'paused';

    glow.classList.remove('hidden');
    glow.classList.toggle('static', paused || !!s.handover);
    glow.classList.toggle('incident', !!incident);

    shieldActive = working && !s.acting;
    shield.classList.toggle('active', shieldActive);

    pill.classList.remove('hidden');
    pill.classList.toggle('incident', !!incident);
    pill.replaceChildren();

    const bot = document.createElement('span');
    bot.className = 'bot' + (working ? ' pulse' : '') + (incident ? ' incident' : '');
    pill.appendChild(bot);

    const label = document.createElement('span');
    label.className = 'label';
    pill.appendChild(label);

    if (incident) {
      label.innerHTML =
        '<b>Security pause: check this page</b>' +
        'Suspicious instructions could not be safely removed. Sentinel hid this page from the AI. ' +
        'Review or change it yourself, then ask Sentinel to inspect a fresh copy.';
      const timer = document.createElement('span');
      timer.className = 'timer';
      const tick = () => {
        const left = Math.max(0, Math.round(s.handover.expires_at - Date.now() / 1000));
        timer.textContent = left >= 60 ? `${Math.floor(left / 60)}m${left % 60}s` : `${left}s`;
      };
      tick();
      countdownTimer = setInterval(tick, 1000);
      const recheck = button(
        s.handover.resolution_pending ? 'Re-checking…' : 'Re-check page',
        'amber',
        () => send('handover_complete', { id: s.handover.handover_id }),
      );
      recheck.disabled = !!s.handover.resolution_pending;
      pill.append(
        timer,
        recheck,
        button('Open Sentinel', '', () => send('open_panel')),
        button('Stop', 'red', () => send('stop')),
      );
    } else if (s.handover) {
      label.innerHTML = '<b>Your turn</b> - ';
      label.appendChild(document.createTextNode(s.handover.reason || 'the agent needs your help'));
      const timer = document.createElement('span');
      timer.className = 'timer';
      const tick = () => {
        const left = Math.max(0, Math.round(s.handover.expires_at - Date.now() / 1000));
        timer.textContent = left >= 60 ? `${Math.floor(left / 60)}m${left % 60}s` : `${left}s`;
      };
      tick();
      countdownTimer = setInterval(tick, 1000);
      const note = document.createElement('input');
      note.placeholder = 'optional note for the agent…';
      note.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') send('handover_complete', { id: s.handover.handover_id, note: note.value });
      });
      pill.append(
        timer,
        note,
        button('Done - continue', 'amber', () =>
          send('handover_complete', { id: s.handover.handover_id, note: note.value }),
        ),
      );
    } else if (paused) {
      label.innerHTML = '<b>You’re in control</b>';
      pill.append(
        button('Give control back', 'amber', () => send('resume')),
        button('Open chat', '', () => send('open_panel')),
        button('Stop', 'red', () => send('stop')),
      );
    } else if (s.agent_status === 'stopping') {
      label.innerHTML = '<b>Stopping…</b>';
    } else {
      label.innerHTML = '<b>Working on task</b>';
      if (s.task) label.title = s.task;
      pill.append(
        button('Take over', 'dark', () => send('pause')),
        button('Open chat', '', () => send('open_panel')),
        button('Stop', 'red', () => send('stop')),
      );
    }
  }

  // ── State plumbing ─────────────────────────────────────────────────────────
  chrome.storage.session.get('sentinelState').then((data) => {
    state = data.sentinelState || null;
    render();
  });
  chrome.storage.local.get('inPageVisuals').then((data) => {
    enabled = data.inPageVisuals !== false;
    render();
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'session' && changes.sentinelState) {
      state = changes.sentinelState.newValue || null;
      render();
    }
    if (area === 'local' && changes.inPageVisuals) {
      enabled = changes.inPageVisuals.newValue !== false;
      render();
    }
  });
})();
