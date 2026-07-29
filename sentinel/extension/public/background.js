// Sentinel service worker: owns the backend WebSocket and relays a compact
// control state to content scripts via chrome.storage.session. Also proxies
// commands (its fetches carry the chrome-extension:// origin the backend pins).

const BASE = 'http://127.0.0.1:8765';
const WS_URL = 'ws://127.0.0.1:8765/ws';

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
// Let content scripts read storage.session.
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' }).catch(() => {});

const hello = () =>
  fetch(`${BASE}/api/hello`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ extension_id: chrome.runtime.id }),
  }).catch(() => {});

chrome.runtime.onInstalled.addListener(hello);
chrome.runtime.onStartup.addListener(hello);
hello();

// ── Control state relay ──────────────────────────────────────────────────────
const DEFAULT_STATE = {
  online: false,
  agent_status: 'idle',
  task: null,
  acting: false,
  handover: null, // compact ControlRequest, including security-incident metadata
  ts: 0,
};
let state = { ...DEFAULT_STATE };
let stateHydrated = false;

function pushState(patch) {
  state = { ...state, ...patch, ts: Date.now() };
  chrome.storage.session.set({ sentinelState: state }).catch(() => {});
}

let ws = null;
let connecting = false;

function connect() {
  if (!stateHydrated) return;
  if (connecting || (ws && ws.readyState <= WebSocket.OPEN)) return;
  connecting = true;
  try {
    ws = new WebSocket(WS_URL);
  } catch {
    connecting = false;
    return;
  }

  ws.onopen = () => {
    connecting = false;
    hello();
  };

  ws.onmessage = (msg) => {
    let frame;
    try {
      frame = JSON.parse(msg.data);
    } catch {
      return;
    }
    switch (frame.type) {
      case 'snapshot': {
        const s = frame.status || {};
        const pending = Array.isArray(frame.pending_handovers) ? frame.pending_handovers : null;
        const handover = pending
          ? pending.find((request) => request.kind === 'security_incident') || pending[0] || null
          : s.handover || null;
        pushState({
          online: true,
          agent_status: s.agent_status ?? 'idle',
          task: s.task ?? null,
          acting: false,
          handover,
        });
        break;
      }
      case 'status_changed':
        pushState({ online: true, agent_status: frame.agent_status, task: frame.task });
        break;
      case 'task_started':
        pushState({ online: true, task: frame.task });
        break;
      case 'action_executing':
        pushState({ acting: true });
        break;
      case 'action_done':
        pushState({ acting: false });
        break;
      case 'control_request':
        {
          const handover = {
            handover_id: frame.handover_id,
            reason: frame.reason,
            url: frame.url,
            expires_at: frame.expires_at,
            kind: frame.kind || 'human_step',
            sanitization_status: frame.sanitization_status || null,
            severity: frame.severity || null,
            resolution_pending: false,
          };
          // Never let a lower-priority request hide an unresolved security
          // incident while the service worker is reconnecting.
          if (state.handover?.kind !== 'security_incident' || handover.kind === 'security_incident') {
            pushState({ handover });
          }
        }
        break;
      case 'control_returned':
        if (!state.handover || state.handover.handover_id === frame.handover_id) {
          pushState({ handover: null });
        }
        break;
    }
  };

  ws.onclose = () => {
    connecting = false;
    ws = null;
    pushState({ online: false, acting: false });
    setTimeout(connect, 2000);
  };

  ws.onerror = () => {
    try {
      ws && ws.close();
    } catch {}
  };
}

// A Manifest V3 service worker can restart while the backend is unreachable.
// Hydrate the last compact state before opening the socket so an unresolved
// security incident is not overwritten by a blank in-memory default.
chrome.storage.session
  .get('sentinelState')
  .then((data) => {
    state = {
      ...DEFAULT_STATE,
      ...(data.sentinelState || {}),
      online: false,
      acting: false,
    };
  })
  .catch(() => {})
  .finally(() => {
    stateHydrated = true;
    pushState({});
    connect();
  });
// Belt-and-braces: an alarm re-arms the socket after service-worker sleeps.
chrome.alarms.create('sentinel-ws', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'sentinel-ws') connect();
});

// ── Commands from content scripts / panel ────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const post = (path, body) =>
    fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    })
      .then((r) => sendResponse({ ok: r.ok }))
      .catch(() => sendResponse({ ok: false }));

  switch (msg && msg.cmd) {
    case 'pause':
    case 'resume':
    case 'stop':
      post(`/api/agent/${msg.cmd}`);
      return true;
    case 'handover_complete': {
      const matching = state.handover?.handover_id === msg.id;
      if (matching) {
        pushState({ handover: { ...state.handover, resolution_pending: true } });
      }
      fetch(`${BASE}/api/handover/${msg.id}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: msg.note || '' }),
      })
        .then((r) => {
          if (!r.ok && matching && state.handover?.handover_id === msg.id) {
            pushState({ handover: { ...state.handover, resolution_pending: false } });
          }
          sendResponse({ ok: r.ok });
        })
        .catch(() => {
          if (matching && state.handover?.handover_id === msg.id) {
            pushState({ handover: { ...state.handover, resolution_pending: false } });
          }
          sendResponse({ ok: false });
        });
      return true;
    }
    case 'open_panel': {
      const tabId = sender && sender.tab && sender.tab.id;
      const opts = tabId != null ? { tabId } : { windowId: sender?.tab?.windowId };
      chrome.sidePanel
        .open(opts)
        .then(() => sendResponse({ ok: true }))
        .catch(() => sendResponse({ ok: false }));
      return true;
    }
  }
  return false;
});
