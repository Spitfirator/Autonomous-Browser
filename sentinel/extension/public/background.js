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
let state = {
  online: false,
  agent_status: 'idle',
  task: null,
  acting: false,
  handover: null, // {handover_id, reason, expires_at}
  ts: 0,
};

function pushState(patch) {
  state = { ...state, ...patch, ts: Date.now() };
  chrome.storage.session.set({ sentinelState: state }).catch(() => {});
}

let ws = null;
let connecting = false;

function connect() {
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
        pushState({
          online: true,
          agent_status: s.agent_status ?? 'idle',
          task: s.task ?? null,
          acting: false,
          handover: (frame.pending_handovers && frame.pending_handovers[0]) || s.handover || null,
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
        pushState({
          handover: { handover_id: frame.handover_id, reason: frame.reason, expires_at: frame.expires_at },
        });
        break;
      case 'control_returned':
        pushState({ handover: null });
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

connect();
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
    case 'handover_complete':
      post(`/api/handover/${msg.id}/complete`, { note: msg.note || '' });
      return true;
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
