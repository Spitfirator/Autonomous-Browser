#!/usr/bin/env node

/*
 * Render thesis figures from the production extension bundle using synthetic,
 * redacted state. The script never starts Sentinel, a browser-agent run, or a
 * benchmark. It requires Playwright on NODE_PATH and an existing
 * sentinel/extension/dist build.
 */

const { createRequire } = require('node:module');
const { dirname, join, resolve } = require('node:path');
const { readFile } = require('node:fs/promises');

const localRequire = createRequire(__filename);
const { chromium } = localRequire('playwright');

const repositoryRoot = resolve(dirname(__filename), '..', '..');
const extensionDist = join(repositoryRoot, 'sentinel', 'extension', 'dist');
const figureDir = join(repositoryRoot, 'thesis', 'figures');
const fixedNow = Date.UTC(2026, 6, 30, 11, 30, 0) / 1000;
const runId = 'fixture-run-20260730';

const config = {
  model: {
    provider: 'ollama',
    model: 'qwen3.5:27b',
    temperature: 0,
    throttle: null,
    fallback: null,
  },
  policies: {
    mode: 'enforce',
    domain_allowlist: null,
    domain_blocklist: [],
    blocked_actions: [],
    approval_required_actions: ['upload_file'],
    approval_required_domains: [],
    sensitive_domains: [],
    prompt_injection: {
      enabled: true,
      browser_sanitize: true,
      detection_threshold: 0.5,
      block_threshold: 0.8,
      hard_block_sinks: [],
      alert_after_sanitize: false,
    },
    data_flow: {
      enabled: true,
      trusted_domains: [],
      sensitive_data_verdict: 'block',
    },
    adaptive_approvals: {
      enabled: true,
      approval_risk_threshold: 45,
      grant_ttl_s: 120,
      grant_max_uses: 2,
      max_prompts_per_run: 4,
      fatigue_strategy: 'handoff',
    },
    audit: {
      store_screenshots: false,
      store_model_reasoning: false,
    },
    budgets: {
      max_steps: 30,
      max_llm_calls: 30,
      approval_timeout_s: 120,
      handover_timeout_s: 300,
    },
  },
  use_judge: false,
  pinned_extension_id: null,
};

const status = {
  backend: 'ready',
  agent_status: 'running',
  browser_status: 'connected',
  extension_seen: true,
  task: 'Review the profile settings and prepare an update; do not submit without approval.',
  run_id: runId,
  model: 'qwen3.5:27b',
  provider: 'ollama',
  calls_used: 7,
  calls_budget: 30,
  total_tokens: 12480,
  ws_clients: 1,
  conversation_id: null,
};

const approval = {
  type: 'approval_request',
  ts: fixedNow,
  seq: 14,
  run_id: runId,
  approval_id: 'fixture-approval',
  action: 'click',
  params: { index: 42, target: 'Save profile' },
  url: 'https://gitlab.example/profile',
  expires_at: fixedNow + 120,
  reason: 'This target appears to publish a consequential account change.',
  risk_score: 68,
  risk_factors: ['page write', 'consequential target'],
  approval_key: 'fixture-scope',
  can_approve_scope: true,
};

const takeover = {
  type: 'control_request',
  ts: fixedNow,
  seq: 21,
  run_id: runId,
  handover_id: 'fixture-takeover',
  reason: 'A one-time code must be entered by you; the proposed agent action is withheld.',
  url: 'https://accounts.example/verify',
  expires_at: fixedNow + 300,
  kind: 'human_step',
  sanitization_status: null,
  severity: null,
};

const incident = {
  type: 'control_request',
  ts: fixedNow,
  seq: 29,
  run_id: runId,
  handover_id: 'fixture-incident',
  reason: 'The current observation could not be sanitised with safe attribution.',
  url: 'https://forum.example/thread/42',
  expires_at: fixedNow + 300,
  kind: 'security_incident',
  sanitization_status: 'unattributable',
  severity: 'high',
};

const baseEvents = [
  {
    type: 'user_message',
    ts: fixedNow - 35,
    seq: 1,
    run_id: runId,
    text: status.task,
    kind: 'task',
  },
  {
    type: 'task_started',
    ts: fixedNow - 34,
    seq: 2,
    run_id: runId,
    task: status.task,
    max_steps: 30,
    model: status.model,
    provider: status.provider,
  },
];

function snapshot({ approvals = [], handovers = [], events = baseEvents, agentStatus = 'running' } = {}) {
  return {
    type: 'snapshot',
    ts: fixedNow,
    seq: 40,
    conversation_id: null,
    status: { ...status, agent_status: agentStatus },
    events,
    pending_approvals: approvals,
    pending_handovers: handovers,
    config,
  };
}

const history = [
  {
    run_id: runId,
    task: status.task,
    started_at: fixedNow - 47.2,
    duration_s: 47.2,
    status: 'done',
    success: true,
    steps: 9,
    llm_calls: 7,
    total_tokens: 12480,
    by_model: { 'qwen3.5:27b': 12480 },
    final_result: 'Profile options reviewed; no account change was submitted.',
    model: status.model,
    provider: status.provider,
    policy_mode: 'enforce',
    enforcement: {
      decisions: {
        allowed: 6,
        approval_required: 1,
        denied_by_human: 1,
      },
      decision_count: 7,
      decision_ms_total: 18.4,
      decision_ms_mean: 2.6,
      decision_ms_max: 4.9,
      enforcement_ms_total: 18.4,
      enforcement_ms_mean: 2.6,
      enforcement_ms_max: 4.9,
      human_wait_s: 20.7,
      approval_wait_s: 8.3,
      handoff_wait_s: 0,
      incident_wait_s: 12.4,
      security_incidents: 1,
      human_interventions: 2,
      prompt_injection_detections: 1,
      approval_prompts: 1,
      approval_reuses: 0,
      actions_attempted: 7,
      actions_completed: 6,
    },
    conversation_id: null,
  },
];

const decisions = [
  {
    seq: 13,
    ts: fixedNow - 19,
    action: 'click',
    url: 'https://gitlab.example/profile',
    verdict: 'approval_required',
    rule: 'adaptive_approval',
    reason: 'Publishing a consequential profile change requires narrow approval.',
    understood: null,
  },
  {
    seq: 28,
    ts: fixedNow - 12,
    action: 'model_input',
    url: 'https://forum.example/thread/42',
    verdict: 'blocked',
    rule: 'unresolved_observation',
    reason: 'The current page observation was withheld pending a fresh inspection.',
    understood: null,
  },
];

const traceEvents = [
  ...baseEvents,
  {
    type: 'prompt_injection_detected',
    ts: fixedNow - 15,
    seq: 25,
    run_id: runId,
    url: 'https://forum.example/thread/42',
    score: 0.91,
    severity: 'high',
    signals: ['authority override', 'instruction suppression'],
    content_hash: 'fixture-digest',
    action_taken: 'observation_quarantined',
  },
  {
    type: 'control_request',
    ...incident,
    ts: fixedNow - 14,
    seq: 26,
  },
  {
    type: 'control_returned',
    ts: fixedNow - 2,
    seq: 27,
    run_id: runId,
    handover_id: incident.handover_id,
    note: null,
    resolved_by: 'user',
    kind: 'security_incident',
  },
  {
    type: 'enforcement_decision',
    ts: fixedNow - 20,
    seq: 13,
    run_id: runId,
    action: 'click',
    params_preview: '{"index":42,"target":"Save profile"}',
    url: 'https://gitlab.example/profile',
    verdict: 'approval_required',
    rule: 'adaptive_approval',
    reason: 'Publishing a consequential profile change requires narrow approval.',
    mode: 'enforce',
    decision_ms: 3.1,
    enforcement_ms: 3.1,
    action_id: 'fixture-action',
    risk_score: 68,
    risk_factors: ['page write', 'consequential target'],
    capabilities: ['page_write'],
    taint_labels: ['untrusted_web'],
    target_origin: 'https://gitlab.example',
    params_digest: 'fixture-params-digest',
  },
  approval,
  {
    type: 'approval_resolved',
    ts: fixedNow - 11,
    seq: 15,
    run_id: runId,
    approval_id: approval.approval_id,
    approved: false,
    resolved_by: 'user',
    scope: 'once',
  },
  {
    type: 'task_done',
    ts: fixedNow,
    seq: 40,
    run_id: runId,
    success: true,
    final_result: history[0].final_result,
    steps: history[0].steps,
    duration_s: history[0].duration_s,
    usage: { total_tokens: history[0].total_tokens },
    enforcement: history[0].enforcement,
  },
];

function apiPayload(url) {
  const pathname = new URL(url).pathname;
  if (pathname === '/api/history') return history;
  if (pathname.endsWith('/decisions')) return decisions;
  if (pathname.endsWith('/events')) {
    return { run_id: runId, total: traceEvents.length, truncated: false, events: traceEvents };
  }
  if (pathname === '/api/keys') return {};
  if (pathname === '/api/actions') return [];
  return { ok: true, resolved: true, kind: null };
}

function contentType(pathname) {
  if (pathname.endsWith('.html')) return 'text/html; charset=utf-8';
  if (pathname.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (pathname.endsWith('.css')) return 'text/css; charset=utf-8';
  if (pathname.endsWith('.woff2')) return 'font/woff2';
  if (pathname.endsWith('.png')) return 'image/png';
  return 'application/octet-stream';
}

async function newFixturePage(browser, fixtureSnapshot, htmlName, viewport) {
  const context = await browser.newContext({
    viewport,
    deviceScaleFactor: 2,
    locale: 'en-GB',
    timezoneId: 'Europe/Paris',
    colorScheme: 'light',
    reducedMotion: 'reduce',
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => console.error(`page error: ${error.message}`));
  await page.addInitScript((fixedTime) => {
    Date.now = () => fixedTime;
  }, fixedNow * 1000);
  await page.route('http://sentinel-fixture.local/**', async (route) => {
    const url = new URL(route.request().url());
    const relativePath = decodeURIComponent(url.pathname).replace(/^\/+/, '') || htmlName;
    const absolutePath = resolve(extensionDist, relativePath);
    if (!absolutePath.startsWith(`${extensionDist}/`)) {
      await route.fulfill({ status: 403, body: 'forbidden' });
      return;
    }
    try {
      const body = await readFile(absolutePath);
      await route.fulfill({
        status: 200,
        contentType: contentType(relativePath),
        body,
      });
    } catch {
      await route.fulfill({ status: 404, body: 'not found' });
    }
  });
  await page.route('http://127.0.0.1:8765/**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { 'access-control-allow-origin': '*' },
      body: JSON.stringify(apiPayload(route.request().url())),
    });
  });
  await page.routeWebSocket('ws://127.0.0.1:8765/ws', (socket) => {
    setTimeout(() => socket.send(JSON.stringify(fixtureSnapshot)), 30);
    socket.onMessage(() => {});
  });
  await page.goto(`http://sentinel-fixture.local/${htmlName}`);
  return { context, page };
}

async function captureCard(browser, name, fixtureSnapshot, selector) {
  const { context, page } = await newFixturePage(
    browser,
    fixtureSnapshot,
    'sidepanel.html',
    { width: 440, height: 820 },
  );
  const card = page.locator(selector);
  await card.waitFor({ state: 'visible' });
  await card.screenshot({
    path: join(figureDir, name),
    animations: 'disabled',
  });
  await context.close();
}

async function captureActivity(browser) {
  const { context, page } = await newFixturePage(
    browser,
    snapshot({ agentStatus: 'idle' }),
    'dashboard.html',
    { width: 1320, height: 1000 },
  );
  await page.getByRole('button', { name: 'Activity' }).click();
  const taskRow = page.locator('tbody > tr').first();
  await taskRow.waitFor({ state: 'visible' });
  await taskRow.click();
  const details = page.locator('.detail-row > td');
  await details.waitFor({ state: 'visible' });
  await page.locator('.dec-panel').waitFor({ state: 'visible' });
  await details.screenshot({
    path: join(figureDir, 'interface-activity.png'),
    animations: 'disabled',
  });
  await context.close();
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    executablePath:
      process.env.SENTINEL_CAPTURE_BROWSER ||
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  });
  try {
    await captureCard(
      browser,
      'interface-approval.png',
      snapshot({ approvals: [approval] }),
      '.card.approval',
    );
    await captureCard(
      browser,
      'interface-takeover.png',
      snapshot({ handovers: [takeover] }),
      '.card.handover',
    );
    await captureCard(
      browser,
      'interface-incident.png',
      snapshot({ handovers: [incident] }),
      '.card.security-incident',
    );
    await captureActivity(browser);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
