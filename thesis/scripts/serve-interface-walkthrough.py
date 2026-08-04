#!/usr/bin/env python3
"""Serve a redacted, deterministic walkthrough of Sentinel's production UI.

This helper is for thesis figure capture.  It does not call a model, launch a
browser agent, touch ``sentinel/data``, or run a benchmark.  It uses the real
policy engine, event models, event hub, trace/history stores, approval and
handover managers, REST/WebSocket API, built extension bundle, and in-page
control script.  The walkthrough therefore documents implemented interface
states while remaining explicitly separate from empirical benchmark evidence.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from aiohttp import web


REPOSITORY = Path(__file__).resolve().parents[2]
SENTINEL = REPOSITORY / "sentinel"
HOST = "127.0.0.1"
PORT = 18765
# Keep the walkthrough separate from an installed Sentinel extension, whose
# production bundle listens on 8765. The served copy is rewritten in memory.
os.environ["SENTINEL_PORT"] = str(PORT)
os.environ["SENTINEL_DEV_ALLOW_ANY_ORIGIN"] = "1"
sys.path.insert(0, str(SENTINEL))

from server.api import build_app  # noqa: E402
from server.config import ConfigStore, EXTENSION_DIST  # noqa: E402
from server.conversations import ConversationStore  # noqa: E402
from server.events import (  # noqa: E402
	ActionAudit,
	EnforcementDecision,
	EventHub,
	LLMCall,
	OperatorMessage,
	PromptInjectionDetected,
	PromptInjectionSanitized,
	StatusChanged,
	StepEvent,
	TaskDone,
	TaskStarted,
)
from server.governance import ApprovalManager, HandoverManager, PolicyEngine  # noqa: E402
from server.history import HistoryStore  # noqa: E402
from server.labels import LabelStore  # noqa: E402
from server.traces import TraceStore  # noqa: E402


MODEL = "qwen3.5:27b"
PROVIDER = "ollama"
LIVE_RUN = "b1c2d3e4"
ACTIVITY_RUN = "c0ffee12"
LIVE_TASK = "Compare the two public policy summaries and prepare a concise note; do not change any settings."
ACTIVITY_TASK = "Review a public project page and prepare an update; do not submit changes without approval."


class WalkthroughBrowser:
	status = "connected"
	extension_seen = True

	def mark_extension_seen(self, _extension_id: str | None) -> None:
		self.extension_seen = True

	def refresh_domain_policy(self) -> None:
		return None


class WalkthroughRunner:
	"""Small API-compatible status source; no AgentRunner is started."""

	def __init__(self, hub: EventHub, browser: WalkthroughBrowser, config: ConfigStore) -> None:
		self._hub = hub
		self._browser = browser
		self._config = config
		self.status = "running"
		self.task_text = LIVE_TASK
		self.run_id = LIVE_RUN
		self.conversation_id = None

	def status_dict(self) -> dict[str, Any]:
		return {
			"backend": "ok",
			"agent_status": self.status,
			"browser_status": self._browser.status,
			"extension_seen": self._browser.extension_seen,
			"task": self.task_text,
			"run_id": self.run_id,
			"model": MODEL,
			"provider": PROVIDER,
			"calls_used": 3,
			"calls_budget": 30,
			"total_tokens": 4210,
			"ws_clients": self._hub.client_count,
			"handover": None,
			"conversation_id": self.conversation_id,
		}

	def _set_status(self, status: str) -> None:
		self.status = status
		self._hub.emit(
			StatusChanged(
				run_id=self.run_id,
				agent_status=status,
				browser_status=self._browser.status,
				extension_seen=self._browser.extension_seen,
				task=self.task_text,
				model=MODEL,
			)
		)

	def pause(self) -> None:
		self._set_status("paused")

	def resume(self) -> None:
		self._set_status("running")

	def stop(self) -> None:
		self._set_status("stopping")

	async def force_reset(self) -> None:
		self._set_status("running")

	def activate_conversation(self, conversation_id: str) -> None:
		self.conversation_id = conversation_id

	async def handle_message(self, _text: str) -> dict[str, Any]:
		return {"kind": "steer", "run_id": self.run_id, "conversation_id": None}

	async def start_task(self, _task: str, _max_steps: int | None = None) -> str:
		return self.run_id


def _decision_event(
	*,
	run_id: str,
	action: str,
	url: str,
	verdict: str,
	rule: str,
	reason: str,
	action_id: str,
	risk_score: int,
	capabilities: list[str],
) -> EnforcementDecision:
	return EnforcementDecision(
		run_id=run_id,
		action=action,
		params_preview="{redacted test parameters}",
		url=url,
		verdict=verdict,
		rule=rule,
		reason=reason,
		mode="enforce",
		decision_ms=0.7,
		enforcement_ms=1.4,
		action_id=action_id,
		risk_score=risk_score,
		risk_factors=["scripted walkthrough"],
		capabilities=capabilities,
		taint_labels=["untrusted_web"],
		target_origin="https://catalog.example.test",
		params_digest=(action_id * 8)[:64],
	)


def _audit_pair(hub: EventHub, decision: EnforcementDecision, outcome: str) -> None:
	common = dict(
		run_id=decision.run_id,
		action_id=decision.action_id or "walkthrough-action",
		action=decision.action,
		url=decision.url,
		target_origin=decision.target_origin,
		capabilities=decision.capabilities,
		risk_score=decision.risk_score,
		enforcement_ms=decision.enforcement_ms,
		risk_factors=decision.risk_factors,
		taint_labels=decision.taint_labels,
		params_digest=decision.params_digest or ("0" * 64),
		verdict=decision.verdict,
	)
	hub.emit(ActionAudit(phase="attempted", outcome="pending", **common))
	hub.emit(ActionAudit(phase="completed", outcome=outcome, duration_ms=18.0, **common))


def seed_activity(
	hub: EventHub,
	history: HistoryStore,
	policy: PolicyEngine,
	config: ConfigStore,
) -> None:
	started = time.time() - 52.4
	hub.emit(
		TaskStarted(
			run_id=ACTIVITY_RUN,
			ts=started,
			task=ACTIVITY_TASK,
			max_steps=30,
			model=MODEL,
			provider=PROVIDER,
		)
	)

	allow = policy.evaluate("click", {"index": 7}, "https://catalog.example.test/projects")
	allow_event = _decision_event(
		run_id=ACTIVITY_RUN,
		action="click",
		url="https://catalog.example.test/projects",
		verdict="allowed",
		rule=allow.rule,
		reason=allow.reason,
		action_id="a11a11a1",
		risk_score=18,
		capabilities=["page_read"],
	)
	hub.emit(allow_event)
	_audit_pair(hub, allow_event, "executed")

	blocked = policy.evaluate("write_file", {"path": "[redacted]"}, None)
	blocked_event = _decision_event(
		run_id=ACTIVITY_RUN,
		action="write_file",
		url="https://catalog.example.test/projects",
		verdict="blocked",
		rule=blocked.rule,
		reason=blocked.reason,
		action_id="b22b22b2",
		risk_score=72,
		capabilities=["local_write"],
	)
	hub.emit(blocked_event)
	_audit_pair(hub, blocked_event, "blocked")

	enforcement = {
		"decisions": {"allowed": 1, "blocked": 1},
		"decision_count": 2,
		"decision_ms_total": 1.4,
		"decision_ms_mean": 0.7,
		"decision_ms_max": 0.8,
		"enforcement_ms_total": 2.8,
		"enforcement_ms_mean": 1.4,
		"enforcement_ms_max": 1.5,
		"human_wait_s": 0.0,
		"approval_wait_s": 0.0,
		"handoff_wait_s": 0.0,
		"incident_wait_s": 0.0,
		"security_incidents": 0,
		"human_interventions": 0,
		"prompt_injection_detections": 0,
		"approval_prompts": 0,
		"approval_reuses": 0,
		"actions_attempted": 2,
		"actions_completed": 2,
	}
	hub.emit(
		TaskDone(
			run_id=ACTIVITY_RUN,
			success=True,
			final_result="Public information reviewed; no settings were changed.",
			steps=3,
			duration_s=52.4,
			usage={"prompt_tokens": 3110, "completion_tokens": 740, "total_tokens": 3850, "by_model": {MODEL: 3850}},
			enforcement=enforcement,
		)
	)
	history.append(
		{
			"run_id": ACTIVITY_RUN,
			"task": ACTIVITY_TASK,
			"started_at": started,
			"duration_s": 52.4,
			"conversation_id": None,
			"model": MODEL,
			"provider": PROVIDER,
			"policy_mode": "enforce",
			"policies": config.get().policies.model_dump(mode="json"),
			"status": "done",
			"success": True,
			"final_result": "Public information reviewed; no settings were changed.",
			"steps": 3,
			"llm_calls": 3,
			"total_tokens": 3850,
			"by_model": {MODEL: 3850},
			"enforcement": enforcement,
		}
	)


def seed_live_run(hub: EventHub, policy: PolicyEngine) -> None:
	hub.clear_replay()
	hub.emit(OperatorMessage(run_id=LIVE_RUN, text=LIVE_TASK, kind="task"))
	hub.emit(
		TaskStarted(
			run_id=LIVE_RUN,
			task=LIVE_TASK,
			max_steps=30,
			model=MODEL,
			provider=PROVIDER,
		)
	)
	hub.emit(
		StepEvent(
			run_id=LIVE_RUN,
			step=1,
			url="https://catalog.example.test/policies",
			title="",
			evaluation_previous_goal="Opened the public policy index.",
			next_goal="Compare the two relevant public summaries.",
			actions=[{"name": "click", "params": {"index": 7}}],
		)
	)
	hub.emit(
		LLMCall(
			run_id=LIVE_RUN,
			model=MODEL,
			provider=PROVIDER,
			latency_ms=1840,
			prompt_tokens=3280,
			completion_tokens=930,
			total_tokens=4210,
			calls_used=3,
			calls_budget=30,
		)
	)
	allow = policy.evaluate("click", {"index": 7}, "https://catalog.example.test/policies")
	allow_event = _decision_event(
		run_id=LIVE_RUN,
		action="click",
		url="https://catalog.example.test/policies",
		verdict="allowed",
		rule=allow.rule,
		reason=allow.reason,
		action_id="c33c33c3",
		risk_score=16,
		capabilities=["page_read"],
	)
	hub.emit(allow_event)
	_audit_pair(hub, allow_event, "executed")


def walkthrough_page() -> str:
	"""Neutral test page plus the production in-page control script."""
	return """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
  <title>Public policy catalogue - walkthrough</title>
  <style>
    :root { color: #171717; background: #f5f5f4; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; }
    header { padding: 76px 7vw 22px; background: #fff; border-bottom: 1px solid #e7e5e4; }
    .eyebrow { color: #8a5a08; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; font-size: 12px; }
    h1 { margin: 10px 0 8px; font-size: 34px; letter-spacing: -.03em; }
    header p { margin: 0; color: #57534e; max-width: 720px; line-height: 1.55; }
    main { padding: 28px 7vw 60px; display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    article { background: #fff; border: 1px solid #e7e5e4; border-radius: 16px; padding: 22px; box-shadow: 0 7px 22px rgb(0 0 0 / .04); }
    h2 { margin: 0 0 8px; font-size: 19px; }
    article p { margin: 0; color: #57534e; line-height: 1.55; }
    .tag { display: inline-block; margin-top: 18px; padding: 6px 9px; border-radius: 999px; background: #fef3c7; color: #78350f; font-size: 12px; font-weight: 650; }
    .walkthrough { position: fixed; right: 16px; bottom: 14px; color: #78716c; font-size: 11px; }
  </style>
  <script>
    const sentinelListeners = [];
    let sentinelState = null;
    window.chrome = {
      storage: {
        session: { get: async () => ({ sentinelState }) },
        local: { get: async () => ({ inPageVisuals: true }) },
        onChanged: { addListener: (fn) => sentinelListeners.push(fn) },
      },
      runtime: { sendMessage: async () => ({ ok: true }) },
    };
    function publishSentinelState(next) {
      sentinelState = next;
      for (const fn of sentinelListeners) fn({ sentinelState: { newValue: next } }, 'session');
    }
    const ws = new WebSocket('ws://127.0.0.1:8765/ws');
    ws.onmessage = (message) => {
      const frame = JSON.parse(message.data);
      if (frame.type !== 'snapshot') return;
      const status = frame.status || {};
      const pending = Array.isArray(frame.pending_handovers) ? frame.pending_handovers : [];
      publishSentinelState({
        online: true,
        agent_status: status.agent_status || 'idle',
        task: status.task || null,
        acting: false,
        handover: pending.find((item) => item.kind === 'security_incident') || pending[0] || null,
        ts: Date.now(),
      });
    };
  </script>
</head>
<body>
  <header>
    <div class=\"eyebrow\">Public test catalogue</div>
    <h1>Governance policy summaries</h1>
    <p>Redacted, benign content used to document Sentinel's implemented browser controls. No account, credential, or private page is involved.</p>
  </header>
  <main>
    <article><h2>Policy summary A</h2><p>Actions are evaluated immediately before execution and recorded with a terminal outcome.</p><span class=\"tag\">Public information</span></article>
    <article><h2>Policy summary B</h2><p>Protected steps remain with the operator while ordinary reading can continue autonomously.</p><span class=\"tag\">Read-only</span></article>
  </main>
  <div class=\"walkthrough\">Scripted implementation walkthrough - redacted test data</div>
  <script src=\"/ui/content.js\"></script>
</body>
</html>""".replace("127.0.0.1:8765", f"127.0.0.1:{PORT}")


async def main() -> None:
	with tempfile.TemporaryDirectory(prefix="sentinel-interface-walkthrough-") as temp_name:
		temp = Path(temp_name)
		config = ConfigStore(temp / "config.json")
		config.update(
			{
				"model": {"provider": PROVIDER, "model": MODEL, "temperature": 0, "throttle": None, "fallback": None},
				"policies": {
					"mode": "enforce",
					"blocked_actions": ["write_file"],
					"approval_required_actions": ["upload_file"],
					"sensitive_domains": ["accounts.example.test"],
					"audit": {"store_screenshots": False, "store_model_reasoning": False},
				},
			}
		)

		hub = EventHub(replay_size=80)
		approvals = ApprovalManager(hub.emit)
		handovers = HandoverManager(hub.emit)
		policy = PolicyEngine(config)
		history = HistoryStore(temp / "history.jsonl")
		traces = TraceStore(temp / "traces", config)
		labels = LabelStore(temp / "labels.jsonl")
		conversations = ConversationStore(temp / "conversations.jsonl")
		browser = WalkthroughBrowser()
		runner = WalkthroughRunner(hub, browser, config)
		hub.status_provider = runner.status_dict
		hub.add_listener(traces.on_event)

		seed_activity(hub, history, policy, config)
		seed_live_run(hub, policy)

		current_scenario = {"name": "governed"}

		async def scenario(request: web.Request) -> web.Response:
			name = request.match_info["name"]
			if name not in {"governed", "approval", "takeover", "incident"}:
				return web.json_response({"error": "unknown scenario"}, status=404)
			approvals.cancel_all()
			handovers.cancel_all()
			current_scenario["name"] = name

			if name == "approval":
				decision = policy.evaluate(
					"upload_file",
					{"path": "[redacted benign test file]"},
					"https://catalog.example.test/submissions",
				)
				hub.emit(
					_decision_event(
						run_id=LIVE_RUN,
						action="upload_file",
						url="https://catalog.example.test/submissions",
						verdict="approval_required",
						rule=decision.rule,
						reason=decision.reason,
						action_id="d44d44d4",
						risk_score=62,
						capabilities=["file_read", "external_write"],
					)
				)
				approvals.create(
					"upload_file",
					{"path": "[redacted benign test file]"},
					"https://catalog.example.test/submissions",
					3600,
					LIVE_RUN,
					reason=decision.reason,
					risk_score=62,
					risk_factors=["file disclosure", "external write"],
					approval_key="walkthrough-upload",
					can_approve_scope=False,
				)
			elif name == "takeover":
				decision = policy.evaluate("click", {"index": 3}, "https://accounts.example.test/verify")
				hub.emit(
					_decision_event(
						run_id=LIVE_RUN,
						action="click",
						url="https://accounts.example.test/verify",
						verdict="handoff_required",
						rule=decision.rule,
						reason=decision.reason,
						action_id="e55e55e5",
						risk_score=78,
						capabilities=["authentication"],
					)
				)
				handovers.create(
					"A one-time code must be entered directly by the operator; the agent action is withheld.",
					"https://accounts.example.test/verify",
					3600,
					LIVE_RUN,
					kind="human_step",
				)
			elif name == "incident":
				hub.emit(
					PromptInjectionDetected(
						run_id=LIVE_RUN,
						url="https://catalog.example.test/community",
						score=0.93,
						severity="high",
						signals=["authority override", "instruction suppression"],
						content_hash="0" * 64,
						action_taken="observation_quarantined",
					)
				)
				request_event = handovers.create(
					"The current observation could not be sanitised with safe attribution.",
					"https://catalog.example.test/community",
					3600,
					LIVE_RUN,
					kind="security_incident",
					sanitization_status="unattributable",
					severity="high",
				)
				hub.emit(
					PromptInjectionSanitized(
						run_id=LIVE_RUN,
						url="https://catalog.example.test/community",
						status="unattributable",
						branch="none",
						regions_unattributable=1,
						residual_detected=True,
						residual_score=0.93,
						alert_emitted=False,
						visual_input_withheld=True,
						handover_id=request_event.handover_id,
					)
				)

			return web.json_response(
				{
					"scenario": name,
					"pending_approvals": approvals.pending_list(),
					"pending_handovers": handovers.pending_list(),
				}
			)

		async def manifest(_request: web.Request) -> web.Response:
			return web.json_response(
				{
					"kind": "scripted implementation walkthrough",
					"scenario": current_scenario["name"],
					"model_calls": 0,
					"browser_agent_started": False,
					"benchmark_started": False,
					"components": [
						"PolicyEngine",
						"EventHub",
						"ApprovalManager",
						"HandoverManager",
						"TraceStore",
						"HistoryStore",
						"production extension bundle",
						"production in-page control script",
					],
				}
			)

		async def extension_asset(request: web.Request) -> web.Response:
			"""Serve the production build with only its localhost port rewritten."""
			relative = request.match_info.get("path", "") or "sidepanel.html"
			path = (EXTENSION_DIST / relative).resolve()
			try:
				path.relative_to(EXTENSION_DIST.resolve())
			except ValueError:
				raise web.HTTPForbidden()
			if not path.is_file():
				raise web.HTTPNotFound()
			body = path.read_bytes()
			if path.suffix in {".js", ".html"}:
				body = body.replace(b"127.0.0.1:8765", f"127.0.0.1:{PORT}".encode())
			content_type, _encoding = mimetypes.guess_type(path.name)
			return web.Response(body=body, content_type=content_type or "application/octet-stream")

		app = build_app(
			config,
			hub,
			runner,
			approvals,
			handovers,
			browser,
			history,
			temp / "traces",
			labels,
			conversations,
		)
		app.router.add_post("/capture/scenario/{name}", scenario)
		app.router.add_get("/capture/manifest", manifest)
		app.router.add_get("/walkthrough", lambda _request: web.Response(text=walkthrough_page(), content_type="text/html"))
		app.router.add_get("/ui/{path:.*}", extension_asset)

		app_runner = web.AppRunner(app)
		await app_runner.setup()
		site = web.TCPSite(app_runner, HOST, PORT)
		await site.start()
		print(json.dumps({"ready": True, "url": f"http://{HOST}:{PORT}/walkthrough"}), flush=True)

		stop_event = asyncio.Event()
		loop = asyncio.get_running_loop()
		for sig in (signal.SIGINT, signal.SIGTERM):
			loop.add_signal_handler(sig, stop_event.set)
		await stop_event.wait()
		approvals.cancel_all()
		handovers.cancel_all()
		traces.close_all()
		await app_runner.cleanup()


if __name__ == "__main__":
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		pass
