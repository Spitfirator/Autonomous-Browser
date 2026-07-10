"""aiohttp REST + WebSocket API for the Sentinel extension.

Bound to 127.0.0.1 only. Origin middleware: requests with no Origin (curl),
chrome-extension:// origins (exact match once an id is pinned), or our own
localhost origin are allowed; everything else gets 403.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from aiohttp import WSMsgType, web
from dotenv import set_key
from pydantic import ValidationError

from server.browser import BrowserManager
from server.config import (
	BASE_URL,
	ENV_FILE,
	EXTENSION_DIST,
	KNOWN_ACTIONS,
	KNOWN_API_KEYS,
	ConfigStore,
)
from server.conversations import ConversationStore
from server.events import ConfigChanged, EventHub
from server.governance import ApprovalManager
from server.history import HistoryStore
from server.labels import LabelStore
from server.llm_factory import MissingApiKeyError
from server.runner import AgentRunner, BrowserNotReady, RunnerBusy

logger = logging.getLogger('sentinel.api')

STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')


def _json_error(status: int, message: str) -> web.Response:
	return web.json_response({'error': message}, status=status)


@web.middleware
async def origin_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
	origin = request.headers.get('Origin')
	# /api/handover/* is called by the in-page takeover overlay from whatever
	# site the agent is on — any origin is fine, the random handover id is the
	# credential (and the endpoint can only end a handover early).
	is_handover_path = request.path.startswith('/api/handover/')
	if origin is not None and not is_handover_path and os.environ.get('SENTINEL_DEV_ALLOW_ANY_ORIGIN') != '1':
		# Any chrome-extension:// origin is fine: CDP-installed unpacked extensions
		# get a fresh id per install, so exact pinning breaks on reinstall — and the
		# server is localhost-bound anyway (originless local callers bypass Origin
		# checks entirely, so pinning added no real security).
		allowed = origin.startswith('chrome-extension://') or origin in (
			BASE_URL,
			BASE_URL.replace('127.0.0.1', 'localhost'),
		)
		if not allowed:
			return _json_error(403, 'Origin not allowed')

	if request.method == 'OPTIONS':
		response: web.StreamResponse = web.Response(status=204)
	else:
		response = await handler(request)

	if origin is not None:
		response.headers['Access-Control-Allow-Origin'] = origin
		response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
		response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
	return response


# ── Handlers ─────────────────────────────────────────────────────────────────
async def get_status(request: web.Request) -> web.Response:
	runner: AgentRunner = request.app['runner']
	return web.json_response(runner.status_dict())


async def get_ping(request: web.Request) -> web.Response:
	return web.Response(text='pong')


async def post_hello(request: web.Request) -> web.Response:
	browser_manager: BrowserManager = request.app['browser_manager']
	try:
		body = await request.json()
	except json.JSONDecodeError:
		body = {}
	browser_manager.mark_extension_seen(body.get('extension_id'))
	return web.json_response({'ok': True})


async def post_message(request: web.Request) -> web.Response:
	"""Chatbot entrypoint: steers a live run, or starts a (follow-up) task when idle."""
	runner: AgentRunner = request.app['runner']
	try:
		body = await request.json()
	except json.JSONDecodeError:
		return _json_error(400, 'Invalid JSON body')
	text = (body.get('text') or '').strip()
	if not text:
		return _json_error(400, 'text is required')
	try:
		result = await runner.handle_message(text)
	except BrowserNotReady as e:
		return _json_error(503, str(e))
	except MissingApiKeyError as e:
		return _json_error(422, str(e))
	except RunnerBusy as e:   # race: run started between status check and start
		return _json_error(409, str(e))
	return web.json_response(result)


async def post_task(request: web.Request) -> web.Response:
	runner: AgentRunner = request.app['runner']
	try:
		body = await request.json()
	except json.JSONDecodeError:
		return _json_error(400, 'Invalid JSON body')
	task = (body.get('task') or '').strip()
	if not task:
		return _json_error(400, 'task is required')
	max_steps = body.get('max_steps')
	if max_steps is not None and (not isinstance(max_steps, int) or max_steps < 1):
		return _json_error(400, 'max_steps must be a positive integer')
	try:
		run_id = await runner.start_task(task, max_steps)
	except RunnerBusy as e:
		return _json_error(409, str(e))
	except BrowserNotReady as e:
		return _json_error(503, str(e))
	except MissingApiKeyError as e:
		return _json_error(422, str(e))
	return web.json_response({'run_id': run_id})


async def post_agent_control(request: web.Request) -> web.Response:
	runner: AgentRunner = request.app['runner']
	command = request.match_info['command']
	if command == 'pause':
		runner.pause()
	elif command == 'resume':
		runner.resume()
	elif command == 'stop':
		runner.stop()
	else:
		return _json_error(404, f'Unknown command {command}')
	return web.json_response({'ok': True, 'agent_status': runner.status})


async def get_config(request: web.Request) -> web.Response:
	config_store: ConfigStore = request.app['config_store']
	return web.json_response(config_store.get().model_dump(mode='json'))


async def put_config(request: web.Request) -> web.Response:
	config_store: ConfigStore = request.app['config_store']
	hub: EventHub = request.app['hub']
	browser_manager: BrowserManager = request.app['browser_manager']
	try:
		patch = await request.json()
	except json.JSONDecodeError:
		return _json_error(400, 'Invalid JSON body')
	if not isinstance(patch, dict):
		return _json_error(400, 'Body must be a JSON object')
	try:
		config = config_store.update(patch)
	except ValidationError as e:
		return web.json_response({'error': 'validation failed', 'details': json.loads(e.json())}, status=422)
	browser_manager.refresh_domain_policy()
	hub.emit(ConfigChanged(config=config.model_dump(mode='json')))
	return web.json_response(config.model_dump(mode='json'))


async def get_keys(request: web.Request) -> web.Response:
	return web.json_response({name: bool(os.environ.get(name)) for name in KNOWN_API_KEYS})


async def put_keys(request: web.Request) -> web.Response:
	try:
		body = await request.json()
	except json.JSONDecodeError:
		return _json_error(400, 'Invalid JSON body')
	name = body.get('name')
	value = body.get('value')
	if name not in KNOWN_API_KEYS:
		return _json_error(400, f'Unknown key name. Allowed: {", ".join(KNOWN_API_KEYS)}')
	if not isinstance(value, str) or not value.strip():
		return _json_error(400, 'value is required')
	ENV_FILE.touch(exist_ok=True)
	set_key(str(ENV_FILE), name, value.strip())
	os.environ[name] = value.strip()
	logger.info(f'Updated {name} in {ENV_FILE}')
	return web.json_response({'ok': True, name: True})


async def post_handover_complete(request: web.Request) -> web.Response:
	handovers = request.app['handovers']
	handover_id = request.match_info['handover_id']
	try:
		body = await request.json()
	except json.JSONDecodeError:
		body = {}
	note = body.get('note')
	if note is not None and not isinstance(note, str):
		return _json_error(400, 'note must be a string')
	if not handovers.complete(handover_id, note):
		return _json_error(404, 'Handover not found or already resolved')
	return web.json_response({'resolved': True})


async def post_approval(request: web.Request) -> web.Response:
	approvals: ApprovalManager = request.app['approvals']
	approval_id = request.match_info['approval_id']
	try:
		body = await request.json()
	except json.JSONDecodeError:
		return _json_error(400, 'Invalid JSON body')
	approve = body.get('approve')
	if not isinstance(approve, bool):
		return _json_error(400, 'approve must be a boolean')
	resolved = approvals.resolve(approval_id, approve)
	if not resolved:
		return _json_error(404, 'Approval not found or already resolved')
	return web.json_response({'resolved': True})


async def get_history(request: web.Request) -> web.Response:
	history: HistoryStore = request.app['history']
	try:
		limit = min(int(request.query.get('limit', '50')), 200)
	except ValueError:
		limit = 50
	return web.json_response(history.list(limit))


async def get_actions(request: web.Request) -> web.Response:
	return web.json_response(KNOWN_ACTIONS)


# Verdicts that aren't a block/pause the operator needs explained.
_NON_EXPLAIN_VERDICTS = {'allowed', 'handoff_returned'}


async def get_run_decisions(request: web.Request) -> web.Response:
	"""Non-allow enforcement decisions for one run (the blocks/pauses whose reason
	the operator sees), each tagged with any 'understood?' tick they've left."""
	traces_dir: Path = request.app['traces_dir']
	labels: LabelStore = request.app['labels']
	run_id = request.match_info['run_id']
	if not run_id.isalnum():   # run ids are uuid4().hex[:8] — blocks path traversal
		return _json_error(400, 'invalid run_id')
	events_path = traces_dir / run_id / 'events.jsonl'
	if not events_path.exists():
		return web.json_response([])
	understood = labels.for_run(run_id)
	rows: list[dict[str, Any]] = []
	try:
		for line in events_path.read_text().splitlines():
			line = line.strip()
			if not line:
				continue
			try:
				ev = json.loads(line)
			except json.JSONDecodeError:
				continue
			if ev.get('type') != 'enforcement_decision' or ev.get('verdict') in _NON_EXPLAIN_VERDICTS:
				continue
			seq = ev.get('seq')
			rows.append({
				'seq': seq,
				'ts': ev.get('ts'),
				'action': ev.get('action'),
				'url': ev.get('url'),
				'verdict': ev.get('verdict'),
				'rule': ev.get('rule'),
				'reason': ev.get('reason'),
				'understood': understood.get(seq),
			})
	except OSError as e:
		logger.warning(f'Failed to read trace events for {run_id}: {e}')
		return _json_error(500, 'failed to read trace')
	return web.json_response(rows)


async def post_understood(request: web.Request) -> web.Response:
	"""Record (or clear, with understood=null) the operator's 'could you tell why?'
	tick for one decision in a run."""
	labels: LabelStore = request.app['labels']
	run_id = request.match_info['run_id']
	if not run_id.isalnum():
		return _json_error(400, 'invalid run_id')
	try:
		seq = int(request.match_info['seq'])
	except ValueError:
		return _json_error(400, 'seq must be an integer')
	try:
		body = await request.json()
	except json.JSONDecodeError:
		return _json_error(400, 'Invalid JSON body')
	understood = body.get('understood')
	if understood is not None and not isinstance(understood, bool):
		return _json_error(400, 'understood must be a boolean or null')
	labels.set_understood(run_id, seq, understood)
	return web.json_response({'ok': True})


async def _ready_for_conversation_change(request: web.Request, body: dict[str, Any]) -> web.Response | None:
	"""Shared guard for create/activate: a live run blocks the switch unless
	force=true, which hard-resets the runner (the new-chat recovery path)."""
	runner: AgentRunner = request.app['runner']
	if runner.status == 'idle':
		return None
	if body.get('force'):
		await runner.force_reset()
		return None
	return _json_error(409, f'A task is already {runner.status} — stop it first or pass force')


async def post_conversation_create(request: web.Request) -> web.Response:
	runner: AgentRunner = request.app['runner']
	conversations: ConversationStore = request.app['conversations']
	try:
		body = await request.json()
	except json.JSONDecodeError:
		body = {}
	blocked = await _ready_for_conversation_change(request, body)
	if blocked is not None:
		return blocked
	conv = conversations.create(body.get('title'))
	runner.activate_conversation(conv['conversation_id'])
	return web.json_response(conv)


async def get_conversations(request: web.Request) -> web.Response:
	runner: AgentRunner = request.app['runner']
	conversations: ConversationStore = request.app['conversations']
	out = conversations.list()
	for conv in out:
		conv['active'] = conv['conversation_id'] == runner.conversation_id
	return web.json_response(out)


async def get_conversation(request: web.Request) -> web.Response:
	conversations: ConversationStore = request.app['conversations']
	conversation_id = request.match_info['conversation_id']
	if not conversation_id.isalnum():
		return _json_error(400, 'invalid conversation_id')
	conv = conversations.get(conversation_id)
	if conv is None:
		return _json_error(404, 'conversation not found')
	return web.json_response(conv)


async def post_conversation_activate(request: web.Request) -> web.Response:
	runner: AgentRunner = request.app['runner']
	conversations: ConversationStore = request.app['conversations']
	conversation_id = request.match_info['conversation_id']
	if not conversation_id.isalnum():
		return _json_error(400, 'invalid conversation_id')
	if not conversations.exists(conversation_id):
		return _json_error(404, 'conversation not found')
	try:
		body = await request.json()
	except json.JSONDecodeError:
		body = {}
	blocked = await _ready_for_conversation_change(request, body)
	if blocked is not None:
		return blocked
	runner.activate_conversation(conversation_id)
	return web.json_response({'conversation_id': conversation_id})


async def post_agent_reset(request: web.Request) -> web.Response:
	"""Hard-reset a wedged runner to idle without restarting the server."""
	runner: AgentRunner = request.app['runner']
	await runner.force_reset()
	return web.json_response({'ok': True, 'agent_status': runner.status})


async def get_run_events(request: web.Request) -> web.Response:
	"""Full event trace for one run, for the Activity tab's inline Logs panel.

	When the trace exceeds `limit` lines we keep the LAST `limit` events and set
	truncated=true — the anchors the operator jumps to (decisions, approvals,
	the outcome) cluster late in a run."""
	traces_dir: Path = request.app['traces_dir']
	run_id = request.match_info['run_id']
	if not run_id.isalnum():   # run ids are uuid4().hex[:8] — blocks path traversal
		return _json_error(400, 'invalid run_id')
	try:
		limit = min(int(request.query.get('limit', '2000')), 5000)
	except ValueError:
		limit = 2000
	limit = max(1, limit)
	events_path = traces_dir / run_id / 'events.jsonl'
	if not events_path.exists():
		return web.json_response({'run_id': run_id, 'total': 0, 'truncated': False, 'events': []})
	events: list[dict[str, Any]] = []
	total = 0
	try:
		for line in events_path.read_text().splitlines():
			line = line.strip()
			if not line:
				continue
			try:
				ev = json.loads(line)
			except json.JSONDecodeError:   # torn last line after a crash
				continue
			total += 1
			ev.pop('screenshot_b64', None)   # traces null it already; belt and braces
			events.append(ev)
	except OSError as e:
		logger.warning(f'Failed to read trace events for {run_id}: {e}')
		return _json_error(500, 'failed to read trace')
	truncated = total > limit
	if truncated:
		events = events[-limit:]
	return web.json_response({'run_id': run_id, 'total': total, 'truncated': truncated, 'events': events})


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
	hub: EventHub = request.app['hub']
	approvals: ApprovalManager = request.app['approvals']
	handovers = request.app['handovers']
	config_store: ConfigStore = request.app['config_store']

	ws = web.WebSocketResponse(heartbeat=30)
	await ws.prepare(request)
	queue = hub.register()
	logger.info(f'WS client connected ({hub.client_count} total)')

	async def pump() -> None:
		while True:
			payload = await queue.get()
			await ws.send_str(payload)

	sender = asyncio.create_task(pump())
	try:
		await ws.send_json(
			hub.snapshot(approvals.pending_list(), config_store.get().model_dump(mode='json'), handovers.pending_list())
		)
		async for msg in ws:
			if msg.type == WSMsgType.TEXT and msg.data == '{"type":"ping"}':
				await ws.send_str('{"type":"pong"}')
			elif msg.type == WSMsgType.ERROR:
				break
	finally:
		sender.cancel()
		hub.unregister(queue)
		logger.info(f'WS client disconnected ({hub.client_count} total)')
	return ws


async def get_setup(request: web.Request) -> web.Response:
	page = open(os.path.join(STATIC_DIR, 'setup.html')).read()
	page = page.replace('{{DIST_PATH}}', str(EXTENSION_DIST))
	return web.Response(text=page, content_type='text/html')


def build_app(
	config_store: ConfigStore,
	hub: EventHub,
	runner: AgentRunner,
	approvals: ApprovalManager,
	handovers: Any,
	browser_manager: BrowserManager,
	history: HistoryStore,
	traces_dir: Path,
	labels: LabelStore,
	conversations: ConversationStore,
) -> web.Application:
	app = web.Application(middlewares=[origin_middleware], client_max_size=1024 * 1024)
	app['config_store'] = config_store
	app['hub'] = hub
	app['runner'] = runner
	app['approvals'] = approvals
	app['handovers'] = handovers
	app['browser_manager'] = browser_manager
	app['history'] = history
	app['traces_dir'] = traces_dir
	app['labels'] = labels
	app['conversations'] = conversations

	app.router.add_get('/api/status', get_status)
	app.router.add_get('/api/ping', get_ping)
	app.router.add_post('/api/hello', post_hello)
	app.router.add_post('/api/task', post_task)
	app.router.add_post('/api/message', post_message)
	app.router.add_post('/api/agent/reset', post_agent_reset)   # before the {command} catch-all
	app.router.add_post('/api/agent/{command}', post_agent_control)
	app.router.add_post('/api/conversations', post_conversation_create)
	app.router.add_get('/api/conversations', get_conversations)
	app.router.add_get('/api/conversations/{conversation_id}', get_conversation)
	app.router.add_post('/api/conversations/{conversation_id}/activate', post_conversation_activate)
	app.router.add_get('/api/config', get_config)
	app.router.add_put('/api/config', put_config)
	app.router.add_get('/api/keys', get_keys)
	app.router.add_put('/api/keys', put_keys)
	app.router.add_post('/api/approvals/{approval_id}', post_approval)
	app.router.add_post('/api/handover/{handover_id}/complete', post_handover_complete)
	app.router.add_get('/api/history', get_history)
	app.router.add_get('/api/traces/{run_id}/decisions', get_run_decisions)
	app.router.add_post('/api/traces/{run_id}/decisions/{seq}', post_understood)
	app.router.add_get('/api/traces/{run_id}/events', get_run_events)
	app.router.add_get('/api/actions', get_actions)
	app.router.add_get('/ws', ws_handler)
	app.router.add_get('/setup', get_setup)
	app.router.add_get('/', get_setup)
	return app
