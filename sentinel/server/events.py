"""WebSocket event models and the fan-out EventHub.

Every frame on /ws is one SentinelEvent serialized as flat JSON with a `type`
discriminator plus shared `ts` / `seq` / `run_id` fields. The extension mirrors
these shapes in src/shared/types.ts — keep them in sync.
"""

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field

logger = logging.getLogger('sentinel.events')

AgentStatus = Literal['idle', 'running', 'paused', 'stopping']
Verdict = Literal[
	'allowed',
	'approval_reused',       # covered by a narrow, explicit run-scoped grant
	'blocked',
	'approval_required',
	'denied_by_human',
	'denied_timeout',
	'denied_cancelled',
	'handoff_required',      # policy forced control to the human (sensitive domain)
	'handoff_returned',      # human finished the sensitive step and handed back
	'handoff_timeout',       # nobody responded to the forced handoff
	'handoff_cancelled',     # the run stopped before control was returned
	'shadow_blocked',        # shadow mode: would have blocked, allowed through
	'shadow_approval_required',
	'shadow_handoff_required',
]


class SentinelEvent(BaseModel):
	type: str
	ts: float = Field(default_factory=time.time)
	seq: int = 0
	run_id: str | None = None
	conversation_id: str | None = None


class StatusChanged(SentinelEvent):
	type: Literal['status_changed'] = 'status_changed'
	agent_status: AgentStatus
	browser_status: str
	extension_seen: bool
	task: str | None = None
	model: str


class TaskStarted(SentinelEvent):
	type: Literal['task_started'] = 'task_started'
	task: str
	max_steps: int
	model: str
	provider: str


class StepEvent(SentinelEvent):
	type: Literal['step'] = 'step'
	step: int
	url: str
	title: str
	evaluation_previous_goal: str | None = None
	next_goal: str | None = None
	memory: str | None = None
	thinking: str | None = None
	actions: list[dict[str, Any]] = Field(default_factory=list)   # [{name, params}]
	screenshot_b64: str | None = None


class LLMCall(SentinelEvent):
	type: Literal['llm_call'] = 'llm_call'
	model: str
	provider: str
	latency_ms: int
	prompt_tokens: int | None = None
	completion_tokens: int | None = None
	total_tokens: int | None = None
	calls_used: int
	calls_budget: int
	is_fallback: bool = False


class PromptInjectionDetected(SentinelEvent):
	"""A privacy-preserving alert: payload text is never included in the event."""

	type: Literal['prompt_injection_detected'] = 'prompt_injection_detected'
	url: str | None = None
	score: float
	severity: Literal['low', 'medium', 'high', 'critical']
	signals: list[str] = Field(default_factory=list)
	content_hash: str
	action_taken: Literal[
		'model_warned',
		'model_sanitized',
		'observation_quarantined',
		'shadow_monitored',
	]


class PromptInjectionSanitized(SentinelEvent):
	"""Per-attempt record of what observation sanitisation achieved.

	Emitted on every attempt, unlike the deduplicated detection alert: a flat
	benchmark result has to be diagnosable without re-reading trajectories.
	`status` distinguishes confirmed removal from a partial removal that left
	detector-positive content behind, and `branch` says which attribution
	strategy fired. No payload text is included.
	"""

	type: Literal['prompt_injection_sanitized'] = 'prompt_injection_sanitized'
	url: str | None = None
	status: Literal['removed', 'residual', 'unattributable', 'not_attempted']
	branch: Literal['line', 'window', 'structural', 'none']
	regions_targeted: int = 0
	regions_changed: int = 0
	regions_unattributable: int = 0
	residual_detected: bool = False
	residual_score: float = 0.0
	alert_emitted: bool = True
	visual_input_withheld: bool = False
	handover_id: str | None = None


class EnforcementDecision(SentinelEvent):
	type: Literal['enforcement_decision'] = 'enforcement_decision'
	action: str
	params_preview: str
	url: str | None = None
	verdict: Verdict
	rule: str
	reason: str
	mode: str = 'enforce'
	decision_ms: float = 0.0   # policy evaluation latency (excludes human wait)
	enforcement_ms: float = 0.0  # URL/DOM context + risk analysis + policy evaluation
	action_id: str | None = None
	risk_score: int = 0
	risk_factors: list[str] = Field(default_factory=list)
	capabilities: list[str] = Field(default_factory=list)
	taint_labels: list[str] = Field(default_factory=list)
	target_origin: str | None = None
	params_digest: str | None = None


class ActionAudit(SentinelEvent):
	"""Start/completion record for every attempted action, including denials."""

	type: Literal['action_audit'] = 'action_audit'
	phase: Literal['attempted', 'completed']
	action_id: str
	action: str
	url: str | None = None
	target_origin: str | None = None
	capabilities: list[str] = Field(default_factory=list)
	risk_score: int = 0
	enforcement_ms: float = 0.0
	risk_factors: list[str] = Field(default_factory=list)
	taint_labels: list[str] = Field(default_factory=list)
	params_digest: str
	verdict: str
	outcome: Literal[
		'pending',
		'executed',
		'tool_error',
		'blocked',
		'denied',
		'timeout',
		'cancelled',
		'handoff_returned',
		'handoff_timeout',
		'exception',
	] = 'pending'
	duration_ms: float | None = None
	error_type: str | None = None


class ApprovalRequest(SentinelEvent):
	type: Literal['approval_request'] = 'approval_request'
	approval_id: str
	action: str
	params: dict[str, Any] = Field(default_factory=dict)
	url: str | None = None
	expires_at: float
	reason: str = ''
	risk_score: int = 0
	risk_factors: list[str] = Field(default_factory=list)
	approval_key: str | None = None
	can_approve_scope: bool = False


class ApprovalResolved(SentinelEvent):
	type: Literal['approval_resolved'] = 'approval_resolved'
	approval_id: str
	approved: bool
	resolved_by: Literal['user', 'timeout', 'cancelled']
	scope: Literal['once', 'similar'] = 'once'


class OperatorMessage(SentinelEvent):
	"""A message the human typed in the chat (task, follow-up, or mid-run steering)."""

	type: Literal['user_message'] = 'user_message'
	text: str
	kind: Literal['task', 'followup', 'steer'] = 'task'


class ActionExecuting(SentinelEvent):
	"""Agent is physically driving the page right now (content script drops the
	input shield for this window so CDP-dispatched clicks reach the page)."""

	type: Literal['action_executing'] = 'action_executing'
	action: str


class ActionDone(SentinelEvent):
	type: Literal['action_done'] = 'action_done'
	action: str


class ControlRequest(SentinelEvent):
	type: Literal['control_request'] = 'control_request'
	handover_id: str
	reason: str
	url: str | None = None
	expires_at: float
	kind: Literal['human_step', 'security_incident'] = 'human_step'
	sanitization_status: Literal['residual', 'unattributable'] | None = None
	severity: Literal['low', 'medium', 'high', 'critical'] | None = None


class ControlReturned(SentinelEvent):
	type: Literal['control_returned'] = 'control_returned'
	handover_id: str
	note: str | None = None
	resolved_by: Literal['user', 'timeout', 'cancelled']
	kind: Literal['human_step', 'security_incident'] = 'human_step'


class TaskDone(SentinelEvent):
	type: Literal['task_done'] = 'task_done'
	success: bool | None = None
	final_result: str | None = None
	steps: int
	duration_s: float
	usage: dict[str, Any] = Field(default_factory=dict)
	enforcement: dict[str, Any] = Field(default_factory=dict)   # RunContext.enforcement_summary()


class TaskError(SentinelEvent):
	type: Literal['task_error'] = 'task_error'
	error: str
	kind: Literal['exception', 'budget_exceeded', 'stopped'] = 'exception'


class TokenUsage(SentinelEvent):
	type: Literal['token_usage'] = 'token_usage'
	prompt_tokens: int
	completion_tokens: int
	total_tokens: int
	by_model: dict[str, int] = Field(default_factory=dict)


class ConfigChanged(SentinelEvent):
	type: Literal['config_changed'] = 'config_changed'
	config: dict[str, Any]


class EventHub:
	"""Fans events out to all connected WebSocket clients via bounded queues.

	Also keeps a small replay buffer so a newly connected panel can rebuild the
	feed. Screenshots and raw page titles are never part of the WebSocket view;
	a synchronous trace listener may still retain an explicitly opted-in frame.
	"""

	def __init__(self, replay_size: int = 50) -> None:
		self._queues: set[asyncio.Queue[str]] = set()
		self._replay: deque[SentinelEvent] = deque(maxlen=replay_size)
		self._seq = 0
		# Synchronous observers of every event (e.g. the trace recorder).
		self._listeners: list[Callable[[SentinelEvent], None]] = []
		# Composed by main.py to include runner + browser + extension state.
		self.status_provider: Callable[[], dict[str, Any]] | None = None
		# Active chat; stamped on every event so clients can partition feeds.
		self.current_conversation_id: str | None = None

	def add_listener(self, listener: Callable[[SentinelEvent], None]) -> None:
		self._listeners.append(listener)

	def emit(self, event: SentinelEvent) -> None:
		self._seq += 1
		event.seq = self._seq
		if event.ts == 0:
			event.ts = time.time()
		if event.conversation_id is None:
			event.conversation_id = self.current_conversation_id

		internal_event = (
			event.model_copy(update={'title': ''})
			if isinstance(event, StepEvent)
			else event
		)
		for listener in self._listeners:
			try:
				listener(internal_event)
			except Exception:
				logger.exception('Event listener failed')

		public_event = (
			internal_event.model_copy(update={'screenshot_b64': None})
			if isinstance(internal_event, StepEvent)
			else internal_event
		)
		self._replay.append(public_event)

		payload = public_event.model_dump_json()
		for queue in self._queues:
			try:
				queue.put_nowait(payload)
			except asyncio.QueueFull:
				try:
					queue.get_nowait()   # drop oldest for this slow client
					queue.put_nowait(payload)
				except (asyncio.QueueEmpty, asyncio.QueueFull):
					pass

	def register(self) -> asyncio.Queue[str]:
		queue: asyncio.Queue[str] = asyncio.Queue(maxsize=256)
		self._queues.add(queue)
		return queue

	def unregister(self, queue: asyncio.Queue[str]) -> None:
		self._queues.discard(queue)

	@property
	def client_count(self) -> int:
		return len(self._queues)

	def clear_replay(self) -> None:
		"""Drop the replay buffer (switching chats). Never resets _seq — labels
		and traces key on the monotonic per-process sequence."""
		self._replay.clear()

	def snapshot(
		self,
		pending_approvals: list[dict[str, Any]],
		config: dict[str, Any],
		pending_handovers: list[dict[str, Any]] | None = None,
	) -> dict[str, Any]:
		"""First frame sent to a newly connected client."""
		events = [e.model_dump(mode='json') for e in self._replay]
		return {
			'type': 'snapshot',
			'ts': time.time(),
			'seq': self._seq,
			'conversation_id': self.current_conversation_id,
			'status': self.status_provider() if self.status_provider else {},
			'events': events,
			'pending_approvals': pending_approvals,
			'pending_handovers': pending_handovers or [],
			'config': config,
		}
