"""AgentRunner: one browser-use Agent at a time against the shared BrowserSession.

State machine: idle -> running <-> paused -> stopping -> idle. Never calls
agent.close()/session.stop() between runs — keep_alive keeps the window and
CDP connection up so the next Agent reuses them.
"""

import asyncio
import logging
import time
from typing import Any
from uuid import uuid4

from browser_use import Agent

from server.browser import BrowserManager
from server.config import ConfigStore
from server.events import (
	AgentStatus,
	EventHub,
	OperatorMessage,
	StatusChanged,
	StepEvent,
	TaskDone,
	TaskError,
	TaskStarted,
	TokenUsage,
)
from server.governance import (
	ApprovalManager,
	BudgetExceededError,
	GovernedTools,
	HandoverManager,
	PolicyEngine,
	RunContext,
)
from server.history import HistoryStore
from server.llm_factory import build_llm_pair

logger = logging.getLogger('sentinel.runner')

HANDOVER_GUIDANCE = (
	'IMPORTANT: if a step needs the human personally — logging in / credentials, verification or '
	'one-time codes, CAPTCHAs, payment, or private details you cannot know (postcodes, addresses, '
	'full names) — never guess or type placeholder values. Call the request_human_control action '
	'with a clear one-sentence reason instead. A human will complete that step in the browser and '
	'hand control back; then continue from the updated page state. '
	# Visual disambiguation only: the pill is already removed from the DOM the agent
	# sees (browser_use_patches.py), so it can't be targeted — but it still shows in
	# screenshot pixels, which we don't filter. This one line stops the model reading
	# its own control chrome as page content; it is not what prevents interaction.
	'Also: a thin amber frame around the page and a small "Working on task" bar at the very top '
	'of screenshots are Sentinel\'s own control overlay, not part of the website — read the page '
	'as if they were not there.'
)


class RunnerBusy(Exception):
	pass


class BrowserNotReady(Exception):
	pass


class AgentRunner:
	def __init__(
		self,
		config_store: ConfigStore,
		hub: EventHub,
		policy: PolicyEngine,
		approvals: ApprovalManager,
		handovers: HandoverManager,
		browser_manager: BrowserManager,
		history: HistoryStore,
	) -> None:
		self._config_store = config_store
		self._hub = hub
		self._policy = policy
		self._approvals = approvals
		self._handovers = handovers
		self._browser_manager = browser_manager
		self._history = history

		self.status: AgentStatus = 'idle'
		self.task_text: str | None = None
		self.run_id: str | None = None
		self.ctx: RunContext | None = None
		self._agent: Agent | None = None
		self._run_task: asyncio.Task | None = None
		self._stop_requested = False
		self._budget_stopped = False
		# Last finished run, used to give follow-up messages continuity.
		self._last_run: dict[str, str] | None = None

	# ── Status ───────────────────────────────────────────────────────────────
	def status_dict(self) -> dict[str, Any]:
		config = self._config_store.get()
		return {
			'backend': 'ok',
			'agent_status': self.status,
			'browser_status': self._browser_manager.status,
			'extension_seen': self._browser_manager.extension_seen,
			'task': self.task_text,
			'run_id': self.run_id,
			'model': config.model.model,
			'provider': config.model.provider,
			'calls_used': self.ctx.llm_calls if self.ctx else 0,
			'calls_budget': self.ctx.max_llm_calls if self.ctx else config.policies.budgets.max_llm_calls,
			'total_tokens': self.ctx.total_tokens if self.ctx else 0,
			'ws_clients': self._hub.client_count,
			'handover': (self._handovers.pending_list() or [None])[0],
		}

	def _set_status(self, status: AgentStatus) -> None:
		self.status = status
		config = self._config_store.get()
		self._hub.emit(
			StatusChanged(
				run_id=self.run_id,
				agent_status=status,
				browser_status=self._browser_manager.status,
				extension_seen=self._browser_manager.extension_seen,
				task=self.task_text,
				model=config.model.model,
			)
		)

	# ── Chat entrypoint ──────────────────────────────────────────────────────
	async def handle_message(self, text: str) -> dict[str, Any]:
		"""One chatbot-style entrypoint: steer if a run is live, otherwise start
		a (follow-up-aware) task."""
		if self.status in ('running', 'paused', 'stopping'):
			self.steer(text)
			return {'kind': 'steer'}
		if self._last_run is not None:
			run_id = await self.start_task(self._build_followup(text), message_text=text, kind='followup')
			return {'kind': 'followup', 'run_id': run_id}
		run_id = await self.start_task(text)
		return {'kind': 'task', 'run_id': run_id}

	def steer(self, text: str) -> None:
		if self.ctx is None:
			return
		self.ctx.steering.append(text)
		self._hub.emit(OperatorMessage(run_id=self.run_id, text=text, kind='steer'))
		logger.info(f'Steering queued for next LLM call: {text[:80]}')

	def _build_followup(self, text: str) -> str:
		assert self._last_run is not None
		return (
			f'Earlier you completed this task: {self._last_run["task"]}\n'
			f'Outcome: {self._last_run["result"]}\n'
			f'The same browser session is still open — continue from its current state.\n'
			f'Follow-up request from the operator: {text}'
		)

	# ── Task lifecycle ───────────────────────────────────────────────────────
	async def start_task(
		self,
		task: str,
		max_steps: int | None = None,
		message_text: str | None = None,
		kind: str = 'task',
	) -> str:
		if self.status != 'idle':
			raise RunnerBusy(f'A task is already {self.status}')
		if self._browser_manager.session is None:
			raise BrowserNotReady('Browser is not running yet — wait a moment or restart the server')

		config = self._config_store.get()
		budgets = config.policies.budgets
		steps = min(max_steps or budgets.max_steps, budgets.max_steps)

		run_id = uuid4().hex[:8]
		ctx = RunContext(run_id=run_id, max_llm_calls=budgets.max_llm_calls)
		llm, fallback = build_llm_pair(config.model, self._hub.emit, ctx)   # raises MissingApiKeyError
		tools = GovernedTools(
			policy=self._policy,
			approvals=self._approvals,
			handovers=self._handovers,
			emit=self._hub.emit,
			ctx=ctx,
			approval_timeout_s=budgets.approval_timeout_s,
			handover_timeout_s=budgets.handover_timeout_s,
			exclude_actions=list(config.policies.blocked_actions),
		)

		# Approval and handover waits happen INSIDE a step, so the step timeout
		# must comfortably exceed them.
		step_timeout = int(max(600, budgets.approval_timeout_s + 120, budgets.handover_timeout_s + 120))

		agent = Agent(
			task=task,
			llm=llm,
			browser_session=self._browser_manager.session,
			tools=tools,
			use_vision=True,
			fallback_llm=fallback,
			register_new_step_callback=self._make_step_callback(ctx),
			use_judge=config.use_judge,
			calculate_cost=False,
			extend_system_message=HANDOVER_GUIDANCE,
			step_timeout=step_timeout,
			enable_signal_handler=False,    # the server owns SIGINT
		)

		self.task_text = task
		self.run_id = run_id
		self.ctx = ctx
		self._agent = agent
		self._stop_requested = False
		self._budget_stopped = False
		self._hub.emit(OperatorMessage(run_id=run_id, text=message_text or task, kind=kind))  # type: ignore[arg-type]
		self._set_status('running')
		self._hub.emit(
			TaskStarted(run_id=run_id, task=task, max_steps=steps, model=config.model.model, provider=config.model.provider)
		)
		self._run_task = asyncio.create_task(self._run(agent, steps, ctx, task))
		return run_id

	def _make_step_callback(self, ctx: RunContext):
		async def on_step(browser_state_summary: Any, agent_output: Any, step_number: int) -> None:
			actions = []
			for action in getattr(agent_output, 'action', None) or []:
				name, params = GovernedTools._describe(action)
				actions.append({'name': name, 'params': params})
			self._hub.emit(
				StepEvent(
					run_id=ctx.run_id,
					step=step_number,
					url=getattr(browser_state_summary, 'url', '') or '',
					title=getattr(browser_state_summary, 'title', '') or '',
					evaluation_previous_goal=getattr(agent_output, 'evaluation_previous_goal', None),
					next_goal=getattr(agent_output, 'next_goal', None),
					memory=getattr(agent_output, 'memory', None),
					thinking=getattr(agent_output, 'thinking', None),
					actions=actions,
					screenshot_b64=getattr(browser_state_summary, 'screenshot', None),
				)
			)
			self._hub.emit(
				TokenUsage(
					run_id=ctx.run_id,
					prompt_tokens=ctx.prompt_tokens,
					completion_tokens=ctx.completion_tokens,
					total_tokens=ctx.total_tokens,
					by_model=dict(ctx.tokens_by_model),
				)
			)
			# Graceful budget stop: the hard backstop lives in GovernedLLM.
			if ctx.llm_calls >= ctx.max_llm_calls and not self._budget_stopped:
				self._budget_stopped = True
				logger.info(f'LLM call budget reached ({ctx.max_llm_calls}) — stopping agent')
				if self._agent is not None:
					self._agent.stop()

		return on_step

	async def _run(self, agent: Agent, max_steps: int, ctx: RunContext, task: str) -> None:
		started_at = time.time()
		record: dict[str, Any] = {
			'run_id': ctx.run_id,
			'task': task,
			'started_at': started_at,
			'model': self._config_store.get().model.model,
			'provider': self._config_store.get().model.provider,
		}
		try:
			history = await agent.run(max_steps=max_steps)
			duration = time.time() - started_at
			if self._budget_stopped:
				self._hub.emit(
					TaskError(run_id=ctx.run_id, error=f'LLM call budget reached ({ctx.max_llm_calls})', kind='budget_exceeded')
				)
				record.update(status='budget_exceeded')
			elif self._stop_requested:
				self._hub.emit(TaskError(run_id=ctx.run_id, error='Stopped by user', kind='stopped'))
				record.update(status='stopped')
			else:
				final_result = history.final_result()
				success = history.is_successful()
				self._last_run = {'task': task[:400], 'result': (final_result or 'finished')[:400]}
				self._hub.emit(
					TaskDone(
						run_id=ctx.run_id,
						success=success,
						final_result=final_result,
						steps=len(history.history),
						duration_s=round(duration, 1),
						usage={
							'prompt_tokens': ctx.prompt_tokens,
							'completion_tokens': ctx.completion_tokens,
							'total_tokens': ctx.total_tokens,
							'by_model': dict(ctx.tokens_by_model),
						},
					)
				)
				record.update(status='done' if success else 'finished', success=success, final_result=(final_result or '')[:2000])
			record.update(steps=len(history.history))
		except BudgetExceededError as e:
			self._hub.emit(TaskError(run_id=ctx.run_id, error=str(e), kind='budget_exceeded'))
			record.update(status='budget_exceeded')
		except Exception as e:
			message = str(e)
			if 'stopped programmatically' in message.lower() or self._stop_requested:
				self._hub.emit(TaskError(run_id=ctx.run_id, error='Stopped by user', kind='stopped'))
				record.update(status='stopped')
			else:
				logger.exception('Agent run failed')
				self._hub.emit(TaskError(run_id=ctx.run_id, error=message[:500], kind='exception'))
				record.update(status='error', error=message[:500])
		finally:
			record.update(
				duration_s=round(time.time() - started_at, 1),
				llm_calls=ctx.llm_calls,
				total_tokens=ctx.total_tokens,
				by_model=dict(ctx.tokens_by_model),
			)
			self._history.append(record)
			self._agent = None
			self._run_task = None
			self.task_text = None
			self.run_id = None
			# Keep ctx for the status bar until the next run starts.
			self._set_status('idle')

	# ── Controls ─────────────────────────────────────────────────────────────
	def pause(self) -> None:
		if self._agent is not None and self.status == 'running':
			self._agent.pause()
			self._set_status('paused')

	def resume(self) -> None:
		if self._agent is not None and self.status == 'paused':
			self._agent.resume()
			self._set_status('running')

	def stop(self) -> None:
		if self._agent is not None and self.status in ('running', 'paused'):
			self._stop_requested = True
			self._set_status('stopping')
			self._approvals.cancel_all()   # unblock any approval wait immediately
			self._handovers.cancel_all()   # ...and any takeover wait
			self._agent.stop()

	async def shutdown(self) -> None:
		if self._run_task is not None:
			self.stop()
			try:
				await asyncio.wait_for(asyncio.shield(self._run_task), timeout=15)
			except (TimeoutError, asyncio.CancelledError):
				self._run_task.cancel()
