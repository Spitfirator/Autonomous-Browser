"""GovernedLLM: the middleware layer every model call flows through.

Emits an `llm_call` event per invocation (model, latency, tokens, budget) and
enforces the per-run LLM call budget as a hard backstop. Wrap order:
GovernedLLM(ThrottledLLM(Chat*)) — throttling happens inside governance so the
emitted latency includes any pacing wait (that is the real wall-clock cost).
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from browser_use.llm.base import BaseChatModel

from server.events import LLMCall, SentinelEvent

logger = logging.getLogger('sentinel.governance')


class BudgetExceededError(Exception):
	pass


class RunContext:
	"""Mutable per-run counters shared by the governed wrappers and the runner."""

	def __init__(self, run_id: str, max_llm_calls: int) -> None:
		self.run_id = run_id
		self.max_llm_calls = max_llm_calls
		self.llm_calls = 0
		self.prompt_tokens = 0
		self.completion_tokens = 0
		self.total_tokens = 0
		self.tokens_by_model: dict[str, int] = {}
		# Operator steering typed mid-run; drained into the next LLM call.
		self.steering: list[str] = []
		# ── Enforcement metrics (see EVALS.md) ─────────────────────────────
		self.decisions_by_verdict: dict[str, int] = {}   # allowed/blocked/… -> count
		self.decision_ms_total = 0.0                     # policy evaluation time only
		self.decision_ms_max = 0.0
		self.decision_count = 0
		# Human wait, split by mechanism so a single run decomposes into baseline
		# task time vs. the extra time enforcement adds:
		#   approval_wait_s — side-panel approve/deny gates. The agent could have
		#     acted on its own, so this is time enforcement genuinely ADDS.
		#   handoff_wait_s — a human did the step in the browser (login, CAPTCHA,
		#     sensitive action). The task needs it with or without enforcement, so
		#     it's BASELINE, not overhead.
		self.approval_wait_s = 0.0
		self.handoff_wait_s = 0.0
		self.human_interventions = 0                     # approvals resolved by a human + handoffs completed
		# Sensitive-domain patterns cleared by a completed handoff this run.
		self.handed_over_patterns: set[str] = set()

	def record_latency(self, decision_ms: float) -> None:
		"""Once per act() — decision_count == number of actions evaluated."""
		self.decision_count += 1
		self.decision_ms_total += decision_ms
		self.decision_ms_max = max(self.decision_ms_max, decision_ms)

	def count_verdict(self, verdict: str) -> None:
		"""Once per emitted enforcement event (an approved action emits both
		approval_required and allowed — 'decisions' mirrors the event stream)."""
		self.decisions_by_verdict[verdict] = self.decisions_by_verdict.get(verdict, 0) + 1

	def enforcement_summary(self) -> dict[str, Any]:
		return {
			'decisions': dict(self.decisions_by_verdict),
			'decision_count': self.decision_count,
			'decision_ms_total': round(self.decision_ms_total, 3),
			'decision_ms_mean': round(self.decision_ms_total / self.decision_count, 3) if self.decision_count else 0.0,
			'decision_ms_max': round(self.decision_ms_max, 3),
			# Total frozen-on-a-human time, plus the split: approval_wait_s is the
			# extra time enforcement adds; handoff_wait_s is baseline the task needs
			# either way (see the panel's baseline-vs-added decomposition).
			'human_wait_s': round(self.approval_wait_s + self.handoff_wait_s, 1),
			'approval_wait_s': round(self.approval_wait_s, 1),
			'handoff_wait_s': round(self.handoff_wait_s, 1),
			'human_interventions': self.human_interventions,
		}


class GovernedLLM:
	"""Plain mutable class on purpose (TokenCost patches `ainvoke` on the
	instance; the Agent setattr's `_verified_api_keys`)."""

	def __init__(
		self,
		inner: BaseChatModel,
		emit: Callable[[SentinelEvent], None],
		ctx: RunContext,
		is_fallback: bool = False,
	) -> None:
		self._inner = inner
		self._emit = emit
		self._ctx = ctx
		self._is_fallback = is_fallback

	# BaseChatModel protocol surface -----------------------------------------
	@property
	def model(self) -> str:
		return self._inner.model

	@property
	def provider(self) -> str:
		return self._inner.provider

	@property
	def name(self) -> str:
		return self._inner.name

	def __getattr__(self, item: str) -> Any:
		return getattr(self._inner, item)

	async def ainvoke(self, messages: list[Any], output_format: type | None = None, **kwargs: Any) -> Any:
		ctx = self._ctx
		if ctx.steering:
			# Inject operator guidance typed mid-run as the freshest user message.
			from browser_use.llm.messages import UserMessage

			notes = '\n'.join(f'- {note}' for note in ctx.steering)
			ctx.steering = []
			messages = [
				*messages,
				UserMessage(
					content=(
						f'[Operator steering — highest priority, follow immediately]\n{notes}\n'
						f'Adjust your plan to honor this before anything else, then continue the task.'
					)
				),
			]
		ctx.llm_calls += 1
		# Hard backstop only (+2 grace so the agent can emit a final `done`);
		# the graceful stop lives in the runner, which calls agent.stop() at budget.
		if ctx.llm_calls > ctx.max_llm_calls + 2:
			raise BudgetExceededError(f'LLM call budget exhausted ({ctx.max_llm_calls} calls)')

		t0 = time.monotonic()
		result = await self._inner.ainvoke(messages, output_format, **kwargs)
		latency_ms = int((time.monotonic() - t0) * 1000)

		usage = getattr(result, 'usage', None)
		prompt_tokens = getattr(usage, 'prompt_tokens', None)
		completion_tokens = getattr(usage, 'completion_tokens', None)
		total_tokens = getattr(usage, 'total_tokens', None)
		if prompt_tokens:
			ctx.prompt_tokens += prompt_tokens
		if completion_tokens:
			ctx.completion_tokens += completion_tokens
		if total_tokens:
			ctx.total_tokens += total_tokens
			ctx.tokens_by_model[self.model] = ctx.tokens_by_model.get(self.model, 0) + total_tokens

		self._emit(
			LLMCall(
				run_id=ctx.run_id,
				model=self.model,
				provider=self.provider,
				latency_ms=latency_ms,
				prompt_tokens=prompt_tokens,
				completion_tokens=completion_tokens,
				total_tokens=total_tokens,
				calls_used=ctx.llm_calls,
				calls_budget=ctx.max_llm_calls,
				is_fallback=self._is_fallback,
			)
		)
		return result
