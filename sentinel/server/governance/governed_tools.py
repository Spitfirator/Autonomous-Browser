"""GovernedTools: every browser action funnels through this act() override.

Verdicts: allow (delegate to browser-use), block (return ActionResult error so
the LLM re-plans), approve (pause inside the step awaiting the human's decision
in the side panel). Signature mirrors Tools.act() in browser-use v0.13.2
(browser_use/tools/service.py:2164) — the Agent calls it with keyword args.
"""

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from browser_use.agent.views import ActionModel, ActionResult
from browser_use.browser import BrowserSession
from browser_use.llm.base import BaseChatModel
from browser_use.tools.service import Tools
from pydantic import BaseModel, Field

from server.events import ActionDone, ActionExecuting, EnforcementDecision, SentinelEvent
from server.governance.approvals import ApprovalManager
from server.governance.governed_llm import RunContext
from server.governance.handover import HandoverManager
from server.governance.policy import PolicyEngine

logger = logging.getLogger('sentinel.governance')

HANDOVER_ACTION = 'request_human_control'


class RequestHumanControlParams(BaseModel):
	reason: str = Field(
		description='What you need the human to do and why, in one sentence. Shown to them on screen.'
	)


class GovernedTools(Tools):
	def __init__(
		self,
		policy: PolicyEngine,
		approvals: ApprovalManager,
		handovers: HandoverManager,
		emit: Callable[[SentinelEvent], None],
		ctx: RunContext,
		approval_timeout_s: float,
		handover_timeout_s: float,
		exclude_actions: list[str] | None = None,
	) -> None:
		super().__init__(exclude_actions=exclude_actions if exclude_actions is not None else [])
		self._policy = policy
		self._approvals = approvals
		self._handovers = handovers
		self._emit = emit
		self._ctx = ctx
		self._approval_timeout_s = approval_timeout_s
		self._handover_timeout_s = handover_timeout_s
		self._register_handover_action()

	def _register_handover_action(self) -> None:
		# Gives the LLM the tool in its schema. The handler below is a fallback —
		# act() intercepts this action and runs the real handover flow instead.
		@self.registry.action(
			'Hand control of the browser to the human operator when a step needs them personally: '
			'logins/credentials, verification or one-time codes, CAPTCHAs, payment, or private details '
			'you do not know (postcodes, addresses, names). Never guess or type placeholder values for '
			'those — call this instead, then continue from the updated page after they hand control back.',
			param_model=RequestHumanControlParams,
			terminates_sequence=True,
		)
		async def request_human_control(params: RequestHumanControlParams) -> ActionResult:
			return ActionResult(extracted_content=f'Human control requested: {params.reason}')

	async def act(
		self,
		action: ActionModel,
		browser_session: BrowserSession,
		page_extraction_llm: BaseChatModel | None = None,
		sensitive_data: dict[str, str | dict[str, str]] | None = None,
		available_file_paths: list[str] | None = None,
		file_system: Any = None,
		extraction_schema: dict | None = None,
		action_timeout: float | None = None,
	) -> ActionResult:
		name, params = self._describe(action)
		try:
			current_url: str | None = await browser_session.get_current_page_url()
		except Exception:
			current_url = None

		t0 = time.perf_counter()
		decision = self._policy.evaluate(name, params, current_url, self._ctx.handed_over_patterns)
		decision_ms = (time.perf_counter() - t0) * 1000
		self._ctx.record_latency(decision_ms)
		preview = json.dumps(params, default=str)[:180]
		mode = decision.mode

		# Shadow mode: report the would-be verdict, then execute as allowed.
		if decision.shadow_verdict is not None:
			shadow = {'block': 'shadow_blocked', 'approve': 'shadow_approval_required', 'handoff': 'shadow_handoff_required'}[
				decision.shadow_verdict
			]
			self._emit_decision(name, preview, current_url, shadow, decision.rule, decision.reason, mode, decision_ms)

		elif decision.verdict == 'block':
			self._emit_decision(name, preview, current_url, 'blocked', decision.rule, decision.reason, mode, decision_ms)
			return ActionResult(
				error=f'Action {name} blocked by policy: {decision.reason}. Choose a different approach or finish the task.'
			)

		elif decision.verdict == 'handoff':
			# Policy-forced handoff: the action is NOT executed; the human does
			# the sensitive step in the browser instead.
			self._emit_decision(name, preview, current_url, 'handoff_required', decision.rule, decision.reason, mode, decision_ms)
			return await self._run_handover(
				{'reason': decision.reason},
				current_url,
				browser_session,
				intercepted_action=name,
				clear_pattern=decision.pattern,
			)

		elif decision.verdict == 'approve':
			self._emit_decision(name, preview, current_url, 'approval_required', decision.rule, decision.reason, mode, decision_ms)
			request = self._approvals.create(name, params, current_url, self._approval_timeout_s, self._ctx.run_id)
			wait_t0 = time.monotonic()
			outcome = await self._approvals.wait(request.approval_id, self._approval_timeout_s)
			self._ctx.human_wait_s += time.monotonic() - wait_t0
			if outcome == 'denied':
				self._ctx.human_interventions += 1
			if outcome != 'approved':
				verdict = 'denied_timeout' if outcome == 'timeout' else 'denied_by_human'
				self._emit_decision(name, preview, current_url, verdict, decision.rule, f'{name} was not approved ({outcome})', mode)
				return ActionResult(
					error=f'Action {name} was denied by the human operator. Do not retry it; find another way or finish the task.'
				)
			self._ctx.human_interventions += 1

		if decision.verdict == 'allow' or decision.verdict == 'approve':
			self._emit_decision(name, preview, current_url, 'allowed', decision.rule, decision.reason, mode, decision_ms)

		if name == HANDOVER_ACTION:
			# Real handover flow runs here, outside the per-action timeout that
			# would kill a blocking action handler after ~180s.
			return await self._run_handover(params, current_url, browser_session)

		# The content script drops its input shield only while the agent is
		# physically driving the page (CDP clicks land in the DOM like user
		# clicks, so the shield must not swallow them).
		self._emit(ActionExecuting(run_id=self._ctx.run_id, action=name))
		try:
			return await super().act(
				action,
				browser_session,
				page_extraction_llm=page_extraction_llm,
				sensitive_data=sensitive_data,
				available_file_paths=available_file_paths,
				file_system=file_system,
				extraction_schema=extraction_schema,
				action_timeout=action_timeout,
			)
		finally:
			self._emit(ActionDone(run_id=self._ctx.run_id, action=name))

	async def _run_handover(
		self,
		params: dict[str, Any],
		current_url: str | None,
		browser_session: BrowserSession,
		intercepted_action: str | None = None,
		clear_pattern: str | None = None,
	) -> ActionResult:
		"""Freeze the run and hand the browser to the human. Two entry points:
		the agent's own request_human_control action, or a policy-forced handoff
		(intercepted_action set — the original action was NOT executed)."""
		reason = str(params.get('reason') or 'The agent needs you to complete a step in the browser.')
		# The extension content script renders the in-page takeover banner from
		# the control_request event; the side panel shows the matching card.
		request = self._handovers.create(reason, current_url, self._handover_timeout_s, self._ctx.run_id)
		wait_t0 = time.monotonic()
		outcome, note = await self._handovers.wait(request.handover_id, self._handover_timeout_s)
		self._ctx.human_wait_s += time.monotonic() - wait_t0

		if outcome == 'returned':
			self._ctx.human_interventions += 1
			if clear_pattern is not None:
				# The human vouched for this sensitive domain — don't re-trigger
				# the handoff for it again this run.
				self._ctx.handed_over_patterns.add(clear_pattern)
			if intercepted_action is not None:
				self._emit_decision(
					intercepted_action, '{}', current_url, 'handoff_returned', 'sensitive_domain',
					f'human completed the sensitive step and returned control (note: {note or "none"})',
				)
			note_text = note or '(no note left)'
			prefix = (
				f'Your {intercepted_action} action was NOT executed — that page is designated human-only. '
				if intercepted_action is not None
				else ''
			)
			return ActionResult(
				extracted_content=(
					f'{prefix}The human operator took control, finished the step, and handed control back. '
					f'Their note: {note_text}. The page may have changed — continue the task from the CURRENT page state.'
				),
				long_term_memory=f'Human helped with: {reason} — note: {note_text}',
			)
		if intercepted_action is not None:
			self._emit_decision(
				intercepted_action, '{}', current_url, 'handoff_timeout', 'sensitive_domain',
				'no human responded to the forced handoff',
			)
		return ActionResult(
			error=(
				'No human responded to the control request. Do not attempt that protected step yourself; '
				'find another way or finish the task with what you have.'
			)
		)

	@staticmethod
	def _describe(action: ActionModel) -> tuple[str, dict[str, Any]]:
		"""ActionModel dumps as {action_name: {params...}} with exactly one key set."""
		dumped = action.model_dump(exclude_unset=True)
		for name, params in dumped.items():
			if params is not None:
				return name, params if isinstance(params, dict) else {'value': params}
		return 'unknown', {}

	def _emit_decision(
		self,
		action: str,
		preview: str,
		url: str | None,
		verdict: str,
		rule: str,
		reason: str,
		mode: str = 'enforce',
		decision_ms: float = 0.0,
	) -> None:
		self._ctx.count_verdict(verdict)
		logger.info(f'[decision] {verdict} {action} rule={rule} url={url or "-"} ({decision_ms:.2f}ms) — {reason}')
		self._emit(
			EnforcementDecision(
				run_id=self._ctx.run_id,
				action=action,
				params_preview=preview,
				url=url,
				verdict=verdict,  # type: ignore[arg-type]
				rule=rule,
				reason=reason,
				mode=mode,
				decision_ms=round(decision_ms, 3),
			)
		)
