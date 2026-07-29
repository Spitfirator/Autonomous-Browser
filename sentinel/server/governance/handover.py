"""Human-in-the-loop control handover.

When the agent hits something only a human should do (credentials, one-time
codes, CAPTCHAs, payment, personal details), it calls the request_human_control
action. GovernedTools intercepts it and the run freezes inside the step; the
extension's content script renders the in-page "YOUR TURN" banner from the
control_request event and the side panel shows the matching card. The human
does the step, optionally leaves a note, and gives control back (page banner or
panel) — the agent resumes from the updated page state.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any, Literal
from uuid import uuid4

from server.events import ControlRequest, ControlReturned, SentinelEvent
from server.governance.security import redact_params, redact_url

logger = logging.getLogger('sentinel.handover')


class PendingHandover:
	def __init__(self, request: ControlRequest) -> None:
		self.request = request
		self.future: asyncio.Future[
			tuple[Literal['returned', 'timeout', 'cancelled'], str | None]
		] = asyncio.get_event_loop().create_future()


class HandoverManager:
	def __init__(self, emit: Callable[[SentinelEvent], None]) -> None:
		self._emit = emit
		self._pending: dict[str, PendingHandover] = {}

	def create(
		self,
		reason: str,
		url: str | None,
		timeout_s: float,
		run_id: str | None,
		*,
		kind: Literal['human_step', 'security_incident'] = 'human_step',
		sanitization_status: Literal['residual', 'unattributable'] | None = None,
		severity: Literal['low', 'medium', 'high', 'critical'] | None = None,
		handover_id: str | None = None,
	) -> ControlRequest:
		safe_reason = str(redact_params({'reason': reason}).get('reason') or 'Protected step requires human control')
		request = ControlRequest(
			run_id=run_id,
			handover_id=handover_id or uuid4().hex,
			reason=safe_reason,
			url=redact_url(url) if url else None,
			expires_at=time.time() + timeout_s,
			kind=kind,
			sanitization_status=sanitization_status,
			severity=severity,
		)
		self._pending[request.handover_id] = PendingHandover(request)
		self._emit(request)
		return request

	def complete(self, handover_id: str, note: str | None) -> bool:
		"""Called when the human gives control back (page overlay or side panel)."""
		pending = self._pending.get(handover_id)
		if pending is None or pending.future.done():
			return False
		# A security incident never accepts text into the agent's context. The
		# operator's return only requests a new observation; it does not approve
		# or annotate the quarantined one.
		safe_note = (
			note.strip()
			if pending.request.kind == 'human_step' and isinstance(note, str)
			else None
		)
		pending.future.set_result(('returned', safe_note))
		return True

	def kind_for(self, handover_id: str) -> Literal['human_step', 'security_incident'] | None:
		pending = self._pending.get(handover_id)
		return pending.request.kind if pending is not None and not pending.future.done() else None

	def has_pending_kind(self, kind: Literal['human_step', 'security_incident']) -> bool:
		return any(
			not pending.future.done() and pending.request.kind == kind
			for pending in self._pending.values()
		)

	async def wait(
		self, handover_id: str, timeout_s: float
	) -> tuple[Literal['returned', 'timeout', 'cancelled'], str | None]:
		pending = self._pending.get(handover_id)
		if pending is None:
			return 'timeout', None
		try:
			outcome, note = await asyncio.wait_for(asyncio.shield(pending.future), timeout=timeout_s)
			if outcome == 'cancelled':
				return 'cancelled', None
			if outcome == 'timeout':
				return 'timeout', None
			safe_note = str(redact_params({'note': note}).get('note')) if note else None
			self._emit(
				ControlReturned(
					run_id=pending.request.run_id,
					handover_id=handover_id,
					note=safe_note,
					resolved_by='user',
					kind=pending.request.kind,
				)
			)
			return 'returned', note
		except TimeoutError:
			if not pending.future.done():
				pending.future.set_result(('timeout', None))
			self._emit(
				ControlReturned(
					run_id=pending.request.run_id,
					handover_id=handover_id,
					note=None,
					resolved_by='timeout',
					kind=pending.request.kind,
				)
			)
			return 'timeout', None
		except asyncio.CancelledError:
			# The outer model/step task can be cancelled independently of the
			# manager (for example during forced reset). Never leave a reconnect
			# snapshot showing an orphaned request or imply that control returned.
			if not pending.future.done():
				pending.future.set_result(('cancelled', None))
			self._emit(
				ControlReturned(
					run_id=pending.request.run_id,
					handover_id=handover_id,
					note=None,
					resolved_by='cancelled',
					kind=pending.request.kind,
				)
			)
			raise
		finally:
			self._pending.pop(handover_id, None)

	def pending_list(self) -> list[dict[str, Any]]:
		return [p.request.model_dump(mode='json') for p in self._pending.values() if not p.future.done()]

	def cancel_all(self) -> None:
		for pending in self._pending.values():
			if not pending.future.done():
				pending.future.set_result(('cancelled', None))
				self._emit(
					ControlReturned(
						run_id=pending.request.run_id,
						handover_id=pending.request.handover_id,
						note=None,
						resolved_by='cancelled',
						kind=pending.request.kind,
					)
				)
