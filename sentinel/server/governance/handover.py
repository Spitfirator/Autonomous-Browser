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

logger = logging.getLogger('sentinel.handover')


class PendingHandover:
	def __init__(self, request: ControlRequest) -> None:
		self.request = request
		self.future: asyncio.Future[str | None] = asyncio.get_event_loop().create_future()


class HandoverManager:
	def __init__(self, emit: Callable[[SentinelEvent], None]) -> None:
		self._emit = emit
		self._pending: dict[str, PendingHandover] = {}

	def create(self, reason: str, url: str | None, timeout_s: float, run_id: str | None) -> ControlRequest:
		request = ControlRequest(
			run_id=run_id,
			handover_id=uuid4().hex[:12],
			reason=reason,
			url=url,
			expires_at=time.time() + timeout_s,
		)
		self._pending[request.handover_id] = PendingHandover(request)
		self._emit(request)
		return request

	def complete(self, handover_id: str, note: str | None) -> bool:
		"""Called when the human gives control back (page overlay or side panel)."""
		pending = self._pending.get(handover_id)
		if pending is None or pending.future.done():
			return False
		pending.future.set_result(note.strip() if isinstance(note, str) else None)
		return True

	async def wait(self, handover_id: str, timeout_s: float) -> tuple[Literal['returned', 'timeout'], str | None]:
		pending = self._pending.get(handover_id)
		if pending is None:
			return 'timeout', None
		try:
			note = await asyncio.wait_for(asyncio.shield(pending.future), timeout=timeout_s)
			self._emit(
				ControlReturned(run_id=pending.request.run_id, handover_id=handover_id, note=note, resolved_by='user')
			)
			return 'returned', note
		except TimeoutError:
			if not pending.future.done():
				pending.future.set_result(None)
			self._emit(
				ControlReturned(run_id=pending.request.run_id, handover_id=handover_id, note=None, resolved_by='timeout')
			)
			return 'timeout', None
		finally:
			self._pending.pop(handover_id, None)

	def pending_list(self) -> list[dict[str, Any]]:
		return [p.request.model_dump(mode='json') for p in self._pending.values() if not p.future.done()]

	def cancel_all(self) -> None:
		for pending in self._pending.values():
			if not pending.future.done():
				pending.future.set_result(None)

