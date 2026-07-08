"""ApprovalManager: human-in-the-loop gate backed by asyncio Futures.

GovernedTools blocks inside act() awaiting the future; the side panel resolves
it via POST /api/approvals/{id}. Timeouts resolve to denied.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any, Literal
from uuid import uuid4

from server.events import ApprovalRequest, ApprovalResolved, SentinelEvent

logger = logging.getLogger('sentinel.approvals')


class PendingApproval:
	def __init__(self, request: ApprovalRequest) -> None:
		self.request = request
		self.future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()


class ApprovalManager:
	def __init__(self, emit: Callable[[SentinelEvent], None]) -> None:
		self._emit = emit
		self._pending: dict[str, PendingApproval] = {}

	def create(self, action: str, params: dict[str, Any], url: str | None, timeout_s: float, run_id: str | None) -> ApprovalRequest:
		request = ApprovalRequest(
			run_id=run_id,
			approval_id=uuid4().hex[:12],
			action=action,
			params=params,
			url=url,
			expires_at=time.time() + timeout_s,
		)
		self._pending[request.approval_id] = PendingApproval(request)
		self._emit(request)
		return request

	def resolve(self, approval_id: str, approved: bool) -> bool:
		"""Called from the REST API. Returns False if unknown or already resolved."""
		pending = self._pending.get(approval_id)
		if pending is None or pending.future.done():
			return False
		pending.future.set_result(approved)
		self._emit(
			ApprovalResolved(
				run_id=pending.request.run_id,
				approval_id=approval_id,
				approved=approved,
				resolved_by='user',
			)
		)
		return True

	async def wait(self, approval_id: str, timeout_s: float) -> Literal['approved', 'denied', 'timeout']:
		pending = self._pending.get(approval_id)
		if pending is None:
			return 'denied'
		try:
			approved = await asyncio.wait_for(asyncio.shield(pending.future), timeout=timeout_s)
			return 'approved' if approved else 'denied'
		except TimeoutError:
			if not pending.future.done():
				pending.future.set_result(False)
			self._emit(
				ApprovalResolved(
					run_id=pending.request.run_id,
					approval_id=approval_id,
					approved=False,
					resolved_by='timeout',
				)
			)
			return 'timeout'
		finally:
			self._pending.pop(approval_id, None)

	def pending_list(self) -> list[dict[str, Any]]:
		"""For WS snapshot replay so a reconnecting panel re-shows approval cards."""
		return [p.request.model_dump(mode='json') for p in self._pending.values() if not p.future.done()]

	def cancel_all(self) -> None:
		"""Deny everything outstanding (used on stop/shutdown)."""
		for approval_id, pending in list(self._pending.items()):
			if not pending.future.done():
				pending.future.set_result(False)
