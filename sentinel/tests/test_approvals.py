import asyncio

import pytest

from server.events import ApprovalRequest, ApprovalResolved
from server.governance.approvals import ApprovalManager


@pytest.mark.asyncio
async def test_explicit_similar_scope_round_trip() -> None:
	events = []
	manager = ApprovalManager(events.append)
	request = manager.create(
		'click',
		{'index': 1},
		'https://example.test',
		1,
		'run',
		approval_key='opaque',
		can_approve_scope=True,
	)
	assert isinstance(events[0], ApprovalRequest)
	assert manager.resolve(request.approval_id, True, 'similar')
	assert await manager.wait(request.approval_id, 1) == 'approved_scope'
	assert isinstance(events[-1], ApprovalResolved)
	assert events[-1].scope == 'similar'


@pytest.mark.asyncio
async def test_scope_is_downgraded_when_request_did_not_offer_it() -> None:
	manager = ApprovalManager(lambda event: None)
	request = manager.create('click', {}, None, 1, 'run', can_approve_scope=False)
	assert manager.resolve(request.approval_id, True, 'similar')
	assert await manager.wait(request.approval_id, 1) == 'approved_once'


@pytest.mark.asyncio
async def test_timeout_fails_closed_and_cleans_pending_request() -> None:
	events = []
	manager = ApprovalManager(events.append)
	request = manager.create('input', {}, None, 0.01, 'run')
	assert await manager.wait(request.approval_id, 0.01) == 'timeout'
	assert manager.pending_list() == []
	assert isinstance(events[-1], ApprovalResolved)
	assert events[-1].resolved_by == 'timeout'


def test_cancel_all_fails_closed() -> None:
	manager = ApprovalManager(lambda event: None)
	request = manager.create('input', {}, None, 1, 'run')
	manager.cancel_all()
	loop = asyncio.get_event_loop()
	assert loop.run_until_complete(manager.wait(request.approval_id, 1)) == 'denied'
