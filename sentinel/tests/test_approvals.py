import asyncio

import pytest

from server.events import ApprovalRequest, ApprovalResolved, ControlReturned
from server.governance.approvals import ApprovalManager
from server.governance.handover import HandoverManager


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


@pytest.mark.asyncio
async def test_cancel_all_is_explicit_and_fails_closed() -> None:
	events = []
	manager = ApprovalManager(events.append)
	request = manager.create('input', {}, None, 1, 'run')
	manager.cancel_all()
	assert await manager.wait(request.approval_id, 1) == 'cancelled'
	resolved = [event for event in events if isinstance(event, ApprovalResolved)]
	assert len(resolved) == 1
	assert not resolved[0].approved
	assert resolved[0].resolved_by == 'cancelled'


@pytest.mark.asyncio
async def test_cancelled_approval_wait_emits_terminal_resolution_and_cleans_pending() -> None:
	events = []
	manager = ApprovalManager(events.append)
	request = manager.create('input', {}, None, 1, 'run')
	waiter = asyncio.create_task(manager.wait(request.approval_id, 1))
	await asyncio.sleep(0)
	waiter.cancel()
	with pytest.raises(asyncio.CancelledError):
		await waiter

	assert manager.pending_list() == []
	resolved = [event for event in events if isinstance(event, ApprovalResolved)]
	assert len(resolved) == 1
	assert not resolved[0].approved
	assert resolved[0].resolved_by == 'cancelled'


@pytest.mark.asyncio
async def test_handover_cancel_is_not_misreported_as_human_return() -> None:
	events = []
	manager = HandoverManager(events.append)
	request = manager.create('Protected step', 'https://example.test', 1, 'run')
	manager.cancel_all()
	assert await manager.wait(request.handover_id, 1) == ('cancelled', None)
	resolved = [event for event in events if isinstance(event, ControlReturned)]
	assert len(resolved) == 1
	assert resolved[0].resolved_by == 'cancelled'


@pytest.mark.asyncio
async def test_security_incident_return_drops_operator_note() -> None:
	events = []
	manager = HandoverManager(events.append)
	request = manager.create(
		'Unsafe observation withheld',
		'https://example.test',
		1,
		'run',
		kind='security_incident',
		sanitization_status='residual',
		severity='high',
	)
	assert manager.complete(request.handover_id, 'text that must not enter model context')
	assert await manager.wait(request.handover_id, 1) == ('returned', None)
	resolved = [event for event in events if isinstance(event, ControlReturned)]
	assert resolved[-1].kind == 'security_incident'
	assert resolved[-1].note is None
