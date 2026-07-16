from pathlib import Path

import asyncio
import pytest

from server.config import ConfigStore
from server.events import ActionAudit, ApprovalRequest, EnforcementDecision
from server.governance.approvals import ApprovalManager
from server.governance.governed_llm import RunContext
from server.governance.governed_tools import GovernedTools
from server.governance.handover import HandoverManager
from server.governance.policy import PolicyEngine


class DummyBrowser:
	cdp_client = None

	async def get_current_page_url(self) -> str:
		return 'https://example.test/form'


def _harness(
	tmp_path: Path,
	events: list,
	policy_patch: dict | None = None,
	approval_timeout_s: float = 1,
) -> tuple[GovernedTools, ApprovalManager, RunContext]:
	store = ConfigStore(tmp_path / 'config.json')
	if policy_patch:
		store.update({'policies': policy_patch})
	approvals = ApprovalManager(events.append)
	ctx = RunContext('run', 10)
	tools = GovernedTools(
		policy=PolicyEngine(store),
		approvals=approvals,
		handovers=HandoverManager(events.append),
		emit=events.append,
		ctx=ctx,
		approval_timeout_s=approval_timeout_s,
		handover_timeout_s=1,
	)
	return tools, approvals, ctx


def _tools(tmp_path: Path, events: list, blocked_actions: list[str] | None = None) -> GovernedTools:
	tools, _, _ = _harness(tmp_path, events, {'blocked_actions': blocked_actions or []})
	return tools


@pytest.mark.asyncio
async def test_blocked_action_has_attempt_and_completion_audit_without_secret(tmp_path: Path) -> None:
	events = []
	tools = _tools(tmp_path, events, ['input'])
	action_model = tools.registry.create_action_model()
	action = action_model.model_validate({'input': {'index': 1, 'text': '<secret>password</secret>'}})
	result = await tools.act(action, DummyBrowser())  # type: ignore[arg-type]
	assert result.error
	audits = [event for event in events if isinstance(event, ActionAudit)]
	assert [event.phase for event in audits] == ['attempted', 'completed']
	assert audits[0].action_id == audits[1].action_id
	assert audits[1].outcome == 'blocked'
	assert '<secret>' not in ''.join(event.model_dump_json() for event in events)
	assert 'password' not in ''.join(event.model_dump_json() for event in events)


@pytest.mark.asyncio
async def test_executed_action_has_matching_completion_audit(tmp_path: Path) -> None:
	events = []
	tools = _tools(tmp_path, events)
	action_model = tools.registry.create_action_model()
	action = action_model.model_validate({'wait': {'seconds': 0}})
	result = await tools.act(action, DummyBrowser())  # type: ignore[arg-type]
	assert not result.error
	audits = [event for event in events if isinstance(event, ActionAudit)]
	assert len(audits) == 2
	assert audits[0].phase == 'attempted'
	assert audits[1].phase == 'completed'
	assert audits[1].outcome == 'executed'
	assert audits[0].params_digest == audits[1].params_digest


@pytest.mark.asyncio
async def test_cancelled_action_still_has_completion_audit(tmp_path: Path) -> None:
	events = []
	tools = _tools(tmp_path, events)
	action_model = tools.registry.create_action_model()
	action = action_model.model_validate({'wait': {'seconds': 30}})
	task = asyncio.create_task(tools.act(action, DummyBrowser()))  # type: ignore[arg-type]
	await asyncio.sleep(0.01)
	task.cancel()
	with pytest.raises(asyncio.CancelledError):
		await task
	audits = [event for event in events if isinstance(event, ActionAudit)]
	assert [event.phase for event in audits] == ['attempted', 'completed']
	assert audits[-1].outcome == 'exception'
	assert audits[-1].error_type == 'CancelledError'


@pytest.mark.asyncio
async def test_approval_timeout_is_fail_closed_and_audited(tmp_path: Path) -> None:
	events = []
	tools, _, ctx = _harness(
		tmp_path,
		events,
		{'approval_required_actions': ['wait']},
		approval_timeout_s=0.01,
	)
	action_model = tools.registry.create_action_model()
	action = action_model.model_validate({'wait': {'seconds': 0}})
	result = await tools.act(action, DummyBrowser())  # type: ignore[arg-type]
	assert result.error
	audits = [event for event in events if isinstance(event, ActionAudit)]
	assert audits[-1].outcome == 'timeout'
	assert ctx.actions_attempted == ctx.actions_completed == 1
	assert any(
		isinstance(event, EnforcementDecision) and event.verdict == 'denied_timeout' for event in events
	)


@pytest.mark.asyncio
async def test_explicit_similar_consent_reuses_scope_without_second_prompt(tmp_path: Path) -> None:
	events = []
	tools, approvals, ctx = _harness(tmp_path, events, {'approval_required_actions': ['wait']})
	action_model = tools.registry.create_action_model()
	action = action_model.model_validate({'wait': {'seconds': 0}})

	first = asyncio.create_task(tools.act(action, DummyBrowser()))  # type: ignore[arg-type]
	for _ in range(50):
		requests = [event for event in events if isinstance(event, ApprovalRequest)]
		if requests:
			break
		await asyncio.sleep(0.001)
	assert requests
	assert approvals.resolve(requests[-1].approval_id, True, 'similar')
	assert not (await first).error

	request_count = len([event for event in events if isinstance(event, ApprovalRequest)])
	assert not (await tools.act(action, DummyBrowser())).error  # type: ignore[arg-type]
	assert len([event for event in events if isinstance(event, ApprovalRequest)]) == request_count
	assert ctx.approval_prompts == 1
	assert ctx.approval_reuses == 1
	assert any(
		isinstance(event, EnforcementDecision) and event.verdict == 'approval_reused' for event in events
	)


@pytest.mark.asyncio
async def test_prompt_budget_blocks_instead_of_asking_again(tmp_path: Path) -> None:
	events = []
	tools, approvals, ctx = _harness(
		tmp_path,
		events,
		{
			'approval_required_actions': ['wait'],
			'adaptive_approvals': {'max_prompts_per_run': 1, 'fatigue_strategy': 'block'},
		},
	)
	action_model = tools.registry.create_action_model()
	action = action_model.model_validate({'wait': {'seconds': 0}})

	first = asyncio.create_task(tools.act(action, DummyBrowser()))  # type: ignore[arg-type]
	for _ in range(50):
		requests = [event for event in events if isinstance(event, ApprovalRequest)]
		if requests:
			break
		await asyncio.sleep(0.001)
	assert approvals.resolve(requests[-1].approval_id, False)
	assert (await first).error

	second = await tools.act(action, DummyBrowser())  # type: ignore[arg-type]
	assert second.error and 'rubber-stamp' in second.error
	assert len([event for event in events if isinstance(event, ApprovalRequest)]) == 1
	assert ctx.approval_prompts == 1
	assert any(
		isinstance(event, EnforcementDecision) and event.rule == 'approval_fatigue_limit' for event in events
	)
