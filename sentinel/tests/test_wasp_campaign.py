import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.wasp import campaign as wasp_campaign
from evals.wasp.campaign import WaspCampaign
from evals.wasp.contract import (
	INJECTION_FORMATS,
	TASK_IDS,
	USER_GOAL_INDICES,
	AggregateCell,
	ModelSettings,
	NativeTaskScore,
	NativeBatchScores,
	Provenance,
	TaskResult,
	WaspBatch,
	aggregate_cell,
	all_batches,
	atomic_write_json,
	load_json,
	validate_generated_tasks,
)
from evals.wasp.runner import (
	EventRecorder,
	WaspCompatibleActionLog,
	_load_run_config,
	_operational_failure_from_history,
	validate_completed_execution,
)
from server.governance import ApprovalManager


def _campaign_args(tmp_path: Path, *, reset_between_cells: bool = True) -> SimpleNamespace:
	policy = tmp_path / 'wasp-policy.json'
	policy.write_text('{}')
	reset_script = tmp_path / 'reset-between-cells.sh'
	reset_script.write_text('#!/usr/bin/env bash\n')
	return SimpleNamespace(
		external_root=tmp_path / '.wasp',
		wasp_root=tmp_path / 'wasp',
		venv_python=tmp_path / 'venv' / 'bin' / 'python',
		run_root=tmp_path / 'run',
		run_tag='test-run',
		policy=policy,
		model='qwen3.5-agentdojo:9b',
		ollama_host='http://127.0.0.1:11435',
		gitlab='http://127.0.0.1:18023',
		reddit='http://127.0.0.1:19999',
		max_steps=30,
		reset_between_cells=reset_between_cells,
		reset_script=reset_script,
	)


def _provenance(mode: str) -> Provenance:
	return Provenance(
		sentinel_commit='sentinel-commit',
		browser_use_commit='browser-use-commit',
		policy_mode=mode,
		policy_sha256='a' * 64,
		model_settings=ModelSettings(),
	)


def _task_result(task_id: int, mode: str, *, detections: int, blocked: int) -> TaskResult:
	return TaskResult(
		case_id=f'user-goal-0-plain/task-{task_id}',
		batch_id='user-goal-0-plain',
		task_id=task_id,
		site='gitlab',
		policy_mode=mode,
		provenance=_provenance(mode),
		status='completed',
		started_at=1.0,
		ended_at=2.0,
		duration_s=1.0,
		steps=2,
		enforcement={
			'prompt_injection_detections': detections,
			'actions_attempted': 3,
			'enforcement_ms_total': 1.5,
			'approval_prompts': 0,
			'decisions': {'blocked': blocked},
		},
		action_names=['click'],
	)


def test_official_wasp_matrix_is_84_cases_per_mode() -> None:
	batches = all_batches()
	assert len(batches) == len(USER_GOAL_INDICES) * len(INJECTION_FORMATS) == 4
	assert len(TASK_IDS) == 21
	assert len({batch.case_id(task_id) for batch in batches for task_id in TASK_IDS}) == 84


def test_batch_ids_and_case_ids_are_stable() -> None:
	assert [batch.batch_id for batch in all_batches()] == [
		'user-goal-0-plain',
		'user-goal-0-url',
		'user-goal-1-plain',
		'user-goal-1-url',
	]
	assert all_batches()[0].case_id(1000) == 'user-goal-0-plain/task-1000'
	with pytest.raises(ValueError):
		all_batches()[0].case_id(999)


def test_generated_task_validation_requires_complete_native_matrix(tmp_path: Path) -> None:
	batch = WaspBatch(user_goal_index=0, injection_format='goal_hijacking_plain_text')
	for task_id in TASK_IDS:
		atomic_write_json(
			tmp_path / f'{task_id}.json',
			{
				'task_id': task_id,
				'sites': ['gitlab' if task_id < 1012 else 'reddit'],
				'start_url': 'http://127.0.0.1/test',
				'intent': 'Complete the benign task.',
				'eval': {'eval_types': ['program_html']},
			},
		)
	assert validate_generated_tasks(tmp_path, batch) == [tmp_path / f'{task_id}.json' for task_id in TASK_IDS]
	(tmp_path / '1007.json').unlink()
	with pytest.raises(ValueError, match='missing generated WASP tasks'):
		validate_generated_tasks(tmp_path, batch)


def test_atomic_json_checkpoint_replaces_complete_document(tmp_path: Path) -> None:
	path = tmp_path / 'checkpoint.json'
	atomic_write_json(path, {'value': 1})
	atomic_write_json(path, {'value': 2, 'nested': {'ok': True}})
	assert load_json(path) == {'nested': {'ok': True}, 'value': 2}
	assert not list(tmp_path.glob('.checkpoint.json-*'))


def test_provider_outage_returned_as_history_is_operational_failure() -> None:
	history = SimpleNamespace(
		is_done=lambda: False,
		errors=lambda: [
			'RuntimeError: net::ERR_CONNECTION_REFUSED',
			'ModelProviderError: Failed to connect to Ollama',
		],
	)
	assert _operational_failure_from_history(history) == 'ModelProviderUnavailable'
	history.is_done = lambda: True
	assert _operational_failure_from_history(history) is None


def test_completed_checkpoint_requires_successful_model_call() -> None:
	result = _task_result(1000, 'enforce', detections=0, blocked=0)
	result.event_counts = {'llm_call': 1}
	validate_completed_execution(result)
	result.event_counts = {'enforcement_decision': 1}
	with pytest.raises(ValueError, match='no successful model calls'):
		validate_completed_execution(result)


def test_pending_cell_resets_before_official_injector(
	tmp_path: Path,
	monkeypatch: pytest.MonkeyPatch,
) -> None:
	campaign = WaspCampaign(_campaign_args(tmp_path))
	state = campaign._new_state()
	batch = all_batches()[0]
	observed: list[str] = []

	monkeypatch.setattr(
		campaign,
		'_reset_environment_before_cell',
		lambda _batch, _mode: observed.append('reset'),
	)
	monkeypatch.setattr(
		wasp_campaign,
		'_run_checked',
		lambda *args, **kwargs: observed.append('injector'),
	)
	monkeypatch.setattr(campaign, '_refresh_auth', lambda: observed.append('auth'))
	monkeypatch.setattr(wasp_campaign, 'validate_generated_tasks', lambda *args: [])

	cell, _ = campaign._prepare_cell(state, batch, 'off')

	assert observed == ['reset', 'injector', 'auth']
	assert cell.status == 'prepared'
	assert campaign.state_path.is_file()


def test_running_cell_resume_does_not_reset_environment(
	tmp_path: Path,
	monkeypatch: pytest.MonkeyPatch,
) -> None:
	campaign = WaspCampaign(_campaign_args(tmp_path))
	state = campaign._new_state()
	batch = all_batches()[0]
	cell = state.cells['user-goal-0-plain/off']
	cell.status = 'running'
	monkeypatch.setattr(wasp_campaign, 'validate_generated_tasks', lambda *args: [])
	monkeypatch.setattr(
		campaign,
		'_reset_environment_before_cell',
		lambda *_args: pytest.fail('running-cell resume must not reset the websites'),
	)

	resumed, _ = campaign._prepare_cell(state, batch, 'off')

	assert resumed is cell
	assert resumed.status == 'running'


def test_reset_failure_leaves_pending_cell_untouched(
	tmp_path: Path,
	monkeypatch: pytest.MonkeyPatch,
) -> None:
	campaign = WaspCampaign(_campaign_args(tmp_path))
	state = campaign._new_state()
	batch = all_batches()[0]
	cell = state.cells['user-goal-0-plain/off']
	cell_dir = Path(cell.output_dir)
	monkeypatch.setattr(
		campaign,
		'_reset_environment_before_cell',
		lambda *_args: (_ for _ in ()).throw(RuntimeError('reset failed')),
	)

	with pytest.raises(RuntimeError, match='reset failed'):
		campaign._prepare_cell(state, batch, 'off')

	assert cell.status == 'pending'
	assert not cell_dir.exists()


def test_successful_reset_is_recorded_after_health_checks(
	tmp_path: Path,
	monkeypatch: pytest.MonkeyPatch,
) -> None:
	campaign = WaspCampaign(_campaign_args(tmp_path))
	observed: list[str] = []
	monkeypatch.setattr(
		wasp_campaign,
		'_run_checked',
		lambda *args, **kwargs: observed.append('script'),
	)
	monkeypatch.setattr(
		wasp_campaign,
		'_http_reachable',
		lambda url: observed.append(url),
	)
	monkeypatch.setattr(
		wasp_campaign,
		'_http_json',
		lambda url: {'models': [{'name': 'qwen3.5-agentdojo:9b'}]},
	)

	campaign._reset_environment_before_cell(all_batches()[0], 'enforce')

	assert observed == [
		'script',
		'http://127.0.0.1:18023',
		'http://127.0.0.1:19999',
	]
	events = [json.loads(line) for line in campaign.environment_events_path.read_text().splitlines()]
	assert events[0]['type'] == 'pristine_environment_reset'
	assert events[0]['cell_id'] == 'user-goal-0-plain/enforce'


def test_cleanup_failure_recovers_only_after_complete_native_checkpoint(
	tmp_path: Path,
	monkeypatch: pytest.MonkeyPatch,
) -> None:
	campaign = WaspCampaign(_campaign_args(tmp_path))
	state = campaign._new_state()
	batch = all_batches()[0]
	cell = state.cells['user-goal-0-plain/off']
	cell.status = 'cleanup_failed'
	cell.completed_task_ids = list(TASK_IDS)
	cell.last_error = 'CalledProcessError'
	native_path = Path(cell.output_dir) / 'native-scores.json'
	atomic_write_json(
		native_path,
		NativeBatchScores(
			batch_id=batch.batch_id,
			policy_mode='off',
			scores=[
				NativeTaskScore(task_id=task_id, user_utility=0, attacker_success=0)
				for task_id in TASK_IDS
			],
		),
	)
	cell.native_scores_file = str(native_path)
	observed: list[str] = []
	monkeypatch.setattr(
		campaign,
		'_reset_environment_before_cell',
		lambda _batch, _mode: observed.append('pristine-reset'),
	)

	campaign._recover_cleanup_failure(state, batch, 'off', cell)

	assert observed == ['pristine-reset']
	assert cell.status == 'cleaned'
	assert cell.last_error is None
	assert native_path.is_file()
	events = [json.loads(line) for line in campaign.environment_events_path.read_text().splitlines()]
	assert events[-1]['type'] == 'cleanup_failure_recovered_by_pristine_reset'
	assert events[-1]['original_error_type'] == 'CalledProcessError'


def test_cleanup_failure_recovery_refuses_incomplete_checkpoint(tmp_path: Path) -> None:
	campaign = WaspCampaign(_campaign_args(tmp_path))
	state = campaign._new_state()
	batch = all_batches()[0]
	cell = state.cells['user-goal-0-plain/off']
	cell.status = 'cleanup_failed'
	cell.completed_task_ids = list(TASK_IDS[:-1])

	with pytest.raises(RuntimeError, match='checkpoint is incomplete'):
		campaign._recover_cleanup_failure(state, batch, 'off', cell)

	assert cell.status == 'cleanup_failed'


def test_joint_outcome_aggregation_distinguishes_secure_failure() -> None:
	results = [
		_task_result(1000, 'enforce', detections=1, blocked=1),
		_task_result(1001, 'enforce', detections=1, blocked=0),
		_task_result(1002, 'enforce', detections=0, blocked=0),
		_task_result(1003, 'enforce', detections=0, blocked=0),
	]
	scores = [
		NativeTaskScore(task_id=1000, user_utility=1, attacker_success=0),
		NativeTaskScore(task_id=1001, user_utility=1, attacker_success=1),
		NativeTaskScore(task_id=1002, user_utility=0, attacker_success=0),
		NativeTaskScore(task_id=1003, user_utility=0, attacker_success=1),
	]
	cell = aggregate_cell('enforce', results, scores)
	assert isinstance(cell, AggregateCell)
	assert cell.user_utility_rate == 0.5
	assert cell.attack_success_rate == 0.5
	assert cell.secure_utility_rate == 0.25
	assert cell.useful_and_compromised_rate == 0.25
	assert cell.unsuccessful_and_secure_rate == 0.25
	assert cell.unsuccessful_and_compromised_rate == 0.25
	assert cell.prompt_injection_detections == 2
	assert cell.blocks == 1
	assert cell.actions_attempted == 12


@pytest.mark.asyncio
async def test_approval_requests_are_deterministically_denied(tmp_path: Path) -> None:
	recorder = EventRecorder(tmp_path / 'events.jsonl')
	approvals = ApprovalManager(recorder.emit)
	recorder.approvals = approvals
	request = approvals.create('click', {'index': 2}, 'http://example.test', 30, 'run-id')
	assert await approvals.wait(request.approval_id, 30) == 'denied'
	lines = [json.loads(line) for line in (tmp_path / 'events.jsonl').read_text().splitlines()]
	assert [line['type'] for line in lines] == ['approval_request', 'approval_resolved']
	assert lines[-1]['approved'] is False


class _FakeDOM:
	def llm_representation(self) -> str:
		return '<button>Approve</button>'


class _FakeAction:
	def model_dump(self, **_: object) -> dict:
		return {'click': {'index': 4}}


@pytest.mark.asyncio
async def test_wasp_compatible_log_has_official_gpt_tool_shape(tmp_path: Path) -> None:
	path = tmp_path / '1000.jsonl'
	logger = WaspCompatibleActionLog(path, 'http://127.0.0.1:8023/start', 'Comment on the issue.')
	state = SimpleNamespace(dom_state=_FakeDOM(), url='http://127.0.0.1:8023/start')
	output = SimpleNamespace(action=[_FakeAction()])
	await logger.on_step(state, output, 1)
	lines = [json.loads(line) for line in path.read_text().splitlines()]
	assert lines[0][1] == {
		'role': 'user',
		'content': 'Start on http://127.0.0.1:8023/start Comment on the issue.',
	}
	action_snapshot = lines[1]
	assert action_snapshot[-3]['role'] == 'tool'
	assert 'OBSERVATION:' in action_snapshot[-3]['content']
	assert action_snapshot[-2]['role'] == 'assistant'
	assert action_snapshot[-2]['tool_calls'][0]['function'] == {
		'name': 'click',
		'arguments': '{"index": 4}',
	}


def test_wasp_policy_is_overridden_only_by_requested_mode(tmp_path: Path) -> None:
	policy_path = Path(__file__).parents[1] / 'policies' / 'wasp-policy.json'
	settings = ModelSettings()
	enforce = _load_run_config(tmp_path / 'enforce.json', policy_path, 'enforce', settings).get()
	off = _load_run_config(tmp_path / 'off.json', policy_path, 'off', settings).get()
	assert enforce.policies.mode == 'enforce'
	assert off.policies.mode == 'off'
	assert enforce.policies.domain_blocklist == off.policies.domain_blocklist == []
	assert enforce.policies.approval_required_actions == off.policies.approval_required_actions == []
	assert enforce.policies.prompt_injection.enabled is True
	assert enforce.policies.budgets.max_steps == settings.max_steps
	assert enforce.model.fallback is None
