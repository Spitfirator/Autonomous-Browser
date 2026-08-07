from pathlib import Path
from types import SimpleNamespace

import pytest

import evals.wasp.replication as replication
from evals.wasp.contract import RuntimeProvenance
from evals.wasp.replication import (
	EXPECTED_RUNTIME_FIXED,
	_condition_summary,
	_none_participant_control_telemetry,
	_paired_effect,
	_validate_runtime,
	render_markdown,
)


def _rows() -> list[dict]:
	rows = []
	for seed in (0, 1, 2):
		for task_id in range(84):
			for condition in ('off', 'policy_only', 'full'):
				attack = condition == 'off' and task_id < seed + 1
				executed = condition != 'full' and task_id < 2
				rows.append(
					{
						'seed': seed,
						'condition': condition,
						'case_id': f'case-{task_id}',
						'user_utility': task_id % 2 == 0,
						'attack_success': attack,
						'action_audited_terminal_attack_success': bool(attack and executed),
						'native_positive_without_executed_attacker_action': bool(
							attack and not executed
						),
						'secure_utility': task_id % 2 == 0 and not attack,
						'attacker_attempted': executed,
						'attacker_attempted_actions': int(executed),
						'attacker_executed': executed,
						'attacker_executed_actions': int(executed),
						'attacker_prevented': False,
						'attacker_prevented_actions': 0,
						'attacker_hard_blocked': False,
						'attacker_hard_blocked_actions': 0,
						'attacker_approval_gated': False,
						'attacker_approval_gated_actions': 0,
						'attacker_handoff_paused': False,
						'attacker_handoff_paused_actions': 0,
						'attacker_execution_failed_actions': 0,
						'potential_false_block_actions': 0,
						'potential_false_hard_block_actions': 0,
						'potential_false_approval_gate_actions': 0,
						'potential_false_handoff_pause_actions': 0,
						'potential_false_blocked': False,
						'duration_s': 10 + seed,
						'actions_attempted': 2,
						'decision_count': 2,
						'enforcement_ms_total': 1.0,
						'approval_prompts': 0,
						'approval_approved': 0,
						'approval_denied': 0,
						'handoffs': 0,
						'scripted_handoff_timeouts': 0,
						'security_incidents': 0,
						'blocks': 0,
						'human_wait_s': 0.0,
						'approval_wait_s': 0.0,
						'handoff_wait_s': 0.0,
						'incident_wait_s': 0.0,
						'scripted_resolutions': 0,
						'sanitisation_attempts': 0,
						'sanitisation_removed': 0,
						'sanitisation_residual': 0,
						'sanitisation_unattributable': 0,
						'sanitisation_not_attempted': 0,
						'sanitisation_branch_line': 0,
						'sanitisation_branch_window': 0,
						'sanitisation_branch_structural': 0,
						'sanitisation_branch_none': 0,
						'sanitisation_regions_targeted': 0,
						'sanitisation_regions_changed': 0,
						'sanitisation_regions_unattributable': 0,
						'sanitisation_alerts_after_removed': 0,
						'sanitisation_residual_detector_positive': 0,
						'model_requests': 2,
						'model_structured_requests': 2,
						'model_successes': 2,
						'model_structured_successes': 2,
						'model_native_thinking_responses': 2,
						'model_prompt_tokens': 20,
						'model_completion_tokens': 10,
						'model_max_prompt_tokens': 12,
						'model_max_completion_tokens': 7,
						'model_stop_reasons': {'stop': 2},
						'model_failure_categories': {},
						'sentinel_commit': replication.SENTINEL_COMMIT,
						'browser_use_commit': replication.BROWSER_USE_COMMIT,
						'benchmark_commit': replication.WASP_COMMIT,
					}
				)
	return rows


def test_condition_summary_reports_exact_denominators_and_seed_variability() -> None:
	off = [row for row in _rows() if row['condition'] == 'off']
	report = _condition_summary(off)

	assert report['executions'] == 252
	assert report['attack_success']['count'] == 6
	assert report['action_audited_terminal_attack_success']['count'] == 5
	assert report['native_positive_without_executed_attacker_action']['count'] == 1
	assert report['attack_success']['variability']['counts'] == {'0': 1, '1': 2, '2': 3}
	assert report['attacker_directed_executed']['tasks'] == {
		'count': 6,
		'denominator': 252,
		'rate': 6 / 252,
	}
	assert report['attacker_directed_attempted']['actions_among_governed_requests'] == {
		'count': 6,
		'denominator': 504,
		'rate': 6 / 504,
	}
	assert report['attacker_directed_executed']['actions_given_attacker_attempt'] == {
		'count': 6,
		'denominator': 6,
		'rate': 1.0,
	}
	assert report['attacker_directed_prevented']['actions_given_attacker_attempt'] == {
		'count': 0,
		'denominator': 6,
		'rate': 0.0,
	}
	assert report['missed_dangerous_actions']['tasks_given_attacker_attempt'] == {
		'count': 6,
		'denominator': 6,
		'rate': 1.0,
	}
	assert report['potential_false_blocks']['actions_among_governed_requests'] == {
		'count': 0,
		'denominator': 504,
		'rate': 0.0,
	}
	assert report['interventions']['policy_or_security_pause_tasks'] == {
		'count': 0,
		'denominator': 252,
		'rate': 0.0,
	}
	assert report['latency']['per_seed_mean_s'] == {'0': 10.0, '1': 11.0, '2': 12.0}
	assert report['interventions']['actual_human_interventions'] is None
	assert report['interventions']['scripted_approval_denials'] == 0
	assert report['interventions']['scripted_handoff_timeouts'] == 0
	assert report['sanitisation_telemetry']['attempts'] == 0
	assert report['sanitisation_telemetry']['status']['removed'] == 0
	assert report['model_output_reliability']['successful_schema_validated_outputs'] == 504
	assert report['model_output_reliability']['requests'] == 504
	assert report['model_output_reliability']['failure_categories'] == {}
	assert report['model_output_reliability']['max_prompt_tokens_per_request'] == 12
	assert report['model_output_reliability']['max_completion_tokens_per_request'] == 7
	assert report['model_output_reliability']['tasks_exceeding_full_output_headroom'] == 0


def test_none_participant_control_telemetry_separates_scripted_from_human() -> None:
	events = [
		{'type': 'approval_request'},
		{'type': 'approval_resolved', 'approved': False, 'resolved_by': 'user'},
		{'type': 'control_request'},
		{'type': 'control_returned', 'resolved_by': 'timeout'},
	]
	assert _none_participant_control_telemetry(
		events, {'approval_prompts': 1, 'human_interventions': 1}, 'case'
	) == {
		'approval_prompts': 1,
		'scripted_approval_denials': 1,
		'handoff_requests': 1,
		'scripted_handoff_timeouts': 1,
	}

	with pytest.raises(ValueError, match='non-denial approval'):
		_none_participant_control_telemetry(
			[{'type': 'approval_request'}, {'type': 'approval_resolved', 'approved': True}],
			{'approval_prompts': 1, 'human_interventions': 1},
			'case',
		)
	with pytest.raises(ValueError, match='completed human handoff'):
		_none_participant_control_telemetry(
			[{'type': 'control_request'}, {'type': 'control_returned', 'resolved_by': 'user'}],
			{'approval_prompts': 0, 'human_interventions': 0},
			'case',
		)


def test_paired_effect_reports_per_seed_rate_deltas() -> None:
	report = _paired_effect(_rows(), 'off', 'full')

	assert report['attack_success']['per_seed_rate_delta'] == {
		'0': -1 / 84,
		'1': -2 / 84,
		'2': -3 / 84,
	}
	assert report['duration_s']['per_seed_mean_delta_s'] == {'0': 0.0, '1': 0.0, '2': 0.0}
	assert 'per_seed_rate_delta' not in report['duration_s']


def test_runtime_validation_requires_exact_archives_and_full_hashes() -> None:
	runtime = RuntimeProvenance(
		**EXPECTED_RUNTIME_FIXED,
		gpu_name='test GPU',
		gpu_memory_total_mib=24576,
		gpu_driver_version='test-driver',
		gitlab_image_sha256='a' * 64,
		reddit_image_sha256='b' * 64,
		compatibility_canary_sha256='c' * 64,
	)
	_validate_runtime(runtime, 'test-run')

	bad = runtime.model_copy(update={'reddit_image_sha256': 'short'})
	with pytest.raises(ValueError, match='not a full SHA-256'):
		_validate_runtime(bad, 'test-run')

	undersized_gpu = runtime.model_copy(update={'gpu_memory_total_mib': 16384})
	with pytest.raises(ValueError, match='GPU memory is insufficient'):
		_validate_runtime(undersized_gpu, 'test-run')


def test_markdown_report_carries_exact_denominators_and_non_participant_boundary() -> None:
	rows = _rows()
	report = {
		'design': {
			'fixed_execution_order_per_seed': [],
			'campaign_run_tags': {
				str(seed): {'full': f'full-{seed}', 'policy_only': f'policy-{seed}'}
				for seed in (0, 1, 2)
			},
		},
		'conditions': {
			condition: _condition_summary([row for row in rows if row['condition'] == condition])
			for condition in ('off', 'policy_only', 'full')
		},
		'paired_effects': {
			'policy_only_minus_off': _paired_effect(rows, 'off', 'policy_only'),
			'full_minus_off': _paired_effect(rows, 'off', 'full'),
			'full_minus_policy_only': _paired_effect(rows, 'policy_only', 'full'),
		},
		'failure_categories': {
			'baseline_security_by_incompetence': {
				'terminal_attack_success': {'tasks': 6, 'user_utility_success': 3, 'user_utility_failure': 3},
				'native_positive_without_executed_attacker_action': {'tasks': 0},
				'attacker_execution_without_terminal_success': {'tasks': 0},
				'attacker_attempt_without_execution': {'tasks': 0},
				'no_recorded_attacker_attempt': {'tasks': 246, 'user_utility_success': 123, 'user_utility_failure': 123},
			},
			'middleware_attribution': {'full_prevented_dangerous_action_task': 6},
		},
		'provenance': {
			'sentinel_commits': 'sentinel',
			'browser_use_commits': 'browser-use',
			'benchmark_commits': 'wasp',
			'campaign_driver_sha256': 'driver',
			'controller_script_sha256': 'controller',
			'aggregation_script_sha256': 'aggregator',
			'intermediate_scorer_version': 4,
			'intermediate_scorer_sha256': 'scorer',
			'enforcement_sha256': 'enforcement',
			'full_policy_sha256': 'full-policy',
			'policy_only_sha256': 'policy-only',
			'runtime': RuntimeProvenance(
				**EXPECTED_RUNTIME_FIXED,
				gpu_name='test GPU',
				gpu_memory_total_mib=24576,
				gpu_driver_version='test-driver',
				gitlab_image_sha256='a' * 64,
				reddit_image_sha256='b' * 64,
				compatibility_canary_sha256='c' * 64,
			).model_dump(),
		},
		'operational_validation': {
			'controller_restart_count': 0,
			'operational_failure_categories': {},
			'abandoned_attempt_categories': {},
			'failed_attempt_model_output': {'failure_categories': {}},
		},
	}

	markdown = render_markdown(report)

	assert '6/252 (2.38%); seed SD' in markdown
	assert 'N/A (`participant=none`)' in markdown
	assert 'Earlier 9B development rows' in markdown
	assert 'Potential false block' in markdown
	assert '6/504 (1.19%) actions' in markdown
	assert '6/6 (100.00%) attempted actions executed' in markdown
	assert 'mean 11.00 s over 252 episodes' in markdown
	assert '0.500 ms/governed decision (n=504)' in markdown
	assert 'not a pure middleware-overhead estimate' in markdown
	assert 'Only `attacker_execution_without_terminal_success` directly supports' in markdown
	assert 'absence of an attempt is not relabelled as a hard block' in markdown
	assert '## Sanitisation mechanism telemetry' in markdown
	assert '## Paired controlled effects' in markdown
	assert 'Full − policy-only (sanitisation increment)' in markdown
	assert '-2.38 pp; seed SD 1.19 pp' in markdown
	assert 'Aggregation/renderer SHA-256: `aggregator`' in markdown
	assert 'Attacker-action scorer: version 4' in markdown
	assert 'GPU: `test GPU`; 24576 MiB; driver `test-driver`' in markdown
	assert '## Model-output reliability' in markdown
	assert '504/504' in markdown


def test_aggregate_exercises_all_756_rows_and_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
	runtime = RuntimeProvenance(
		**EXPECTED_RUNTIME_FIXED,
		gpu_name='test GPU',
		gpu_memory_total_mib=24576,
		gpu_driver_version='test-driver',
		gitlab_image_sha256='a' * 64,
		reddit_image_sha256='b' * 64,
		compatibility_canary_sha256='c' * 64,
	)

	def state(policy_sha: str) -> SimpleNamespace:
		cell = SimpleNamespace(input_manifest_sha256='manifest', restart_count=0)
		return SimpleNamespace(
			runtime_provenance=runtime,
			enforcement_sha256=replication.ENFORCEMENT_SHA256,
			campaign_driver_sha256=replication.CAMPAIGN_DRIVER_SHA256,
			policy_sha256=policy_sha,
			cells={'batch/off': cell, 'batch/enforce': cell},
		)

	def load_campaign(_root: Path, tag: str, _seed: int, _modes: tuple[str, ...]):
		return state(
			replication.POLICY_ONLY_SHA256 if 'nosanitise' in tag else replication.FULL_POLICY_SHA256
		), SimpleNamespace()

	rows = _rows()

	def task_rows(
		_root: Path,
		_tag: str,
		seed: int,
		condition: str,
		_mode: str,
		_state: SimpleNamespace,
	):
		return [row for row in rows if row['seed'] == seed and row['condition'] == condition]

	monkeypatch.setattr(replication, '_load_campaign', load_campaign)
	monkeypatch.setattr(replication, '_task_rows', task_rows)
	monkeypatch.setattr(replication, '_read_jsonl', lambda _path: [])
	monkeypatch.setattr(replication, 'all_batches', lambda: [SimpleNamespace(batch_id='batch')])

	report = replication.aggregate(Path('/ignored'))

	assert report['design']['total_executions'] == 756
	assert report['conditions']['off']['executions'] == 252
	assert report['provenance']['runtime']['ollama_version'] == '0.32.5'
	assert report['provenance']['intermediate_scorer_version'] == 4
	assert len(report['provenance']['aggregation_script_sha256']) == 64
	assert len(report['provenance']['intermediate_scorer_sha256']) == 64
	assert report['input_manifests'] == {
		'0': {'batch': 'manifest'},
		'1': {'batch': 'manifest'},
		'2': {'batch': 'manifest'},
	}
