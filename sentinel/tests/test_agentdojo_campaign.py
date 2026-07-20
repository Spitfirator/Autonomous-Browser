import json
import errno
from datetime import datetime, timezone
from types import SimpleNamespace

from evals.agentdojo_campaign import (
	CampaignCase,
	_atomic_write_json,
	build_manifest,
	campaign_report_path,
	classify_failure,
	report_completions,
	seconds_until_daily_reset,
)


def _suite(users: list[str], injections: list[str]) -> SimpleNamespace:
	return SimpleNamespace(
		user_tasks={task_id: object() for task_id in users},
		injection_tasks={task_id: object() for task_id in injections},
	)


def test_manifest_prioritizes_resumable_cross_suite_lane() -> None:
	suites = {
		'workspace': _suite(['user_task_0', 'user_task_1'], ['injection_task_0', 'injection_task_1']),
		'slack': _suite(['user_task_0', 'user_task_1'], ['injection_task_1', 'injection_task_2']),
	}
	manifest = build_manifest(suites)
	assert manifest[:4] == [
		CampaignCase('workspace', 'user_task_0', 'injection_task_0'),
		CampaignCase('slack', 'user_task_0', 'injection_task_1'),
		CampaignCase('workspace', 'user_task_1', 'injection_task_0'),
		CampaignCase('slack', 'user_task_1', 'injection_task_1'),
	]
	assert len(manifest) == 8
	assert len(set(manifest)) == len(manifest)


def test_manifest_interleaves_remaining_cases_across_suites() -> None:
	suites = {
		'first': _suite(['user_task_0', 'user_task_1'], ['injection_task_0']),
		'second': _suite(['user_task_0'], ['injection_task_0', 'injection_task_1']),
	}

	assert build_manifest(suites, interleave=True) == [
		CampaignCase('first', 'user_task_0', 'injection_task_0'),
		CampaignCase('second', 'user_task_0', 'injection_task_0'),
		CampaignCase('first', 'user_task_1', 'injection_task_0'),
		CampaignCase('second', 'user_task_0', 'injection_task_1'),
	]


def test_report_discovery_uses_report_contents_not_filename(tmp_path) -> None:
	path = tmp_path / 'arbitrary-name.json'
	path.write_text(
		json.dumps(
			{
				'kind': 'agentdojo-native-agent-run',
				'provenance': {
					'provider': 'ollama',
					'model': 'qwen3.5:4b',
					'attack': 'tool_knowledge',
					'suite_version': 'v1',
					'approval_mode': 'deny',
					'policy': {'mode': 'enforce'},
				},
				'results': {
					'utility': {'slack/user_task_7/injection_task_1': True},
					'attack_success': {'slack/user_task_7/injection_task_1': False},
				},
			}
		)
	)
	assert report_completions(
		[path],
		provider='ollama',
		model='qwen3.5:4b',
		attack='tool_knowledge',
		suite_version='v1',
		approval_mode='deny',
	) == {
		('enforce', 'slack/user_task_7/injection_task_1'): path
	}
	assert report_completions(
		[path],
		provider='gemini',
		model='gemini-3.1-flash-lite',
		attack='tool_knowledge',
		suite_version='v1',
		approval_mode='deny',
	) == {}


def test_report_discovery_filters_ollama_driver_profile(tmp_path) -> None:
	def write_report(name: str, key: str, profile: str | None) -> None:
		model_settings = {} if profile is None else {'profile': profile}
		(tmp_path / name).write_text(
			json.dumps(
				{
					'kind': 'agentdojo-native-agent-run',
					'provenance': {
						'provider': 'ollama',
						'model': 'qwen3.5:9b',
						'attack': 'tool_knowledge',
						'suite_version': 'v1',
						'approval_mode': 'deny',
						'policy': {'mode': 'enforce'},
						'model_settings': model_settings,
					},
					'results': {
						'utility': {key: True},
						'attack_success': {key: False},
					},
				}
			)
		)

	write_report('legacy.json', 'workspace/user_task_0/injection_task_0', None)
	write_report('nonthinking.json', 'slack/user_task_0/injection_task_1', 'nonthinking')
	write_report('thinking.json', 'travel/user_task_0/injection_task_0', 'thinking')
	paths = list(tmp_path.glob('*.json'))
	common = {
		'provider': 'ollama',
		'model': 'qwen3.5:9b',
		'attack': 'tool_knowledge',
		'suite_version': 'v1',
		'approval_mode': 'deny',
	}

	assert set(report_completions(paths, **common, ollama_profile='nonthinking')) == {
		('enforce', 'workspace/user_task_0/injection_task_0'),
		('enforce', 'slack/user_task_0/injection_task_1'),
	}
	assert set(report_completions(paths, **common, ollama_profile='thinking')) == {
		('enforce', 'travel/user_task_0/injection_task_0'),
	}


def test_incomplete_report_is_not_resumed_as_complete(tmp_path) -> None:
	path = tmp_path / 'incomplete.json'
	path.write_text(
		json.dumps(
			{
				'kind': 'agentdojo-native-agent-run',
				'provenance': {'policy': {'mode': 'off'}},
				'results': {'utility': {'workspace/user_task_1/injection_task_0': True}},
			}
		)
	)
	assert report_completions(
		[path],
		provider='ollama',
		model='qwen3.5:4b',
		attack='tool_knowledge',
		suite_version='v1',
		approval_mode='deny',
	) == {}


def test_daily_quota_is_distinguished_from_short_window_limit() -> None:
	daily = classify_failure(1, 'quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier')
	transient = classify_failure(1, '429 RESOURCE_EXHAUSTED requests per minute')
	assert daily.kind == 'daily_quota'
	assert transient.kind == 'transient_quota'


def test_provider_connection_failure_stops_campaign_cleanly() -> None:
	failure = classify_failure(1, 'openai.APIConnectionError: Connection error.')

	assert failure.kind == 'provider_unavailable'
	assert failure.summary == 'model provider is unavailable'


def test_daily_reset_uses_midnight_pacific() -> None:
	# 07:00 UTC in January is 23:00 Pacific on the previous day.
	now = datetime(2026, 1, 15, 7, 0, tzinfo=timezone.utc)
	assert seconds_until_daily_reset(now, buffer_s=120) == 3720


def test_campaign_report_path_is_stable(tmp_path) -> None:
	case = CampaignCase('travel', 'user_task_3', 'injection_task_6')
	assert campaign_report_path(tmp_path, case, 'off') == (
		tmp_path / 'travel' / 'user_task_3--injection_task_6--off.json'
	)


def test_checkpoint_falls_back_when_macos_rejects_atomic_replace(tmp_path, monkeypatch) -> None:
	path = tmp_path / 'state.json'
	path.write_text('{"old": true}\n')

	def reject_replace(source, destination) -> None:
		raise PermissionError(errno.EPERM, 'Operation not permitted', destination)

	monkeypatch.setattr('evals.agentdojo_campaign.os.replace', reject_replace)
	_atomic_write_json(path, {'completed_executions': 51})

	assert json.loads(path.read_text()) == {'completed_executions': 51}
	assert list(tmp_path.glob('.state.json.*.tmp')) == []
