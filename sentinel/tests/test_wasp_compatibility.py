from pathlib import Path

import pytest
from pydantic import ValidationError

from evals.wasp.compatibility import _neutral_context_probe, build_complete_action_schema
from evals.wasp.contract import (
	CompatibilityCanaryCase,
	CompatibilityCanaryReport,
	ModelSettings,
)

ROOT = Path(__file__).resolve().parents[2]


def _settings(seed: int) -> ModelSettings:
	return ModelSettings(
		model='qwen3.5-agentdojo:27b',
		seed=seed,
		output_tokens=8192,
		native_thinking=True,
		browseruse_structured_thinking=True,
	)


def _report() -> CompatibilityCanaryReport:
	digest = 'a' * 64
	return CompatibilityCanaryReport(
		created_at='2026-08-05T00:00:00Z',
		sentinel_commit='sentinel',
	browser_use_commit='browser-use',
	enforcement_sha256='b' * 64,
	campaign_driver_sha256='d' * 64,
	ollama_version='0.32.5',
		model_digest='c' * 64,
		settings_by_seed=[_settings(seed) for seed in (0, 1, 2)],
		action_schema_sha256=digest,
		condition_schema_sha256={condition: digest for condition in ('off', 'policy_only', 'full')},
		context_probe_chars=50_000,
		cases=[
			CompatibilityCanaryCase(
				seed=seed,
				succeeded=True,
				latency_s=1.0,
				action_name='done',
				native_thinking_observed=True,
				stop_reason='stop',
				prompt_tokens=10_000,
				completion_tokens=500,
			)
			for seed in (0, 1, 2)
		],
	)


def test_complete_browseruse_schema_is_identical_across_conditions() -> None:
	model, hashes = build_complete_action_schema(
		full_policy=ROOT / 'sentinel' / 'policies' / 'wasp-v2-sanitise-noalert-policy.json',
		policy_only_policy=(
			ROOT / 'sentinel' / 'policies' / 'wasp-v2-nosanitise-noalert-policy.json'
		),
		settings=_settings(0),
	)

	assert len(set(hashes.values())) == 1
	schema_text = str(model.model_json_schema())
	assert 'DoneActionModel' in schema_text
	assert 'NavigateActionModel' in schema_text
	assert 'RequestHumanControlParams' in schema_text


def test_neutral_context_probe_is_deterministic_and_exactly_sized() -> None:
	probe = _neutral_context_probe('TOKEN', 50_000)
	assert len(probe) == 50_000
	assert 'neutral_token_start=TOKEN-START' in probe
	assert 'neutral_token_end=TOKEN-END' in probe
	assert probe == _neutral_context_probe('TOKEN', 50_000)


def test_canary_report_requires_all_three_native_thinking_successes() -> None:
	report = _report()
	assert [case.seed for case in report.cases] == [0, 1, 2]

	bad_case = report.model_dump(mode='json')
	bad_case['cases'][1]['native_thinking_observed'] = False
	with pytest.raises(ValidationError, match='every compatibility case must pass'):
		CompatibilityCanaryReport.model_validate(bad_case)

	bad_schema = report.model_dump(mode='json')
	bad_schema['condition_schema_sha256']['full'] = 'd' * 64
	with pytest.raises(ValidationError, match='identical action schema'):
		CompatibilityCanaryReport.model_validate(bad_schema)

	bad_headroom = report.model_dump(mode='json')
	bad_headroom['cases'][0]['prompt_tokens'] = 25_000
	with pytest.raises(ValidationError, match='complete configured output budget'):
		CompatibilityCanaryReport.model_validate(bad_headroom)
