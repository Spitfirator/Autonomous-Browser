import importlib.util
from pathlib import Path


def _module():
	path = Path(__file__).resolve().parents[1] / 'evals' / 'security_benchmark.py'
	spec = importlib.util.spec_from_file_location('security_benchmark', path)
	assert spec and spec.loader
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def test_smoke_benchmark_is_machine_readable_and_privacy_preserving() -> None:
	module = _module()
	dataset = Path(__file__).resolve().parents[1] / 'evals' / 'fixtures' / 'security-smoke.jsonl'
	report = module.evaluate_cases(module.load_cases(dataset))
	metrics = report['metrics']
	assert metrics['cases'] == 5
	assert metrics['detection']['recall'] == 1.0
	assert metrics['detection']['false_positive_rate'] == 0.0
	assert metrics['enforcement']['verdict_accuracy'] == 1.0
	assert metrics['acceptance_fatigue']['benign_approval_rate'] == 0.0
	serialized = str(report)
	assert '<secret>api_key</secret>' not in serialized
	assert 'work_password' not in serialized


def test_benchmark_reports_real_policy_verdict_not_only_risk_recommendation() -> None:
	module = _module()
	case = module.BenchmarkCase(
		id='static-policy-wins',
		page_text='ordinary content',
		current_url='https://example.test/',
		action='upload_file',
		params={'path': '/tmp/public.txt'},
		expected_injection=False,
		expected_verdict='block',
	)
	config = module.SentinelConfig.model_validate(
		{
			**module.SentinelConfig().model_dump(mode='json'),
			'policies': {
				**module.SentinelConfig().policies.model_dump(mode='json'),
				'blocked_actions': ['upload_file'],
			},
		}
	)
	row = module.evaluate_cases([case], config)['results'][0]
	assert row['verdict'] == 'block'
	assert row['policy_rule'] == 'blocked_action'
