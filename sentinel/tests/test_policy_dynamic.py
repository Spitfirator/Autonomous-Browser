from pathlib import Path

import pytest

from server.config import ConfigStore
from server.governance.policy import PolicyEngine
from server.governance.security import RiskAssessment


def _risk(recommendation: str, rule: str = 'test_dynamic') -> RiskAssessment:
	return RiskAssessment(
		score=90,
		recommendation=recommendation,
		rule=rule,
		reason='dynamic risk reason',
		factors=['test factor'],
		capabilities=['data_disclosure'],
		taint_labels=['untrusted_web'],
		target_origin='https://example.test',
		params_digest='digest',
		approval_key='scope',
		redacted_params={},
	)


def _engine(tmp_path: Path, patch: dict | None = None) -> PolicyEngine:
	store = ConfigStore(tmp_path / 'config.json')
	if patch:
		store.update({'policies': patch})
	return PolicyEngine(store)


def test_dynamic_hard_block_wins_over_static_approval(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'approval_required_actions': ['input']})
	decision = engine.evaluate('input', {'text': 'redacted'}, 'https://example.test', risk=_risk('block'))
	assert decision.verdict == 'block'
	assert decision.rule == 'test_dynamic'


def test_dynamic_handoff_wins_over_static_approval(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'approval_required_actions': ['input']})
	decision = engine.evaluate('input', {'text': 'redacted'}, 'https://example.test', risk=_risk('handoff'))
	assert decision.verdict == 'handoff'
	assert decision.rule == 'test_dynamic'


def test_dynamic_hard_block_wins_over_sensitive_domain_handoff(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'sensitive_domains': ['example.test']})
	decision = engine.evaluate(
		'input',
		{'text': 'redacted'},
		'https://example.test',
		risk=_risk('block', 'prompt_injection_high_confidence'),
	)
	assert decision.verdict == 'block'
	assert decision.rule == 'prompt_injection_high_confidence'


def test_human_only_dynamic_handoff_wins_over_generic_sensitive_domain_handoff(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'sensitive_domains': ['example.test']})
	decision = engine.evaluate(
		'input',
		{'text': 'redacted'},
		'https://example.test',
		risk=_risk('handoff', 'human_only_sensitive_data'),
	)
	assert decision.verdict == 'handoff'
	assert decision.rule == 'human_only_sensitive_data'
	assert decision.pattern is None


def test_shadow_mode_keeps_dynamic_block_priority_over_sensitive_domain(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'mode': 'shadow', 'sensitive_domains': ['example.test']})
	decision = engine.evaluate(
		'input',
		{'text': 'redacted'},
		'https://example.test',
		risk=_risk('block', 'prompt_injection_high_confidence'),
	)
	assert decision.verdict == 'allow'
	assert decision.shadow_verdict == 'block'
	assert decision.rule == 'prompt_injection_high_confidence'


def test_dynamic_approval_carries_opaque_scope(tmp_path: Path) -> None:
	engine = _engine(tmp_path)
	decision = engine.evaluate('click', {'index': 1}, 'https://example.test', risk=_risk('approve'))
	assert decision.verdict == 'approve'
	assert decision.approval_key == 'scope'


def test_shadow_mode_records_would_block_but_allows(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'mode': 'shadow'})
	decision = engine.evaluate('input', {}, 'https://example.test', risk=_risk('block'))
	assert decision.verdict == 'allow'
	assert decision.shadow_verdict == 'block'
	assert decision.mode == 'shadow'


def test_static_domain_block_still_precedes_dynamic_rules(tmp_path: Path) -> None:
	engine = _engine(tmp_path, {'domain_blocklist': ['example.test']})
	decision = engine.evaluate('click', {}, 'https://example.test', risk=_risk('approve'))
	assert decision.verdict == 'block'
	assert decision.rule == 'domain_blocklist'


@pytest.mark.parametrize(
	('url', 'scheme'),
	[
		('data:text/html,%3Ch1%3EPersonal%20Access%20Tokens%3C%2Fh1%3E', 'data'),
		('javascript:alert(document.cookie)', 'javascript'),
		('\njava\tscript:alert(document.cookie)', 'javascript'),
		('blob:https://example.test/opaque-object-id', 'blob'),
		('file:///Users/operator/private.html', 'file'),
		('mailto:person@example.test?body=private', 'mailto'),
	],
)
def test_enforce_blocks_non_web_agent_navigation_without_echoing_payload(
	tmp_path: Path,
	url: str,
	scheme: str,
) -> None:
	decision = _engine(tmp_path).evaluate('navigate', {'url': url}, 'https://example.test')
	assert decision.verdict == 'block'
	assert decision.rule == 'unsafe_navigation_scheme'
	assert f"'{scheme}:'" in decision.reason
	assert 'Personal' not in decision.reason
	assert 'document.cookie' not in decision.reason
	assert 'operator' not in decision.reason
	assert 'person@example' not in decision.reason


def test_safe_web_and_recovery_navigation_remain_allowed(tmp_path: Path) -> None:
	engine = _engine(tmp_path)
	for url in ('https://example.test/path', 'http://127.0.0.1:8877/test.html', 'about:blank'):
		decision = engine.evaluate('navigate', {'url': url}, 'https://example.test')
		assert decision.verdict == 'allow', url


def test_special_navigation_respects_experiment_modes(tmp_path: Path) -> None:
	url = 'data:text/html,%3Ch1%3Eprivate-payload%3C%2Fh1%3E'
	shadow = _engine(tmp_path, {'mode': 'shadow'}).evaluate(
		'navigate', {'url': url}, 'https://example.test'
	)
	assert shadow.verdict == 'allow'
	assert shadow.shadow_verdict == 'block'
	assert shadow.rule == 'unsafe_navigation_scheme'
	off = _engine(tmp_path, {'mode': 'off'}).evaluate(
		'navigate', {'url': url}, 'https://example.test'
	)
	assert off.verdict == 'allow'
	assert off.rule == 'enforcement_off'
