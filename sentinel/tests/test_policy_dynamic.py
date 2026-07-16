from pathlib import Path

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
