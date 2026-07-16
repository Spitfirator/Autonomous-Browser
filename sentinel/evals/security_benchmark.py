#!/usr/bin/env python3
"""Offline security-policy evaluator for public benchmark adapters.

The input is JSONL so AgentDojo, BrowserGym/WorkArena injection suites, or a
custom red-team corpus can be converted without coupling Sentinel to a specific
benchmark version.  No page payload or raw action parameter is written to the
report: results contain hashes, signal names, redacted parameters and metrics.

Example:
    PYTHONPATH=sentinel python sentinel/evals/security_benchmark.py \
      sentinel/evals/fixtures/security-smoke.jsonl --pretty
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

SENTINEL_DIR = Path(__file__).resolve().parents[1]
if str(SENTINEL_DIR) not in sys.path:
	sys.path.insert(0, str(SENTINEL_DIR))

from server.config import SentinelConfig  # noqa: E402
from server.governance.policy import PolicyEngine  # noqa: E402
from server.governance.security import assess_action, detect_prompt_injection  # noqa: E402

FinalVerdict = Literal['allow', 'approve', 'block', 'handoff']


class BenchmarkCase(BaseModel):
	model_config = ConfigDict(extra='forbid')

	id: str
	category: str = 'uncategorized'
	page_text: str
	current_url: str = 'https://benchmark.invalid/'
	action: str = 'extract'
	params: dict[str, Any] = Field(default_factory=dict)
	# Optional DOM metadata of the action's target element (element text, input
	# type, autocomplete). The live extension extracts this at runtime; benchmark
	# adapters that map a tool call to a click/input sink supply the destination's
	# natural UI label or field type so target-semantic policy paths are exercised.
	target_context: dict[str, Any] | None = None
	trusted_origin: bool = False
	expected_injection: bool
	expected_verdict: FinalVerdict | None = None
	# Some security cases specify a set of safe outcomes. For example, a
	# malicious side effect may be either hard-blocked or held for explicit human
	# review. Exact expected_verdict remains available for single-outcome cases.
	expected_verdicts: list[FinalVerdict] | None = None


BenchmarkCase.model_rebuild()


def load_cases(path: Path) -> list[BenchmarkCase]:
	cases: list[BenchmarkCase] = []
	for line_number, raw in enumerate(path.read_text().splitlines(), 1):
		if not raw.strip() or raw.lstrip().startswith('#'):
			continue
		try:
			cases.append(BenchmarkCase.model_validate_json(raw))
		except ValidationError as exc:
			raise ValueError(f'{path}:{line_number}: {exc}') from exc
	if not cases:
		raise ValueError(f'{path}: no benchmark cases found')
	return cases


def load_config(path: Path | None) -> SentinelConfig:
	if path is None:
		return SentinelConfig()
	body = json.loads(path.read_text())
	# Reference policy files may be a partial {"policies": ...} patch. Merge it
	# with defaults before validation so benchmark config stays concise.
	base = SentinelConfig().model_dump(mode='json')
	for key, value in body.items():
		if isinstance(value, dict) and isinstance(base.get(key), dict):
			base[key].update(value)
		else:
			base[key] = value
	return SentinelConfig.model_validate(base)


def evaluate_cases(cases: list[BenchmarkCase], config: SentinelConfig | None = None) -> dict[str, Any]:
	config = config or SentinelConfig()
	policy = config.policies
	engine = PolicyEngine(_StaticConfigStore(config))  # type: ignore[arg-type]
	rows: list[dict[str, Any]] = []
	tp = fp = tn = fn = 0
	verdict_correct = verdict_total = 0
	attack_contained = attack_total = 0
	attack_hard_blocked = 0
	benign_approvals = benign_total = 0
	benign_blocked = 0
	category_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

	for case in cases:
		finding = detect_prompt_injection(case.page_text, policy.prompt_injection, case.current_url)
		risk = assess_action(
			case.action,
			case.params,
			case.current_url,
			finding,
			policy.prompt_injection,
			policy.data_flow,
			policy.adaptive_approvals,
			case.trusted_origin,
			b'sentinel-offline-benchmark',
			target_context=case.target_context,
		)
		decision = engine.evaluate(case.action, case.params, case.current_url, risk=risk)
		final_verdict: FinalVerdict = decision.verdict
		predicted = finding.detected
		if case.expected_injection and predicted:
			tp += 1
		elif case.expected_injection:
			fn += 1
		elif predicted:
			fp += 1
		else:
			tn += 1

		if case.expected_injection:
			attack_total += 1
			if final_verdict in ('approve', 'block', 'handoff') or case.action == 'extract':
				# Read-only observation is intentionally allowed; it does not give the
				# injection an effect. Side-effecting cases must be contained.
				attack_contained += 1
			if final_verdict == 'block':
				attack_hard_blocked += 1
		else:
			benign_total += 1
			if final_verdict in ('approve', 'handoff'):
				benign_approvals += 1
			if final_verdict == 'block':
				benign_blocked += 1

		expected = case.expected_verdicts or ([case.expected_verdict] if case.expected_verdict is not None else None)
		if expected is not None:
			verdict_total += 1
			if final_verdict in expected:
				verdict_correct += 1

		bucket = category_counts[case.category]
		bucket['cases'] += 1
		bucket['detected'] += int(predicted)
		bucket[f'verdict_{final_verdict}'] += 1
		report_params = (
			{'redacted': '[ATTACK_ACTION_PARAMETERS_OMITTED]'}
			if case.expected_injection
			else risk.redacted_params
		)
		rows.append(
			{
				'id': case.id,
				'category': case.category,
				'expected_injection': case.expected_injection,
				'detected': predicted,
				'score': finding.score,
				'severity': finding.severity,
				'signals': finding.signals,
				'content_hash': finding.content_hash,
				'action': case.action,
				'expected_verdict': case.expected_verdict,
				'expected_verdicts': expected,
				'risk_recommendation': risk.recommendation,
				'verdict': final_verdict,
				'policy_rule': decision.rule,
				'risk_score': risk.score,
				'risk_factors': risk.factors,
				'taint_labels': risk.taint_labels,
				'params_digest': risk.params_digest,
				'redacted_params': report_params,
			}
		)

	precision = _ratio(tp, tp + fp)
	recall = _ratio(tp, tp + fn)
	metrics = {
		'cases': len(cases),
		'detection': {
			'tp': tp,
			'fp': fp,
			'tn': tn,
			'fn': fn,
			'precision': precision,
			'recall': recall,
			'f1': _f1(precision, recall),
			'false_positive_rate': _ratio(fp, fp + tn),
		},
		'enforcement': {
			'attack_containment_rate': _ratio(attack_contained, attack_total),
			'attack_hard_block_rate': _ratio(attack_hard_blocked, attack_total),
			'verdict_accuracy': _ratio(verdict_correct, verdict_total),
			'labeled_verdict_cases': verdict_total,
		},
		'acceptance_fatigue': {
			'benign_approval_rate': _ratio(benign_approvals, benign_total),
			'benign_approvals': benign_approvals,
			'benign_block_rate': _ratio(benign_blocked, benign_total),
			'benign_blocks': benign_blocked,
			'benign_cases': benign_total,
		},
		'by_category': {name: dict(counts) for name, counts in sorted(category_counts.items())},
	}
	return {'schema_version': 1, 'metrics': metrics, 'results': rows}


class _StaticConfigStore:
	"""Read-only ConfigStore protocol for an offline benchmark run."""

	def __init__(self, config: SentinelConfig) -> None:
		self._config = config

	def get(self) -> SentinelConfig:
		return self._config


def _ratio(numerator: float, denominator: float) -> float | None:
	return round(numerator / denominator, 6) if denominator else None


def _f1(precision: float | None, recall: float | None) -> float | None:
	if precision is None or recall is None:
		return None
	return _ratio(2 * precision * recall, precision + recall)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('dataset', type=Path, help='JSONL benchmark cases')
	parser.add_argument('--policy', type=Path, help='optional Sentinel config/reference-policy JSON')
	parser.add_argument('--output', type=Path, help='write the privacy-preserving JSON report here')
	parser.add_argument('--pretty', action='store_true', help='indent JSON output')
	args = parser.parse_args()
	try:
		report = evaluate_cases(load_cases(args.dataset), load_config(args.policy))
	except (OSError, ValueError, json.JSONDecodeError) as exc:
		parser.error(str(exc))
	payload = json.dumps(report, indent=2 if args.pretty else None, sort_keys=args.pretty)
	if args.output:
		args.output.parent.mkdir(parents=True, exist_ok=True)
		args.output.write_text(payload + '\n')
	else:
		print(payload)
	return 0


if __name__ == '__main__':
	raise SystemExit(main())
