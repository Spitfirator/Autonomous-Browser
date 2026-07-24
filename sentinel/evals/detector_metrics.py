#!/usr/bin/env python3
"""Compact, checked-in detector scorecard across every offline corpus.

The per-case reports from :mod:`evals.security_benchmark` are large and stay
local (see ``.gitignore``).  This writes the small artifact that is actually
tracked: headline detector metrics, the full-page score distribution, and — when
a previous middleware revision is supplied — an explicit v1 versus v2 delta.

The delta is reported as *classification* agreement, not byte equality: a score
may move inside a band without changing what the middleware does.

Usage::

    PYTHONPATH=sentinel browser-use/.venv/bin/python sentinel/evals/detector_metrics.py \\
        --out sentinel/evals/detector-v2-metrics.json --pretty
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

SENTINEL_DIR = Path(__file__).resolve().parents[1]
if str(SENTINEL_DIR) not in sys.path:
	sys.path.insert(0, str(SENTINEL_DIR))

WORKSPACE_ROOT = SENTINEL_DIR.parent

from evals.wasp.contract import enforcement_source_sha256  # noqa: E402
from server.config import PromptInjectionPolicy  # noqa: E402
from server.governance.security import detect_prompt_injection  # noqa: E402

CORPORA = (
	'agentdojo-security',
	'agentdojo-v1-tool-knowledge',
	'wasp-security',
)


def band(score: float, policy: PromptInjectionPolicy) -> str:
	if score >= policy.block_threshold:
		return 'block'
	if score >= policy.detection_threshold:
		return 'detected'
	return 'clear'


def load_corpus(name: str) -> list[dict[str, Any]]:
	path = SENTINEL_DIR / 'evals' / 'fixtures' / f'{name}.jsonl'
	if not path.is_file():
		return []
	return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def score_corpus(cases: list[dict[str, Any]], policy: PromptInjectionPolicy) -> dict[str, Any]:
	attack: list[float] = []
	benign: list[float] = []
	bands: list[str] = []
	for case in cases:
		finding = detect_prompt_injection(case['page_text'], policy, case.get('current_url'))
		bands.append(band(finding.score, policy))
		(attack if case['expected_injection'] else benign).append(finding.score)

	tp = sum(1 for score in attack if score >= policy.detection_threshold)
	fp = sum(1 for score in benign if score >= policy.detection_threshold)
	summary: dict[str, Any] = {
		'cases': len(cases),
		'attack_cases': len(attack),
		'benign_cases': len(benign),
		'recall': round(tp / len(attack), 6) if attack else None,
		'precision': round(tp / (tp + fp), 6) if (tp + fp) else None,
		'false_positive_rate': round(fp / len(benign), 6) if benign else None,
		'bands': {name: bands.count(name) for name in ('clear', 'detected', 'block')},
	}
	if attack:
		summary['attack_scores'] = {
			'min': round(min(attack), 3),
			'median': round(statistics.median(attack), 3),
			'max': round(max(attack), 3),
			'at_or_above_block_threshold': sum(1 for score in attack if score >= policy.block_threshold),
		}
	if benign:
		summary['benign_scores'] = {'max': round(max(benign), 3)}
	return summary


def band_delta(name: str, cases: list[dict[str, Any]], policy: PromptInjectionPolicy, baseline: Path) -> dict[str, Any]:
	"""Compare against a previous revision of the middleware, if available."""

	source = subprocess.run(
		['git', 'show', f'{baseline}:sentinel/server/governance/security.py'],
		cwd=WORKSPACE_ROOT,
		capture_output=True,
		text=True,
	)
	if source.returncode != 0:
		return {'available': False, 'reason': source.stderr.strip()[:200]}

	# Load as a real module: the file uses `from __future__ import annotations`,
	# so pydantic needs an importable namespace to resolve its own annotations.
	module = types.ModuleType('sentinel_security_baseline')
	sys.modules[module.__name__] = module
	exec(compile(source.stdout, 'sentinel_security_baseline.py', 'exec'), module.__dict__)  # noqa: S102
	module.PromptInjectionFinding.model_rebuild()
	module.RiskAssessment.model_rebuild()
	previous_detect = module.detect_prompt_injection

	changed_detection = changed_band = changed_score = 0
	for case in cases:
		before = previous_detect(case['page_text'], policy, case.get('current_url'))
		after = detect_prompt_injection(case['page_text'], policy, case.get('current_url'))
		changed_score += before.score != after.score
		changed_detection += before.detected != after.detected
		changed_band += band(before.score, policy) != band(after.score, policy)
	return {
		'available': True,
		'baseline': str(baseline),
		'cases': len(cases),
		'changed_detection_classification': changed_detection,
		'changed_score_band': changed_band,
		'changed_score_value_only': changed_score - changed_band,
	}


def main() -> None:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--out', type=Path, default=SENTINEL_DIR / 'evals' / 'detector-v2-metrics.json')
	parser.add_argument('--baseline', default='HEAD', help='git revision holding the previous middleware')
	parser.add_argument('--pretty', action='store_true')
	args = parser.parse_args()

	policy = PromptInjectionPolicy()
	report: dict[str, Any] = {
		'kind': 'sentinel-detector-scorecard',
		'detection_threshold': policy.detection_threshold,
		'block_threshold': policy.block_threshold,
		'enforcement_sha256': enforcement_source_sha256(SENTINEL_DIR),
		'corpora': {},
		'baseline_comparison': {},
	}
	for name in CORPORA:
		cases = load_corpus(name)
		if not cases:
			report['corpora'][name] = {'available': False}
			continue
		report['corpora'][name] = score_corpus(cases, policy)
		report['baseline_comparison'][name] = band_delta(name, cases, policy, args.baseline)

	args.out.write_text(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True) + '\n', encoding='utf-8')
	print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
	main()
